import sys
import re
import threading
import uuid
from pathlib import Path
import tkinter as tk
from tkinter import filedialog

import streamlit as st


# ============================================================
# 경로 설정
# ============================================================
BASE_DIR = Path(__file__).resolve().parents[1]
APP_DIR = BASE_DIR / "app"

if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))


# ============================================================
# Streamlit 기본 설정
# ============================================================
st.set_page_config(
    page_title="AI Source Security Analyzer",
    page_icon="🔐",
    layout="wide",
)


# ============================================================
# Session State
# ============================================================
if "source_dir" not in st.session_state:
    st.session_state.source_dir = str(BASE_DIR / "data" / "source")

if "scan_result" not in st.session_state:
    st.session_state.scan_result = None
if "scan_error" not in st.session_state:
    st.session_state.scan_error = None
if "scan_requested" not in st.session_state:
    st.session_state.scan_requested = False
if "scan_running" not in st.session_state:
    st.session_state.scan_running = False
if "chat_messages" not in st.session_state:
    st.session_state.chat_messages = []
if "chat_scan_pending" not in st.session_state:
    st.session_state.chat_scan_pending = False
if "active_scan_job_id" not in st.session_state:
    st.session_state.active_scan_job_id = None

should_run_scan = st.session_state.scan_requested
if should_run_scan:
    st.session_state.scan_requested = False
    st.session_state.scan_running = True


# ============================================================
# 폴더 선택
# ============================================================
def select_folder():
    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)

    selected_folder = filedialog.askdirectory(title="보안점검할 소스 폴더 선택")
    root.destroy()

    if selected_folder:
        st.session_state.source_dir = selected_folder


# ============================================================
# 보안점검 실행
# ============================================================
def request_scan():
    st.session_state.scan_result = None
    st.session_state.scan_error = None
    st.session_state.scan_requested = True


@st.cache_resource
def get_scan_job_store():
    """Keep worker state outside Streamlit session state across reruns."""
    return {"jobs": {}, "lock": threading.RLock()}


SCAN_JOB_STORE = get_scan_job_store()


def update_scan_job(job_id, **updates):
    with SCAN_JOB_STORE["lock"]:
        job = SCAN_JOB_STORE["jobs"].get(job_id)
        if job is not None:
            job.update(updates)


def run_security_agent_in_background(job_id, source_path):
    def update_progress(progress, message):
        progress = max(0, min(100, int(progress)))
        if progress < 15:
            stage = "소스코드 수집"
        elif progress < 40:
            stage = "Rule 기반 보안점검"
        elif progress < 65:
            stage = "Qwen AI 분석"
        elif progress < 80:
            stage = "AI 검증"
        elif progress < 90:
            stage = "결과 통합"
        elif progress < 100:
            stage = "HTML 리포트 생성"
        else:
            stage = "완료"
        update_scan_job(
            job_id,
            progress=progress,
            stage=stage,
            message=message or "분석 중입니다...",
        )

    try:
        from agent.security_agent import SecurityAgent

        result = SecurityAgent(source_dir=str(source_path)).run(
            progress_callback=update_progress
        )
        update_scan_job(job_id, status="done", result=result, error=None)
    except Exception as error:
        update_scan_job(job_id, status="done", result=None, error=str(error))


def finish_chat_scan():
    if not st.session_state.chat_scan_pending:
        return

    st.session_state.chat_scan_pending = False
    if st.session_state.scan_error:
        reply = f"보안점검을 완료하지 못했습니다: {st.session_state.scan_error}"
    else:
        result = st.session_state.scan_result or {}
        findings = result.get("findings") or []
        counts = {}
        for finding in findings:
            severity = str(finding.get("severity") or "미분류").upper()
            counts[severity] = counts.get(severity, 0) + 1
        severity_summary = ", ".join(
            f"{severity} {count}건" for severity, count in counts.items()
        ) or "취약점이 발견되지 않았습니다"
        report_file = result.get("report_file")
        reply = (
            f"보안점검을 완료했습니다. 분석 파일 {result.get('source_count', 0)}개, "
            f"취약점 {len(findings)}건({severity_summary})."
        )
        if report_file:
            reply += f" 보고서: {report_file}"
    st.session_state.chat_messages.append(
        {"role": "assistant", "content": reply}
    )


def start_scan_job():
    source_path = Path(st.session_state.source_dir).expanduser()

    if not source_path.exists():
        st.session_state.scan_error = f"소스 경로를 찾을 수 없습니다: {source_path}"
        st.session_state.scan_running = False
        finish_chat_scan()
        return

    if not source_path.is_dir():
        st.session_state.scan_error = f"입력한 경로가 폴더가 아닙니다: {source_path}"
        st.session_state.scan_running = False
        finish_chat_scan()
        return

    job_id = str(uuid.uuid4())
    with SCAN_JOB_STORE["lock"]:
        SCAN_JOB_STORE["jobs"][job_id] = {
            "status": "running",
            "progress": 0,
            "stage": "준비",
            "message": "보안점검을 시작하고 있습니다...",
            "result": None,
            "error": None,
        }
    st.session_state.active_scan_job_id = job_id
    st.session_state.scan_running = True
    worker = threading.Thread(
        target=run_security_agent_in_background,
        args=(job_id, source_path),
        daemon=True,
    )
    worker.start()


def get_scan_job(job_id):
    with SCAN_JOB_STORE["lock"]:
        job = SCAN_JOB_STORE["jobs"].get(job_id)
        return dict(job) if job is not None else None


def publish_scan_job(job_id):
    job = get_scan_job(job_id)
    if not job or job.get("status") != "done":
        return False

    st.session_state.scan_result = job.get("result")
    st.session_state.scan_error = job.get("error")
    st.session_state.scan_running = False
    st.session_state.active_scan_job_id = None
    finish_chat_scan()
    with SCAN_JOB_STORE["lock"]:
        SCAN_JOB_STORE["jobs"].pop(job_id, None)
    return True


def rerun_app():
    if hasattr(st, "fragment"):
        st.rerun(scope="app")
    elif hasattr(st, "rerun"):
        st.rerun()
    else:
        st.experimental_rerun()


def render_scan_progress_contents(job_id):
    job = get_scan_job(job_id)
    if job is None:
        st.warning("점검 작업 정보를 찾을 수 없습니다. 다시 실행해 주세요.")
        st.session_state.scan_running = False
        st.session_state.active_scan_job_id = None
        rerun_app()

    st.subheader("🔍 보안점검 진행 상황")
    st.progress(int(job.get("progress", 0)))
    st.write(f"**현재 단계:** {job.get('stage', '분석 중')}")
    st.info(job.get("message") or "분석 중입니다...")

    if job.get("status") == "done" and publish_scan_job(job_id):
        rerun_app()


def render_scan_progress():
    job_id = st.session_state.active_scan_job_id
    if not job_id:
        return

    if hasattr(st, "fragment"):
        @st.fragment(run_every="1s")
        def progress_fragment():
            render_scan_progress_contents(job_id)

        progress_fragment()
    else:
        render_scan_progress_contents(job_id)
        st.caption(
            "현재 Streamlit 버전은 자동 진행 갱신을 지원하지 않습니다. "
            "채팅을 계속 사용할 수 있으며, 화면이 다시 그려질 때 진행 상황이 갱신됩니다."
        )


def is_scan_request(message):
    text = message.strip().lower()
    if text.startswith("/scan"):
        return True
    return bool(
        re.search(
            r"(?:보안\s*점검|취약점\s*점검|점검|스캔|security\s*scan)"
            r".{0,24}(?:해줘|해주세요|실행|시작|돌려|해봐)|"
            r"(?:점검|스캔)해\s*(?:줘|주세요)",
            text,
        )
    )


def answer_chat(message):
    from llm.qwen_client import chat_qwen

    history = st.session_state.chat_messages[-13:-1]
    messages = [
        {
            "role": "system",
            "content": (
                "당신은 사내 Qwen 기반 소스코드 보안점검 도우미입니다. "
                "한국어로 간결하고 정확하게 답하고, 실제 점검 결과가 없는 경우 "
                "점검을 완료했다고 말하지 마세요. 보안점검 실행은 앱에서 별도로 처리합니다."
            ),
        },
        *history,
        {"role": "user", "content": message},
    ]
    return chat_qwen(messages)


# ============================================================
# 결과 표시
# ============================================================
def show_result(result):
    if not isinstance(result, dict):
        st.warning("분석 결과 형식이 올바르지 않습니다.")
        return

    findings = result.get("findings") or result.get("vulnerabilities") or []
    report_path = (
        result.get("report_file")
        or result.get("report_path")
        or result.get("html_report")
    )

    st.success("보안점검이 완료되었습니다.")
    st.subheader("점검 결과")

    critical_count = sum(
        1 for finding in findings if finding.get("severity") == "CRITICAL"
    )
    high_count = sum(
        1 for finding in findings if finding.get("severity") == "HIGH"
    )
    medium_count = sum(
        1 for finding in findings if finding.get("severity") == "MEDIUM"
    )
    summary_cols = st.columns(5)
    summary_cols[0].metric("분석 파일", result.get("source_count", 0))
    summary_cols[1].metric("전체 취약점", len(findings))
    summary_cols[2].metric("Critical", critical_count)
    summary_cols[3].metric("High", high_count)
    summary_cols[4].metric("Medium", medium_count)

    if findings:
        st.subheader("취약점 목록")
        for index, finding in enumerate(findings, 1):
            vulnerability_type = finding.get("type", "-")
            severity = finding.get("severity", "-")
            file_name = finding.get("file", "-")
            line = finding.get("line", "-")

            with st.expander(
                f"{index}. {vulnerability_type} [{severity}] {file_name}:{line}"
            ):
                col1, col2, col3 = st.columns(3)
                col1.write("**심각도**")
                col1.write(severity)
                col2.write("**상태**")
                col2.write(finding.get("status", "-"))
                col3.write("**신뢰도**")
                col3.write(finding.get("confidence", "-"))

                st.write(f"**탐지 방법:** {finding.get('detection', '-')}")
                st.write(f"**파일:** {file_name}")
                st.write(f"**라인:** {line}")
                st.markdown("#### 🔎 증거")
                st.code(finding.get("evidence", "-"), language="text")
                st.markdown("#### 설명")
                st.write(finding.get("description", "-"))
                st.markdown("#### AI 판단 근거")
                st.write(finding.get("reason", "-"))
                st.markdown("#### 🛠 개선 방법")
                st.write(finding.get("recommendation", "-"))
    else:
        st.success("취약점이 발견되지 않았습니다.")

    if report_path:
        st.divider()
        st.subheader("HTML 리포트")
        st.success("HTML 보안 리포트가 생성되었습니다.")
        st.code(str(report_path), language="text")

        report_file = Path(report_path)
        if report_file.exists():
            st.download_button(
                "📥 HTML 리포트 다운로드",
                data=report_file.read_bytes(),
                file_name=report_file.name,
                mime="text/html",
                use_container_width=True,
            )


# ============================================================
# 화면
# ============================================================
st.title("🔐 AI Source Security Analyzer")
st.write("Java / JavaScript / JSP 소스코드를 AI 기반으로 보안 점검합니다.")
st.divider()

scan_col, chat_col = st.columns([2, 1], gap="large")

with scan_col:
    st.subheader("소스 코드")
    col1, col2 = st.columns([5, 1])

    is_scanning = st.session_state.scan_running

    with col1:
        st.text_input(
            "소스 코드 경로",
            key="source_dir",
            disabled=is_scanning,
            label_visibility="collapsed",
        )

    with col2:
        st.button(
            "📁 폴더 선택",
            on_click=select_folder,
            disabled=is_scanning,
            use_container_width=True,
        )

    st.caption(
        "선택한 폴더와 하위 폴더에서 Java / JavaScript / JSP 파일을 자동으로 탐색합니다."
    )
    st.divider()

    st.button(
        "🔍 보안 점검 시작",
        disabled=is_scanning,
        type="primary",
        use_container_width=True,
        on_click=request_scan,
    )

    if should_run_scan:
        start_scan_job()
        st.rerun()

    render_scan_progress()

    if st.session_state.scan_error:
        st.error(st.session_state.scan_error)

    if st.session_state.scan_result is not None:
        st.divider()
        show_result(st.session_state.scan_result)

with chat_col:
    st.subheader("💬 Qwen 채팅")
    st.caption(
        "점검 중에도 대화할 수 있습니다. 일반 질문이나 ‘현재 선택한 폴더 보안점검 해줘’를 입력하세요."
    )
    for chat_message in st.session_state.chat_messages:
        with st.chat_message(chat_message["role"]):
            st.markdown(chat_message["content"])

    prompt = st.chat_input(
        "Qwen에게 질문하거나 보안점검을 요청하세요",
    )
    if prompt:
        st.session_state.chat_messages.append(
            {"role": "user", "content": prompt}
        )
        if is_scan_request(prompt):
            st.session_state.chat_scan_pending = True
            request_scan()
            st.rerun()
        else:
            with st.spinner("Qwen이 답변을 작성하고 있습니다..."):
                try:
                    answer = answer_chat(prompt)
                except Exception as error:
                    answer = (
                        "Qwen에 연결하지 못했습니다. 사내 Qwen 연결 설정과 네트워크를 "
                        f"확인해 주세요. 상세 오류: {error}"
                    )
            st.session_state.chat_messages.append(
                {"role": "assistant", "content": answer}
            )
            st.rerun()
