import sys
from pathlib import Path
import tkinter as tk
from tkinter import filedialog
import threading
import uuid

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
# 프로세스 수준 Job Store
# - Streamlit session이 다시 생성되어도 백그라운드 작업을 잃지 않도록
#   실제 작업 상태는 모듈 전역에 보관합니다.
# ============================================================
if "JOB_STORE" not in globals():
    JOB_STORE = {}


# ============================================================
# Session State
# ============================================================
if "source_dir" not in st.session_state:
    st.session_state.source_dir = str(BASE_DIR / "data" / "source")

if "active_job_id" not in st.session_state:
    st.session_state.active_job_id = None


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
# Agent 실행 Thread
# ============================================================
def update_job_state(job_id, progress, message):
    job = JOB_STORE.get(job_id)
    if job is None:
        return

    job["progress"] = max(0, min(100, int(progress)))
    job["message"] = message or ""


def run_security_agent(job_id, source_path):
    try:
        from agent.security_agent import SecurityAgent

        job = JOB_STORE.get(job_id)
        if job is None:
            return

        job["stage"] = "Source Analyzer"
        job["message"] = "소스코드를 수집하고 있습니다..."
        job["progress"] = 5

        agent = SecurityAgent(source_dir=str(source_path))
        result = agent.run(
            progress_callback=lambda progress, message: update_job_state(
                job_id, progress, message
            )
        )

        job["progress"] = 100
        job["stage"] = "완료"
        job["message"] = "보안점검이 완료되었습니다."
        job["result"] = result
        job["done"] = True

    except Exception as e:
        job = JOB_STORE.get(job_id)
        if job is not None:
            job["error"] = e
            job["stage"] = "오류"
            job["message"] = "보안점검 중 오류가 발생했습니다."
            job["done"] = True


# ============================================================
# 보안점검 시작
# ============================================================
def start_scan():
    source_path = Path(st.session_state.source_dir)

    if not source_path.exists():
        st.error(f"소스 경로를 찾을 수 없습니다: {source_path}")
        return

    if not source_path.is_dir():
        st.error(f"입력한 경로가 폴더가 아닙니다: {source_path}")
        return

    job_id = str(uuid.uuid4())

    JOB_STORE[job_id] = {
        "progress": 0,
        "stage": "준비",
        "message": "보안점검을 준비하고 있습니다...",
        "done": False,
        "result": None,
        "error": None,
    }

    st.session_state.active_job_id = job_id

    thread = threading.Thread(
        target=run_security_agent,
        args=(job_id, source_path),
        daemon=True,
    )
    thread.start()


# ============================================================
# 결과 표시
# ============================================================
def show_result(result):
    if not isinstance(result, dict):
        st.warning("분석 결과 형식이 올바르지 않습니다.")
        return

    findings = result.get("findings") or result.get("vulnerabilities") or []
    report_path = result.get("report_path") or result.get("html_report")

    st.success("보안점검이 완료되었습니다.")

    if findings:
        st.subheader("🔎 취약점 목록")
        rows = []
        for index, finding in enumerate(findings, 1):
            rows.append(
                {
                    "No.": index,
                    "취약점": finding.get("type", "-"),
                    "Severity": finding.get("severity", "-"),
                    "파일": finding.get("file", "-"),
                    "라인": finding.get("line", "-"),
                    "상태": finding.get("status", "-"),
                    "신뢰도": finding.get("confidence", "-"),
                }
            )
        st.dataframe(rows, use_container_width=True, hide_index=True)
    else:
        st.info("취약점이 발견되지 않았습니다.")

    if report_path:
        st.subheader("📄 HTML 리포트")
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
# 진행 화면
# ============================================================
def render_scan_progress(job_id):
    job = JOB_STORE.get(job_id)

    if job is None:
        st.warning("점검 작업 정보를 찾을 수 없습니다. 다시 실행해 주세요.")
        st.session_state.active_job_id = None
        return

    st.divider()
    st.subheader("🔍 보안점검 진행 상황")

    progress = int(job.get("progress", 0))
    stage = job.get("stage", "분석 중")
    message = job.get("message", "")

    st.progress(progress)
    st.write(f"**현재 단계:** {stage}")
    st.info(message)

    if job.get("error") is not None:
        st.error(str(job["error"]))
        st.session_state.active_job_id = None
        return

    if job.get("done"):
        result = job.get("result")
        st.session_state.active_job_id = None
        show_result(result)
        return

    st.caption("분석이 진행 중입니다. 이 화면은 자동으로 갱신됩니다.")


# ============================================================
# 화면
# ============================================================
st.title("🔐 AI Source Security Analyzer")
st.write("Java / JavaScript / JSP 소스코드를 AI 기반으로 보안 점검합니다.")
st.divider()

st.subheader("소스 코드")
col1, col2 = st.columns([5, 1])

active_job_id = st.session_state.active_job_id
is_scanning = bool(active_job_id and active_job_id in JOB_STORE and not JOB_STORE[active_job_id].get("done"))

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

start_clicked = st.button(
    "🔍 보안 점검 시작",
    disabled=is_scanning,
    type="primary",
    use_container_width=True,
)

# 버튼 클릭을 현재 실행 사이클에서 직접 처리합니다.
# on_click 콜백보다 먼저 화면 상태를 확실히 반영할 수 있어
# 클릭 직후 버튼 비활성화 및 진행 화면 표시가 가능합니다.
if start_clicked:
    start_scan()


# ============================================================
# Streamlit Fragment 기반 진행상황 Polling
# while + sleep으로 전체 Streamlit 실행을 붙잡지 않습니다.
# ============================================================
if st.session_state.active_job_id and not start_clicked:
    if hasattr(st, "fragment"):

        @st.fragment(run_every="0.5s")
        def scan_progress_fragment():
            job_id = st.session_state.active_job_id
            if job_id:
                render_scan_progress(job_id)

        scan_progress_fragment()

    else:
        # 구버전 Streamlit에서는 자동 polling을 사용할 수 없습니다.
        # 분석 자체는 백그라운드 Thread에서 계속 실행됩니다.
        render_scan_progress(st.session_state.active_job_id)
        st.warning(
            "현재 Streamlit 버전에서는 자동 진행상황 갱신을 지원하지 않습니다. "
            "가능하면 Streamlit을 최신 버전으로 업데이트해 주세요."
        )
