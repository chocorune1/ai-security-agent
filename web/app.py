import sys
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


def run_security_agent(source_path, progress_bar, stage_display, message_display):
    from agent.security_agent import SecurityAgent

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

        progress_bar.progress(progress)
        stage_display.write(f"**현재 단계:** {stage}")
        message_display.info(message or "분석 중입니다...")

    agent = SecurityAgent(source_dir=str(source_path))
    return agent.run(progress_callback=update_progress)


def execute_scan():
    source_path = Path(st.session_state.source_dir).expanduser()

    if not source_path.exists():
        st.session_state.scan_error = f"소스 경로를 찾을 수 없습니다: {source_path}"
        st.session_state.scan_running = False
        return

    if not source_path.is_dir():
        st.session_state.scan_error = f"입력한 경로가 폴더가 아닙니다: {source_path}"
        st.session_state.scan_running = False
        return

    st.divider()
    st.subheader("🔍 보안점검 진행 상황")
    progress_bar = st.progress(0)
    stage_display = st.empty()
    message_display = st.empty()
    stage_display.write("**현재 단계:** 준비")
    message_display.info("보안점검을 시작하고 있습니다...")

    try:
        st.session_state.scan_result = run_security_agent(
            source_path,
            progress_bar,
            stage_display,
            message_display,
        )
    except Exception as error:
        st.session_state.scan_error = str(error)
    finally:
        st.session_state.scan_running = False


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
    execute_scan()
    st.rerun()

if st.session_state.scan_error:
    st.error(st.session_state.scan_error)

if st.session_state.scan_result is not None:
    st.divider()
    show_result(st.session_state.scan_result)
