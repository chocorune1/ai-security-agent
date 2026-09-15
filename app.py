import sys
from pathlib import Path
import tkinter as tk
from tkinter import filedialog
import threading
import time

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
    layout="wide"
)


# ============================================================
# Session State
# ============================================================

if "source_dir" not in st.session_state:
    st.session_state.source_dir = str(
        BASE_DIR / "data" / "source"
    )

if "scanning" not in st.session_state:
    st.session_state.scanning = False

if "scan_result" not in st.session_state:
    st.session_state.scan_result = None

if "scan_error" not in st.session_state:
    st.session_state.scan_error = None

if "scan_state" not in st.session_state:
    st.session_state.scan_state = {
        "progress": 0,
        "message": "",
        "done": False,
        "result": None,
        "error": None
    }

if "scan_start_time" not in st.session_state:
    st.session_state.scan_start_time = None


# ============================================================
# 폴더 선택
# ============================================================

def select_folder():

    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)

    selected_folder = filedialog.askdirectory(
        title="보안점검할 소스 폴더 선택"
    )

    root.destroy()

    if selected_folder:
        st.session_state.source_dir = selected_folder


# ============================================================
# Agent 실행 Thread
# ============================================================

def run_security_agent(
    source_path,
    scan_state
):

    try:

        from agent.security_agent import SecurityAgent

        agent = SecurityAgent(
            source_dir=str(source_path)
        )

        result = agent.run(
            progress_callback=(
                lambda progress, message:
                update_scan_state(
                    scan_state,
                    progress,
                    message
                )
            )
        )

        scan_state["progress"] = 100

        scan_state["message"] = (
            "보안점검이 완료되었습니다."
        )

        scan_state["result"] = result

        scan_state["done"] = True

    except Exception as e:

        scan_state["error"] = e
        scan_state["done"] = True


# ============================================================
# 진행상황 업데이트
# ============================================================

def update_scan_state(
    scan_state,
    progress,
    message
):

    scan_state["progress"] = progress
    scan_state["message"] = message


# ============================================================
# 보안점검 시작
# ============================================================

def start_scan():

    st.session_state.scanning = True

    st.session_state.scan_result = None

    st.session_state.scan_error = None

    st.session_state.scan_start_time = time.time()

    scan_state = {
        "progress": 5,
        "message": (
            "보안점검을 준비하고 있습니다..."
        ),
        "done": False,
        "result": None,
        "error": None
    }

    st.session_state.scan_state = scan_state

    source_path = Path(
        st.session_state.source_dir
    )

    scan_thread = threading.Thread(
        target=run_security_agent,
        args=(
            source_path,
            scan_state
        ),
        daemon=True
    )

    scan_thread.start()


# ============================================================
# 화면
# ============================================================

st.title(
    "🔐 AI Source Security Analyzer"
)

st.write(
    "Java / JavaScript / JSP 소스코드를 "
    "AI 기반으로 보안 점검합니다."
)

st.divider()


# ============================================================
# 소스 코드 경로
# ============================================================

st.subheader(
    "소스 코드"
)

col1, col2 = st.columns(
    [5, 1]
)

with col1:

    st.text_input(
        "소스 코드 경로",
        key="source_dir",
        disabled=st.session_state.scanning,
        label_visibility="collapsed"
    )

with col2:

    st.button(
        "📁 폴더 선택",
        on_click=select_folder,
        disabled=st.session_state.scanning,
        use_container_width=True
    )


st.caption(
    "선택한 폴더와 하위 폴더에서 "
    "Java / JavaScript / JSP 파일을 자동으로 탐색합니다."
)

st.divider()


# ============================================================
# 보안점검 시작 버튼
# ============================================================

st.button(
    "🔍 보안 점검 시작",
    on_click=start_scan,
    disabled=st.session_state.scanning,
    type="primary",
    use_container_width=True
)


# ============================================================
# 보안점검 진행
# ============================================================

if st.session_state.scanning:

    source_path = Path(
        st.session_state.source_dir
    )

    # --------------------------------------------------------
    # 경로 확인
    # --------------------------------------------------------

    if not source_path.exists():

        st.error(
            "소스 경로를 찾을 수 없습니다."
        )

        st.code(
            str(source_path)
        )

        st.session_state.scanning = False

        st.stop()


    if not source_path.is_dir():

        st.error(
            "입력한 경로가 폴더가 아닙니다."
        )

        st.code(
            str(source_path)
        )

        st.session_state.scanning = False

        st.stop()


    # --------------------------------------------------------
    # 진행 화면
    # --------------------------------------------------------

    st.divider()

    st.subheader(
        "🔍 보안점검 진행 상황"
    )

    progress_placeholder = st.empty()

    status_placeholder = st.empty()

    stage_placeholder = st.empty()

    elapsed_placeholder = st.empty()


    scan_state = (
        st.session_state.scan_state
    )


    # --------------------------------------------------------
    # Agent 실행 완료까지 화면 갱신
    # --------------------------------------------------------

    while not scan_state["done"]:

        current_progress = scan_state.get(
            "progress",
            0
        )

        current_message = scan_state.get(
            "message",
            "보안점검을 준비하고 있습니다..."
        )


        # 진행률
        progress_placeholder.progress(
            current_progress
        )


        # 현재 작업
        status_placeholder.info(
            "🔄 "
            + current_message
        )


        # 현재 단계
        if current_progress < 20:

            current_stage = (
                "① 소스코드 수집"
            )

        elif current_progress < 40:

            current_stage = (
                "② Rule 기반 보안점검"
            )

        elif current_progress < 65:

            current_stage = (
                "③ Qwen AI 보안 분석"
            )

        elif current_progress < 80:

            current_stage = (
                "④ Rule 탐지 결과 AI 검증"
            )

        elif current_progress < 90:

            current_stage = (
                "⑤ 보안점검 결과 통합"
            )

        elif current_progress < 100:

            current_stage = (
                "⑥ HTML 리포트 생성"
            )

        else:

            current_stage = (
                "✓ 보안점검 완료"
            )


        stage_placeholder.write(
            f"**현재 단계:** {current_stage}"
        )


        # 경과 시간
        if st.session_state.scan_start_time:

            elapsed_seconds = int(
                time.time()
                - st.session_state.scan_start_time
            )

            elapsed_placeholder.caption(
                f"⏱ 경과 시간: "
                f"{elapsed_seconds}초"
            )


        # 오류
        if scan_state.get("error"):

            st.error(
                "보안점검 중 오류가 발생했습니다."
            )

            st.exception(
                scan_state["error"]
            )

            st.session_state.scan_error = (
                scan_state["error"]
            )

            st.session_state.scanning = False

            st.stop()


        # 0.3초마다 진행상태 확인
        time.sleep(0.3)


    # --------------------------------------------------------
    # 완료
    # --------------------------------------------------------

    progress_placeholder.progress(
        100
    )

    status_placeholder.success(
        "✅ 보안점검이 완료되었습니다."
    )

    stage_placeholder.write(
        "**현재 단계:** ✓ 보안점검 완료"
    )


    if st.session_state.scan_start_time:

        elapsed_seconds = int(
            time.time()
            - st.session_state.scan_start_time
        )

        elapsed_placeholder.caption(
            f"⏱ 총 소요 시간: "
            f"{elapsed_seconds}초"
        )


    st.session_state.scan_result = (
        scan_state.get("result")
    )

    st.session_state.scanning = False


# ============================================================
# 결과 표시
# ============================================================

result = st.session_state.scan_result


if result is not None:

    findings = result.get(
        "findings",
        []
    )

    report_file = result.get(
        "report_file"
    )

    source_count = result.get(
        "source_count",
        0
    )


    # ========================================================
    # 결과 요약
    # ========================================================

    st.divider()

    st.subheader(
        "점검 결과"
    )


    critical_count = sum(
        1
        for finding in findings
        if finding.get("severity")
        == "CRITICAL"
    )


    high_count = sum(
        1
        for finding in findings
        if finding.get("severity")
        == "HIGH"
    )


    medium_count = sum(
        1
        for finding in findings
        if finding.get("severity")
        == "MEDIUM"
    )


    low_count = sum(
        1
        for finding in findings
        if finding.get("severity")
        == "LOW"
    )


    col1, col2, col3, col4, col5 = (
        st.columns(5)
    )


    col1.metric(
        "분석 파일",
        source_count
    )


    col2.metric(
        "전체 취약점",
        len(findings)
    )


    col3.metric(
        "Critical",
        critical_count
    )


    col4.metric(
        "High",
        high_count
    )


    col5.metric(
        "Medium",
        medium_count
    )


    # ========================================================
    # 취약점 목록
    # ========================================================

    st.subheader(
        "취약점 목록"
    )


    if not findings:

        st.success(
            "취약점이 발견되지 않았습니다."
        )

    else:

        for index, finding in enumerate(
            findings,
            start=1
        ):

            vulnerability_type = finding.get(
                "type",
                "-"
            )

            severity = finding.get(
                "severity",
                "-"
            )

            file_name = finding.get(
                "file",
                "-"
            )

            line = finding.get(
                "line",
                "-"
            )


            with st.expander(
                f"{index}. "
                f"{vulnerability_type} "
                f"[{severity}] "
                f"{file_name}:{line}"
            ):

                col1, col2, col3 = (
                    st.columns(3)
                )


                with col1:

                    st.write(
                        "**심각도**"
                    )

                    st.write(
                        severity
                    )


                with col2:

                    st.write(
                        "**상태**"
                    )

                    st.write(
                        finding.get(
                            "status",
                            "-"
                        )
                    )


                with col3:

                    st.write(
                        "**신뢰도**"
                    )

                    st.write(
                        finding.get(
                            "confidence",
                            "-"
                        )
                    )


                st.write(
                    f"**탐지 방법:** "
                    f"{finding.get('detection', '-')}"
                )


                st.write(
                    f"**파일:** "
                    f"{file_name}"
                )


                st.write(
                    f"**라인:** "
                    f"{line}"
                )


                st.markdown(
                    "#### 🔎 증거"
                )


                st.code(
                    finding.get(
                        "evidence",
                        "-"
                    ),
                    language="text"
                )


                st.markdown(
                    "#### 설명"
                )


                st.write(
                    finding.get(
                        "description",
                        "-"
                    )
                )


                st.markdown(
                    "#### AI 판단 근거"
                )


                st.write(
                    finding.get(
                        "reason",
                        "-"
                    )
                )


                st.markdown(
                    "#### 🛠 개선 방법"
                )


                st.write(
                    finding.get(
                        "recommendation",
                        "-"
                    )
                )


    # ========================================================
    # HTML 리포트
    # ========================================================

    if report_file:

        st.divider()

        st.subheader(
            "HTML 리포트"
        )

        st.success(
            "HTML 보안 리포트가 생성되었습니다."
        )

        st.code(
            str(report_file),
            language="text"
        )
