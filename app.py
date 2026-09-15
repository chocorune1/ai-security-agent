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
# 보안점검 시작
# ============================================================

def start_scan():
    st.session_state.scanning = True
    st.session_state.scan_result = None


# ============================================================
# 화면
# ============================================================

st.title("🔐 AI Source Security Analyzer")

st.write(
    "Java / JavaScript / JSP 소스코드를 "
    "AI 기반으로 보안 점검합니다."
)

st.divider()


# ============================================================
# 소스 코드 경로
# ============================================================

st.subheader("소스 코드")

col1, col2 = st.columns([5, 1])

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
# 보안점검 실행
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
    # Security Agent Import
    # --------------------------------------------------------

    try:

        from agent.security_agent import SecurityAgent

    except Exception as e:

        st.error(
            "Security Agent를 불러오지 못했습니다."
        )

        st.exception(e)

        st.session_state.scanning = False

        st.stop()


    # --------------------------------------------------------
    # 진행 화면
    # --------------------------------------------------------

    st.divider()

    st.subheader(
        "보안점검 진행 상황"
    )

    progress = st.progress(0)

    status = st.empty()


    # --------------------------------------------------------
    # Agent 실행
    # --------------------------------------------------------

    try:

        progress.progress(10)

        status.info(
            "AI Security Agent를 준비하고 있습니다..."
        )


        progress.progress(20)

        status.info(
            "소스코드를 수집하고 있습니다..."
        )


        agent = SecurityAgent()


        progress.progress(30)

        status.info(
            "Rule Scanner로 소스코드를 분석하고 있습니다..."
        )


        result = agent.run(
            mode="full",
            source_dir=str(source_path)
        )


        progress.progress(100)

        status.success(
            "보안점검이 완료되었습니다."
        )


        st.session_state.scan_result = result

        st.session_state.scanning = False


    except Exception as e:

        progress.empty()

        status.empty()

        st.error(
            "보안점검 중 오류가 발생했습니다."
        )

        st.exception(e)

        st.session_state.scanning = False

        st.stop()


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
        if finding.get("severity") == "CRITICAL"
    )


    high_count = sum(
        1
        for finding in findings
        if finding.get("severity") == "HIGH"
    )


    medium_count = sum(
        1
        for finding in findings
        if finding.get("severity") == "MEDIUM"
    )


    low_count = sum(
        1
        for finding in findings
        if finding.get("severity") == "LOW"
    )


    col1, col2, col3, col4, col5 = st.columns(5)


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

                col1, col2, col3 = st.columns(3)


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
