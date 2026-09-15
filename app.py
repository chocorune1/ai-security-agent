import sys
from pathlib import Path

import streamlit as st


# ==================================================
# 프로젝트 경로
# ==================================================

BASE_DIR = Path(__file__).resolve().parents[1]
APP_DIR = BASE_DIR / "app"

if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))


# ==================================================
# Streamlit 페이지 설정
# ==================================================

st.set_page_config(
    page_title="AI Source Security Analyzer",
    page_icon="🔐",
    layout="wide"
)


# ==================================================
# 화면
# ==================================================

st.title("🔐 AI Source Security Analyzer")

st.write(
    "Java / JavaScript / JSP 소스코드를 "
    "AI 기반으로 보안 점검합니다."
)

st.divider()


# ==================================================
# 점검 설정
# ==================================================

st.subheader("점검 설정")

source_dir = st.text_input(
    "소스 코드 경로",
    value=str(
        BASE_DIR / "data" / "source"
    )
)

st.caption(
    "현재 지원하는 점검 방식: 전체 소스 점검"
)


# ==================================================
# 점검 시작
# ==================================================

if st.button(
    "🔍 보안 점검 시작",
    type="primary"
):

    source_path = Path(
        source_dir
    )

    # ----------------------------------------------
    # 경로 확인
    # ----------------------------------------------

    if not source_path.exists():

        st.error(
            f"소스 경로를 찾을 수 없습니다.\n\n"
            f"{source_path}"
        )

        st.stop()


    if not source_path.is_dir():

        st.error(
            "입력한 경로가 폴더가 아닙니다."
        )

        st.stop()


    # ----------------------------------------------
    # Agent import
    # ----------------------------------------------

    try:

        from agent.security_agent import SecurityAgent

    except Exception as e:

        st.error(
            "Security Agent를 불러오지 못했습니다."
        )

        st.exception(e)

        st.stop()


    # ----------------------------------------------
    # Agent 실행
    # ----------------------------------------------

    st.info(
        "AI Security Agent가 "
        "소스코드를 분석하고 있습니다."
    )

    progress = st.progress(0)

    status = st.empty()

    try:

        status.write(
            "소스코드를 수집하고 있습니다..."
        )

        progress.progress(10)


        agent = SecurityAgent()


        status.write(
            "Rule Scanner와 AI 분석을 시작합니다..."
        )

        progress.progress(20)


        result = agent.run(
            mode="full",
            source_dir=str(
                source_path
            )
        )


        progress.progress(100)

        status.success(
            "보안점검이 완료되었습니다."
        )


    except Exception as e:

        progress.empty()

        status.empty()

        st.error(
            "보안점검 중 오류가 발생했습니다."
        )

        st.exception(e)

        st.stop()


    # ==================================================
    # 결과
    # ==================================================

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


    st.divider()

    st.subheader(
        "점검 결과"
    )


    # ==================================================
    # 결과 요약
    # ==================================================

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


    # ==================================================
    # 취약점 목록
    # ==================================================

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

                col1.write(
                    f"**심각도**\n\n"
                    f"{severity}"
                )

                col2.write(
                    f"**상태**\n\n"
                    f"{finding.get('status', '-')}"
                )

                col3.write(
                    f"**신뢰도**\n\n"
                    f"{finding.get('confidence', '-')}"
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


    # ==================================================
    # HTML Report
    # ==================================================

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
