# GitHub push 자동 보안점검

`.github/workflows/security-scan.yml`은 이 저장소에 push하거나 Pull Request를
열 때 GitHub Actions에서 Java, JavaScript, JSP 파일을 점검합니다. 기존
`SecurityAgent`를 실행하고, 결과 보고서를 workflow run의 **Artifacts**에
30일 동안 보관합니다. 기본 차단 기준은 AI가 확정한 Critical/High 취약점이며,
기준은 workflow의 `SECURITY_FAIL_ON` 값으로 변경할 수 있습니다.

## Qwen 서버 연결

GitHub-hosted runner는 GitHub가 제공하는 외부 실행 환경입니다. 기존 Qwen API
주소는 `app/llm/qwen_client.py`의 `BASE_URL`에 설정되어 있으므로, Actions runner가
그 주소로 네트워크 연결을 할 수 있어야 AI 분석도 동작합니다. 사내망에서만
접근 가능한 주소라면 GitHub-hosted runner에서는 연결되지 않습니다. workflow는
AI 분석 중 Qwen 요청이 실패하면 작업도 실패 처리하도록 설정되어 있어, Rule
결과만으로 성공한 것으로 표시하지 않습니다. 전체 Qwen 분석이 필요하면 사내
네트워크에 연결된 GitHub self-hosted runner를 사용해야 합니다.

## 확인 방법

1. 이 브랜치의 workflow를 GitHub 저장소에 push합니다.
2. 저장소의 **Actions** 탭에서 **AI Security Scan** 실행을 엽니다.
3. `Scan Java, JavaScript, and JSP sources` 작업 로그에서 분석 결과와 Qwen 연결
   오류 여부를 확인합니다.
4. 작업 페이지의 **Artifacts**에서 HTML 보고서와 JSON 결과를 내려받습니다.

의존성은 `requirements-ci.txt`에 정의되어 있으며 GitHub-hosted runner가 패키지
저장소에 접근해 설치합니다. 외부 패키지 다운로드가 제한된 조직은 승인된 내부
패키지 미러나 사전 구성된 runner 이미지를 사용해야 합니다.
