# GitLab push 자동 보안점검

`.gitlab-ci.yml`은 push와 Merge Request 파이프라인에서 저장소의 Java,
JavaScript, JSP 파일을 찾아 기존 `SecurityAgent`로 검사합니다. 점검 결과는
파이프라인 작업의 **Artifacts**에서 HTML 보고서와 `security_scan.json`으로
받을 수 있습니다.

## GitLab Runner 준비

이 저장소의 Qwen API 주소는 `app/llm/qwen_client.py`의 `BASE_URL`에 설정되어
있습니다. 전체 Rule + Qwen 분석을 수행하려면 GitLab Runner가 해당 사내 주소에
네트워크로 연결되어야 합니다. 회사 네트워크에 연결된 Docker Runner를 사용하고,
Runner에서 Python 패키지 인덱스에 접근할 수 있는지 확인하세요. 이 프로젝트는
`.env`를 사용하지 않습니다.

## 적용 방법

1. `.gitlab-ci.yml`, `requirements-ci.txt`, `app/ci_scan.py`, `GITLAB_CI.md`를
   GitLab 저장소의 루트/경로에 반영합니다.
2. GitLab에서 프로젝트의 **Build > Pipelines**가 활성화되어 있고 Runner가
   해당 프로젝트에 할당되어 있는지 확인합니다.
3. 변경사항을 GitLab 브랜치에 push합니다. `security_scan` 작업이 실행됩니다.
4. 작업이 끝나면 파이프라인 작업 페이지의 **Artifacts**에서 HTML 및 JSON 결과를
   내려받습니다.

기본 차단 기준은 `CRITICAL,HIGH`이며, AI 상태가 `CONFIRMED` 또는
`AI_CONFIRMED`인 경우 파이프라인을 실패시킵니다. 미확정 검토 항목은 결과에
기록하되 push를 차단하지 않습니다. 프로젝트의 GitLab CI/CD 변수
`SECURITY_FAIL_ON`을 예를 들어 `CRITICAL`로 지정해 기준을 조정할 수 있습니다.
빈 값으로 두면 취약점 발견으로 인한 실패를 비활성화합니다.

Python 의존성 설치나 사내 Qwen 서버 접속이 차단되어 있으면 작업이 완료되지
않거나 Qwen 분석을 수행할 수 없습니다. 이 경우 회사 네트워크에서 실행되는
Runner와 사내 패키지 미러를 사용해야 합니다.
