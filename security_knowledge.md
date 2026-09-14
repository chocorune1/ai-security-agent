# SQL Injection

## 설명

SQL Injection은 외부 입력값이 SQL 문장의 일부로 직접 연결될 때 발생할 수 있는 취약점이다.

공격자가 입력값을 조작하면 원래 의도하지 않은 SQL 조건이나 명령이 실행될 수 있다.

## 위험

- 인증 우회
- 데이터 조회
- 데이터 변경
- 민감정보 노출
- 데이터베이스 권한에 따른 추가 공격

## 안전한 처리 방법

PreparedStatement를 사용할 경우 SQL 구조와 사용자 입력값을 분리할 수 있다.

잘못된 예:

String sql = "SELECT * FROM USERS WHERE USER_ID = '" + userId + "'";

권장 예:

String sql = "SELECT * FROM USERS WHERE USER_ID = ?";
PreparedStatement stmt = conn.prepareStatement(sql);
stmt.setString(1, userId);

## 판단 기준

사용자 입력값이 SQL 문자열에 직접 연결되는지 확인해야 한다.


# Command Injection

## 설명

Command Injection은 외부 입력값이 운영체제 명령 실행에 직접 사용될 때 발생할 수 있는 취약점이다.

## 위험

공격자가 명령어를 조작하여 서버에서 의도하지 않은 명령을 실행할 수 있다.

## 위험한 코드

Runtime.getRuntime().exec(command);

## 안전한 처리 방법

외부 입력값을 OS 명령어에 직접 전달하지 않는 것이 가장 안전하다.

부득이한 경우 허용된 명령과 인자만 사용할 수 있도록 allowlist 기반 검증을 적용해야 한다.

## 판단 기준

Runtime.exec, ProcessBuilder 등으로 전달되는 값이 외부 입력에 의해 결정되는지 확인한다.


# Hard-coded Credential

## 설명

비밀번호, API Key, Secret 등의 인증정보를 소스코드에 직접 저장하는 방식이다.

## 위험

소스코드가 유출되거나 저장소에 접근할 수 있는 사람이 인증정보를 획득할 수 있다.

## 위험한 코드

private String dbPassword = "admin1234";

## 안전한 처리 방법

인증정보는 소스코드에 저장하지 않고 환경변수 또는 Secret 관리 시스템을 사용한다.

## 판단 기준

password, passwd, secret, api_key 등의 변수에 실제 인증정보가 문자열로 직접 할당되어 있는지 확인한다.


# Cross-Site Scripting

## 설명

XSS는 공격자가 제어할 수 있는 값이 HTML 또는 JavaScript 문맥에서 안전하게 처리되지 않고 브라우저에서 실행될 때 발생할 수 있는 취약점이다.

## 위험

- 사용자 세션 탈취
- 악성 스크립트 실행
- 사용자 정보 탈취
- 피싱 페이지 삽입

## 안전한 처리 방법

HTML 출력 시 컨텍스트에 맞는 인코딩을 적용하고 사용자 입력값을 신뢰하지 않는다.

## 판단 기준

사용자 입력이 HTML, JavaScript, DOM 등에 직접 삽입되는지 확인한다.


# Path Traversal

## 설명

Path Traversal은 외부 입력값이 파일 경로에 직접 사용되어 의도하지 않은 파일에 접근할 수 있는 취약점이다.

## 위험

공격자가 ../ 등의 경로 조작을 이용하여 서버의 허용되지 않은 파일에 접근할 수 있다.

## 안전한 처리 방법

파일 경로를 직접 조합하지 말고 허용된 파일 목록 또는 안전한 기준 경로를 사용한다.

사용자 입력에 대한 경로 정규화 및 allowlist 검증을 적용한다.

## 판단 기준

사용자 입력이 File, Path, InputStream 등의 파일 접근 API에 직접 전달되는지 확인한다.
