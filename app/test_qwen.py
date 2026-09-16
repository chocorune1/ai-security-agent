from llm.qwen_client import ask_qwen


def main():

    prompt = """
당신은 소프트웨어 보안 분석 전문가입니다.

다음 질문에 간단하게 답해주세요.

SQL Injection이 무엇인지 한국어로 2~3문장으로 설명해주세요.
"""

    print("Qwen 호출 중...")
    print()

    answer = ask_qwen(prompt)

    print("===== Qwen 응답 =====")
    print(answer)
    print("====================")


if __name__ == "__main__":
    main()
