import requests


BASE_URL = "http://107.120.93.129:4307/v1"
MODEL_ID = "Qwen3.8-27B"
QWEN_REQUEST_ERRORS = 0


def ask_qwen(prompt):
    global QWEN_REQUEST_ERRORS
    url = f"{BASE_URL}/chat/completions"

    payload = {
        "model": MODEL_ID,
        "messages": [
            {
                "role": "user",
                "content": prompt
            }
        ],
        "temperature": 0.1
    }

    try:
        response = requests.post(
            url,
            json=payload,
            timeout=120
        )
        response.raise_for_status()
        result = response.json()
        return result["choices"][0]["message"]["content"]
    except Exception:
        QWEN_REQUEST_ERRORS += 1
        raise
