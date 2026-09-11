import requests


BASE_URL = "http://107.120.93.129:4307/v1"
MODEL_ID = "Qwen3.8-27B"


def ask_qwen(prompt):
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

    response = requests.post(
        url,
        json=payload,
        timeout=120
    )

    response.raise_for_status()

    result = response.json()

    return result["choices"][0]["message"]["content"]
