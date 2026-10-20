import requests


BASE_URL = "http://107.120.93.129:4307/v1"
MODEL_ID = "Qwen3.8-27B"


def _request_qwen(messages, temperature):
    """Call the project's configured OpenAI-compatible Qwen endpoint."""
    response = requests.post(
        f"{BASE_URL.rstrip('/')}/chat/completions",
        json={
            "model": MODEL_ID,
            "messages": messages,
            "temperature": temperature,
        },
        timeout=120,
    )
    response.raise_for_status()
    return response.json()["choices"][0]["message"]["content"]


def chat_qwen(messages):
    """Send chat history to Qwen using BASE_URL and MODEL_ID."""
    return _request_qwen(messages, temperature=0.3)


def ask_qwen(prompt):
    return _request_qwen(
        [{"role": "user", "content": prompt}], temperature=0.1
    )
