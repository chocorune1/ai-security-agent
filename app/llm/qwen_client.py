import requests
import os
from pathlib import Path

try:
    from dotenv import load_dotenv
except ImportError:  # The project can also receive settings from the process env.
    load_dotenv = None


BASE_URL = "http://107.120.93.129:4307/v1"
MODEL_ID = "Qwen3.8-27B"


def _qwen_settings():
    env_file = Path(__file__).resolve().parents[2] / ".env"
    if load_dotenv is not None:
        load_dotenv(env_file)
    elif env_file.is_file():
        # Keep the feature usable in installations without python-dotenv.
        for line in env_file.read_text(encoding="utf-8").splitlines():
            key, separator, value = line.partition("=")
            if separator and key.strip() in {
                "QWEN_CODER_URL", "QWEN_URL", "QWEN_CODER_KEY",
                "QWEN_API_KEY", "QWEN_CODER_MODEL", "QWEN_MODEL",
            }:
                os.environ.setdefault(
                    key.strip(), value.strip().strip('"').strip("'")
                )

    base_url = (
        os.getenv("QWEN_CODER_URL")
        or os.getenv("QWEN_URL")
        or BASE_URL
    ).rstrip("/")
    api_key = os.getenv("QWEN_CODER_KEY") or os.getenv("QWEN_API_KEY")
    model = (
        os.getenv("QWEN_CODER_MODEL")
        or os.getenv("QWEN_MODEL")
        or MODEL_ID
    )
    return base_url, api_key, model


def chat_qwen(messages):
    """Send chat history to the configured OpenAI-compatible Qwen endpoint."""
    base_url, api_key, model = _qwen_settings()
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    response = requests.post(
        f"{base_url}/chat/completions",
        headers=headers,
        json={"model": model, "messages": messages, "temperature": 0.3},
        timeout=120,
    )
    response.raise_for_status()
    return response.json()["choices"][0]["message"]["content"]


def ask_qwen(prompt):
    base_url, api_key, model = _qwen_settings()
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    response = requests.post(
        f"{base_url}/chat/completions",
        headers=headers,
        json={
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.1,
        },
        timeout=120,
    )
    response.raise_for_status()
    return response.json()["choices"][0]["message"]["content"]
