"""
config.py
Central configuration for the AI-Enhanced SIEM System.

All values can be overridden with environment variables so that the
same codebase works for local development, classroom demos, and a
"real" AI-connected deployment without touching source code.
"""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent


class Config:
    # --- Flask -----------------------------------------------------------
    SECRET_KEY = os.environ.get("SIEM_SECRET_KEY", "dev-secret-key-change-in-production")
    DEBUG = os.environ.get("SIEM_DEBUG", "true").lower() == "true"

    # --- Storage -----------------------------------------------------------
    BASE_DIR = BASE_DIR
    UPLOAD_FOLDER = str(BASE_DIR / "logs")
    DATABASE_PATH = str(BASE_DIR / "data" / "siem.db")
    REPORTS_FOLDER = str(BASE_DIR / "reports" / "generated")

    ALLOWED_EXTENSIONS = {"log", "txt"}
    MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10 MB per uploaded file

    # --- Rule Engine thresholds -------------------------------------------
    # Number of failed logins from the same IP within the time window below
    # before it is flagged as a brute-force attempt.
    BRUTE_FORCE_FAILED_ATTEMPTS = 5
    BRUTE_FORCE_WINDOW_MINUTES = 10

    # Number of distinct usernames targeted by the same IP within the
    # window below before it is flagged as suspicious / credential-stuffing
    # style activity.
    SUSPICIOUS_IP_DISTINCT_USERS = 4
    SUSPICIOUS_IP_WINDOW_MINUTES = 15

    # --- AI Engine -----------------------------------------------------------
    # AI_PROVIDER: "openai" | "ollama" | "simulated"
    #   openai     -> calls the OpenAI Chat Completions API (needs OPENAI_API_KEY)
    #   ollama     -> calls a local Ollama server (e.g. Llama 3 / Mistral)
    #   simulated  -> deterministic, rule-grounded local summarizer that
    #                 needs no internet connection or API key. This is the
    #                 default so the project runs out-of-the-box for
    #                 demos/grading, and automatically stops being used the
    #                 moment a real provider is configured.
    AI_PROVIDER = os.environ.get("SIEM_AI_PROVIDER", "simulated")

    OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
    OPENAI_MODEL = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
    OPENAI_API_URL = "https://api.openai.com/v1/chat/completions"

    OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
    OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3")

    AI_REQUEST_TIMEOUT_SECONDS = 20
