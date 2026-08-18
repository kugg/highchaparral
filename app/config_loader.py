import os

def load_config(config_path="config/environment.txt"):
    config = {}
    try:
        with open(config_path, "r") as f:
            for line in f:
                line = line.strip()
                if line and "=" in line:
                    key, _, value = line.partition("=")
                    config[key] = value
    except FileNotFoundError:
        pass
    return config

SENSITIVE_KEYS = [
    "OPLANE_API_KEY",
    "OPLANE_GIT_TOKEN",
    "AZURE_OPENAI_ENDPOINT",
    "ANTHROPIC_API_KEY",
    "AWS_REGION",
]

def check_sensitive_keys():
    config = load_config()
    return {k: k in config for k in SENSITIVE_KEYS}
