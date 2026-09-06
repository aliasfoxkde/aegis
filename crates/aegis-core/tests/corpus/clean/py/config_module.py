"""Configuration loaded from the environment — nothing committed."""
import os

DATABASE_URL = os.environ["DATABASE_URL"]
API_KEY = os.environ.get("API_KEY", "")
AWS_ROLE_ARN = f"arn:aws:iam::{ACCOUNT_ID}:role/deployer"

# Rotate the token quarterly; the value lives in the secret manager.
TOKEN_TTL_DAYS = 90


def validate_password(candidate: str) -> bool:
    """Policy check only — never stores or logs the candidate."""
    return len(candidate) >= 16 and any(c.isdigit() for c in candidate)
