import os
import secrets
from pathlib import Path


def main() -> None:
    destination = Path(__file__).resolve().parents[1] / ".env"
    if destination.exists():
        print("Existing local environment retained")
        return
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        for name in [
            "LEARNING_ADMIN_PASSWORD",
            "LEARNING_DEMO_PASSWORD",
            "LEARNING_AGENT_SECRET",
        ]:
            stream.write(name + "=" + secrets.token_urlsafe(32) + "\n")
    print("Generated private local demo credentials in ignored .env; values not displayed")


if __name__ == "__main__":
    main()
