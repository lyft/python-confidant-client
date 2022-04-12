from typing import Dict


def format_cred_key(key: str, prefix: str) -> str:
    return f"{prefix}{key}".upper()


# Avoids passing the user's AWS auth session into the running process by
# removing environmental variables that have these keys
# XXX: TODO move to ~/.confidant
def sanitize_secrets(secrets: Dict[str, str]) -> None:
    remove = ['AWS_ACCESS_KEY_ID',
              'AWS_SECRET_ACCESS_KEY',
              'AWS_SECURITY_TOKEN',
              'AWS_SESSION_TOKEN']

    for key in remove:
        if secrets.get(key):
            del secrets[key]
