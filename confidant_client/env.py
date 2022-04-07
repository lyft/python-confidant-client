
import os
import click
import sys
from typing import Dict
from confidant_client import ConfidantClient
from kmsauth import TokenGenerationError


def format_cred_key(key: str, prefix: str) -> str:
    return f"{prefix}{key}".upper()


def get_service(
        client: ConfidantClient,
        service: str,
        prefix: str) -> Dict[str, str]:
    try:
        ret = client.get_service(service)
    except TokenGenerationError:
        sys.exit("Unable to locate AWS credentials.")

    cred_pairs = {}
    for cred in ret['service']['credentials']:
        for k, v in cred['credential_pairs'].items():
            cred_pairs[format_cred_key(k, prefix)] = v
    return cred_pairs


@click.command()
@click.option('--service', type=str, required=True, default="",
              help="Get all credential pairs of this service")
@click.option('--prefix', type=str, required=False, default="CREDENTIALS_",
              help="Prepend env keys with this prefix")
@click.argument("command", nargs=-1, required=True)
def exec(command, service, prefix):
    """Gets credentials from Confidant and launch process
    with these credentials as env vars
    """
    client = ConfidantClient()
    cred_pairs = get_service(client=client, service=service, prefix=prefix)
    environment_vars = {**os.environ, **cred_pairs}
    os.execvpe(command[0], command, environment_vars)


def main():
    exec()


if __name__ == '__main__':
    main()
