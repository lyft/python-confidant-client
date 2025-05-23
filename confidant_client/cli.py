# -*- coding: utf-8 -*-
"""Confidant cli module."""

# Import python libs
from __future__ import absolute_import
from __future__ import print_function
from confidant_client.lib import helper
import logging
import json
import argparse
import sys
import getpass
import re
import os

import confidant_client

KEY_BAD_PATTERN = re.compile(r'(\W|^\d)')


def _get_client_from_args(args):
    if args.mfa:
        mfa_pin = getpass.getpass('Enter the MFA code: ')
    else:
        mfa_pin = None
    auth_context = {}
    if args._from:
        auth_context['from'] = args._from
    if args._to:
        auth_context['to'] = args._to
    if args.user_type:
        auth_context['user_type'] = args.user_type
    if not auth_context:
        auth_context = None
    if args.config_files:
        config_files = args.config_files.split(',')
    else:
        config_files = None
    client = confidant_client.ConfidantClient(
        args.url,
        args.auth_key,
        auth_context,
        token_lifetime=args.token_lifetime,
        token_version=args.token_version,
        assume_role=args.assume_role,
        mfa_pin=mfa_pin,
        region=args.region,
        retries=args.retries,
        config_files=config_files,
        profile=args.profile,
        verify=args.verify,
        timeout=args.timeout
    )
    return client


def _parse_args():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=('A client for fetching credentials from a confidant'
                     ' server.'),
        add_help=False
    )
    parser.add_argument(
        '-h',
        '--help',
        action=_HelpAction,
        help='show this help message and exit'
    )
    parser.add_argument(
        '--config-files',
        help=('Comma separated list of configuration files to use. Default:'
              ' ~/.confidant,/etc/confidant/config')
    )
    parser.add_argument(
        '--profile',
        help='Configuration profile to use. Default: default'
    )
    parser.add_argument(
        '-u',
        '--url',
        help=('url of the confidant server. i.e.'
              ' https://confidant-production.example.com')
    )
    parser.add_argument(
        '-v',
        '--verify-ssl',
        help='Whether we verify the servers TLS certificate',
        action='store_true',
        dest='verify',
        default=True
    )
    parser.add_argument(
        '--retries',
        help=('Number of retries that should be attempted on confidant server'
              ' errors. Default 0.'),
        type=int
    )
    parser.add_argument(
        '--timeout',
        help=('Connect and read timeout in seconds to confidant server.'
              ' Default 5.'),
        type=int,
    )
    parser.add_argument(
        '-k',
        '--auth-key',
        help='The KMS auth key to use. It must either be an ARN (i.e. a string'
             ' starting with "arn:aws:kms:") or an alias with the prefix'
             ' "alias/" (i.e. "alias/authnz-production")'
    )
    parser.add_argument(
        '-l',
        '--token-lifetime',
        type=int,
        help=('The token lifetime, in minutes. The client will backdate the'
              ' token by 3 minutes to avoid clockskew issues, so the minimum'
              ' lifetime you should use is 4. You may also want to pad the'
              ' lifetime by a few minutes to avoid clock skew the other'
              ' direction, so a safe recommended minimum is 7.')
    )
    parser.add_argument(
        '--token-version',
        type=int,
        help='The version of the KMS auth token.'
    )
    parser.add_argument(
        '--from',
        dest='_from',
        help=('The IAM role or user to authenticate with. i.e.'
              ' myservice-production or myuser')
    )
    parser.add_argument(
        '--to',
        dest='_to',
        help='The IAM role name of confidant i.e. confidant-production'
    )
    parser.add_argument(
        '--user-type',
        help='The confidant user-type to authenticate as i.e. user or service'
    )
    parser.add_argument(
        '--mfa',
        help='Prompt for an MFA token.',
        action='store_true',
        dest='mfa'
    )
    parser.add_argument(
        '--assume-role',
        help='Assume the specified role.'
    )
    parser.add_argument(
        '--region',
        help='Use the specified region for authentication.'
    )
    parser.add_argument(
        '--log-level',
        help='Logging verbosity.',
        default='info'
    )
    parser.add_argument(
        '--version',
        help='Print version and exit.',
        action='version',
        version='%(prog)s {version}'.format(version=confidant_client.VERSION)
    )
    parser.set_defaults(mfa=False)

    subparsers = parser.add_subparsers(dest='subcommand')
    env_parser = subparsers.add_parser(
        'env',
        help=('Run a command with secrets injected as environmental variables'),
    )
    env_parser.add_argument(
        '--service',
        help='The service\'s secrets to get.'
    )
    env_parser.add_argument(
        '--prefix',
        help=('Prefix env var keynames with this value.  '
              'Defaults to CREDENTIALS_'),
        required=False,
        default='CREDENTIALS_'
    )
    env_parser.add_argument(
        '--wrapped',
        action='store_true',
        dest='wrapped',
        help=('Flag indicating that confidant was called by a command in'
              'command_wrap defined in ~/.confidant'),
        required=False,
    )
    env_parser.add_argument(
        '--force',
        action='store_true',
        dest='force',
        help=('If command_safety_regex in ~/.confidant is matched, '
              '--force is required to run the command'),
        default=False,
        required=False,
    )
    env_parser.set_defaults(
        decrypt_blind=False
    )
    env_parser.add_argument('command', action='store', type=str, nargs='*')

    get_service_parser = subparsers.add_parser('get_service')
    get_service_parser.add_argument(
        '--service',
        help='The service to get.'
    )
    get_service_parser.add_argument(
        '--no-decrypt-blind',
        help=('Do not decrypt blind credentials, instead give back the raw'
              ' results from get_service.'),
        action='store_false',
        dest='decrypt_blind'
    )
    get_service_parser.set_defaults(
        decrypt_blind=True
    )

    create_blind_cred_parser = subparsers.add_parser('create_blind_credential')
    create_blind_cred_parser.add_argument(
        '--blind-keys',
        required=True,
        help=('A dict of region to kms key mappings to use for at-rest'
              ' encryption for multiple regions in json format i.e.'
              ' {"us-east-1":"alias/confidant-production-blind-useast1",'
              '"us-west-2":"alias/confidant-production-blind-uswest2"}'),
        type=json.loads
    )
    context_group = create_blind_cred_parser.add_mutually_exclusive_group(
        required=True
    )
    context_group.add_argument(
        '--group-context',
        help=('A encryption context for blind credentials in json format i.e.'
              ' {"group":"web-production"}. This context will be applied to'
              ' all regions, if multiple regions are provided in --blind-keys.'
              ' Mutually exclusive with --blind-contexts.'),
        type=json.loads
    )
    context_group.add_argument(
        '--blind-contexts',
        help=('A custom dict of region to encryption context for blind'
              ' credentials in json format i.e.'
              ' \'{"us-east-1":{"to":"web-production-useast1"},'
              '"us-west-2":{"to":"web-production-uswest2"}}\'. Mutually'
              ' exclusive with --group-context.'),
        type=json.loads
    )
    create_blind_cred_parser.add_argument(
        '--name',
        required=True,
        help='A name for this blind credential i.e. \'production ssl key\'.'
    )
    create_blind_cred_parser.add_argument(
        '--credential-pairs',
        required=True,
        help=('A dict of key/value pairs for credentials in json format i.e.'
              '\'{"ssl_key":"----- BEGIN...","ssl_cert":"----- BEGIN..."}\'.'),
        type=json.loads
    )
    create_blind_cred_parser.add_argument(
        '--cipher-type',
        help='The type of cipher to use for at-rest encryption.',
        default='fernet'
    )
    create_blind_cred_parser.add_argument(
        '--cipher-version',
        help=('The version of the cipher implementation to use for at-rest'
              ' encryption.'),
        default=2
    )
    create_blind_cred_parser.add_argument(
        '--no-store-keys',
        help=('Do not to store the dict keys of credential-pairs as a clear'
              ' text list in the blind-credential metadata. By default the'
              ' dict keys are stored to help ensure blind credentials will not'
              ' conflict with each other when mapped to a service and also to'
              ' aid in use of the credentials in application code (since you'
              ' need to reference the key to get the value).'),
        action='store_false',
        dest='store_keys'
    )
    create_blind_cred_parser.add_argument(
        '--metadata',
        help=('A dict of key/value pairs to be stored as clear-text extensible'
              ' along with the credential in json format i.e. '
              '\'{"path":"/etc/mysecret","mode":"0600"}\'.'),
        type=json.loads,
        default='{}'
    )
    enabled_group = create_blind_cred_parser.add_mutually_exclusive_group()
    enabled_group.add_argument(
        '--enabled',
        help='Enable this credential (default).',
        action='store_true',
        dest='enabled'
    )
    enabled_group.add_argument(
        '--disabled',
        help='Disable this credential.',
        action='store_false',
        dest='enabled'
    )
    create_blind_cred_parser.add_argument(
        '--documentation',
        help='Documentation on how to rotate this credential'
    )
    create_blind_cred_parser.set_defaults(
        store_keys=True,
        enabled=True
    )

    update_blind_cred_parser = subparsers.add_parser('update_blind_credential')
    update_blind_cred_parser.add_argument(
        '--blind-keys',
        help=('A dict of region to kms key mappings to use for at-rest'
              ' encryption for multiple regions in json format i.e.'
              ' {"us-east-1":"alias/confidant-production-blind-useast1",'
              '"us-west-2":"alias/confidant-production-blind-uswest2"}'),
        type=json.loads
    )
    context_group = update_blind_cred_parser.add_mutually_exclusive_group()
    context_group.add_argument(
        '--group-context',
        help=('A encryption context for blind credentials in json format i.e.'
              ' {"group":"web-production"}. This context will be applied to'
              ' all regions, if multiple regions are provided in --blind-keys.'
              ' Mutually exclusive with --blind-contexts.'),
        type=json.loads
    )
    context_group.add_argument(
        '--blind-contexts',
        help=('A custom dict of region to encryption context for blind'
              ' credentials in json format i.e.'
              ' \'{"us-east-1":{"to":"web-production-useast1"},'
              '"us-west-2":{"to":"web-production-uswest2"}}\'. Mutually'
              ' exclusive with --group-context.'),
        type=json.loads
    )
    update_blind_cred_parser.add_argument(
        '--id',
        required=True,
        help=('An id for this blind credential i.e.'
              ' \'f232fcd3747c47718e48a034f4cdfc0e\'.'),
        dest='_id'
    )
    update_blind_cred_parser.add_argument(
        '--name',
        help='A name for this blind credential i.e. \'production ssl key\'.'
    )
    update_blind_cred_parser.add_argument(
        '--credential-pairs',
        help=('A dict of key/value pairs for credentials in json format i.e.'
              '\'{"ssl_key":"----- BEGIN...","ssl_cert":"----- BEGIN..."}\'.'),
        type=json.loads
    )
    update_blind_cred_parser.add_argument(
        '--cipher-type',
        help='The type of cipher to use for at-rest encryption.'
    )
    update_blind_cred_parser.add_argument(
        '--cipher-version',
        help=('The version of the cipher implementation to use for at-rest'
              ' encryption.')
    )
    update_blind_cred_parser.add_argument(
        '--no-store-keys',
        help=('Do not to store the dict keys of credential-pairs as a clear'
              ' text list in the blind-credential metadata. By default the'
              ' dict keys are stored to help ensure blind credentials will not'
              ' conflict with each other when mapped to a service and also to'
              ' aid in use of the credentials in application code (since you'
              ' need to reference the key to get the value).'),
        action='store_false',
        dest='store_keys'
    )
    update_blind_cred_parser.add_argument(
        '--metadata',
        help=('A dict of key/value pairs to be stored as clear-text extensible'
              ' along with the credential in json format i.e.'
              ' \'{"path":"/etc/mysecret","mode":"0600"}\'.'),
        type=json.loads
    )
    enabled_group = update_blind_cred_parser.add_mutually_exclusive_group()
    enabled_group.add_argument(
        '--enabled',
        help='Enable this credential (default).',
        action='store_true',
        dest='enabled'
    )
    enabled_group.add_argument(
        '--disabled',
        help='Disable this credential.',
        action='store_false',
        dest='enabled'
    )
    update_blind_cred_parser.add_argument(
        '--documentation',
        help='Documentation on how to rotate this credential'
    )
    update_blind_cred_parser.set_defaults(
        enabled=None,
        store_keys=True
    )

    get_blind_cred_parser = subparsers.add_parser('get_blind_credential')
    get_blind_cred_parser.add_argument(
        '--id',
        required=True,
        help=('An id for this blind credential i.e.'
              ' \'f232fcd3747c47718e48a034f4cdfc0e\'.'),
        dest='_id'
    )
    get_blind_cred_parser.add_argument(
        '--decrypt-blind',
        help=('Decrypt blind credentials, rather than giving back the raw'
              ' results from get_blind_credential.'),
        action='store_true',
        dest='decrypt_blind'
    )
    get_blind_cred_parser.set_defaults(
        decrypt_blind=False
    )

    subparsers.add_parser('list_blind_credentials')

    revert_cred_parser = subparsers.add_parser('revert_credential')
    revert_cred_parser.add_argument(
        '--id',
        required=True,
        help=('An id for this credential i.e.'
              ' \'f232fcd3747c47718e48a034f4cdfc0e\'.'),
        dest='_id'
    )
    revert_cred_parser.add_argument(
        '--revision',
        help=('The revision number to revert to. Omit if you want to restore '
              'the most recent revision.'),
        type=int
    )

    revert_service_parser = subparsers.add_parser('revert_service')
    revert_service_parser.add_argument(
        '--id',
        required=True,
        help=('The id for this service'),
        dest='_id'
    )
    revert_service_parser.add_argument(
        '--revision',
        help=('The revision number to revert to. Omit if you want to restore '
              'the most recent revision.'),
        type=int
    )

    revert_blind_cred_parser = subparsers.add_parser('revert_blind_credential')
    revert_blind_cred_parser.add_argument(
        '--id',
        required=True,
        help=('An id for this blind_credential i.e.'
              ' \'f232fcd3747c47718e48a034f4cdfc0e\'.'),
        dest='_id'
    )
    revert_blind_cred_parser.add_argument(
        '--revision',
        help=('The revision number to revert to. Omit if you want to restore '
              'the most recent revision.'),
        type=int
    )

    ca_get_certificate_parser = subparsers.add_parser('get_certificate')
    ca_get_certificate_parser.add_argument(
        '--ca',
        required=True,
        help='The certificate authority to issue a certificate from.',
    )
    ca_get_certificate_parser.add_argument(
        '--cn',
        help=('A cerftificate signing request (CSR) file to issue a certificate'
              'from.'),
    )
    ca_get_certificate_parser.add_argument(
        '--san',
        nargs='+',
        help=('A list of subject alternative name values that should be'
              ' present in the issued certificate.'),
    )
    ca_get_certificate_parser.add_argument(
        '--validity',
        help='The validity of the certificate in number of days from today',
        type=int,
        default=120,
    )

    ca_get_certificate_from_csr_parser = subparsers.add_parser(
        'get_certificate_from_csr'
    )
    ca_get_certificate_from_csr_parser.add_argument(
        '--ca',
        required=True,
        help='The certificate authority to issue a certificate from.',
    )
    ca_get_certificate_from_csr_parser.add_argument(
        '--csr-file',
        help=('A certificate signing request (CSR) file to issue a certificate'
              'from.'),
    )
    ca_get_certificate_from_csr_parser.add_argument(
        '--validity',
        help='The validity of the certificate in number of days from today',
        type=int,
        default=120,
    )

    ca_get_ca_parser = subparsers.add_parser(
        'get_ca'
    )
    ca_get_ca_parser.add_argument(
        '--ca',
        required=True,
        help='The certificate authority to get.',
    )

    subparsers.add_parser(
        'list_cas'
    )

    add_creds_to_service_parser = subparsers.add_parser(
        'add_creds',
        help=('Add credential ids to a service'),
    )
    add_creds_to_service_parser.add_argument(
        '--cred-ids',
        type=str,
        nargs='+',
        dest='cred_ids',
        default=[],
        help=('list of credential ids, separated by whitespace'),
    )
    add_creds_to_service_parser.add_argument(
        '--blind-cred-ids',
        type=str,
        nargs='+',
        dest='blind_cred_ids',
        default=[],
        help=('list of credential ids, separated by whitespace'),
    )
    add_creds_to_service_parser.add_argument(
        '--service-id',
        type=str,
        dest='service_id',
    )

    rm_creds_from_service_parser = subparsers.add_parser(
        'remove_creds',
        help=('Remove credential ids to a service'),
    )
    rm_creds_from_service_parser.add_argument(
        '--cred-ids',
        type=str,
        nargs='+',
        dest='cred_ids',
        default=[],
        help=('list of credential ids, separated by whitespace'),
    )
    rm_creds_from_service_parser.add_argument(
        '--blind-cred-ids',
        type=int,
        nargs='+',
        dest='blind_cred_ids',
        default=[],
        help=('list of credential ids, separated by whitespace'),
    )
    rm_creds_from_service_parser.add_argument(
        '--service-id',
        type=str,
        dest='service_id',
        required=True,
    )

    get_jwt = subparsers.add_parser(
        'get_jwt',
        help='Generate a JWT for the authenticated user',
    )
    get_jwt.add_argument(
        '--environment',
        type=str,
        dest='environment',
        required=True,
    )
    get_jwt.add_argument(
        '--resource-id',
        type=str,
        dest='resource_id',
        default=None,
        help='The actual name of the resource to generate a JWT for',
    )
    get_jwt.add_argument(
        '--expiry',
        type=int,
        dest='expiry',
        default=None,
        help='The expiry of the JWT in seconds',
    )

    get_jwks = subparsers.add_parser(
        'get_jwks',
        help='Retrieve a public JWKS for the requested environment',
    )
    get_jwks.add_argument(
        '--environment',
        type=str,
        dest='environment',
        required=True,
    )

    return parser.parse_args()


def main():
    """Entrypoint function for confidant cli."""
    args = _parse_args()

    numeric_loglevel = getattr(logging, args.log_level.upper(), None)
    if not isinstance(numeric_loglevel, int):
        raise ValueError('Invalid log level: {0}'.format(args.loglevel))
    logging.basicConfig(
        level=numeric_loglevel,
        format='%(asctime)s %(name)s: %(levelname)s %(message)s',
        stream=sys.stderr
    )

    client = _get_client_from_args(args)
    ret = {'result': False}

    if args.subcommand == 'env':
        safety_re = client.config.get('command_safety_regex')
        if safety_re and re.search(safety_re, args.service) and not args.force:
            msg = client.config.get(
                'command_safety_msg',
                'Fetching sensitive service credentials.  '
                'Use --force to override'
            )
            logging.warning(msg)
            sys.exit(-1)

        # If command_wrap is set in ~/.confidant then call 'confidant'
        # with the command_wrap and pass in flag --wrapped indicating
        # it's been wrapped so that we don't wrap again.
        # eg: command_wrap = 'aws-vault exec lisa --'
        # then the following will be called:
        # 'aws-vault exec lisa -- confidant env --wrapped [command]
        if client.config.get('command_wrap') and not args.wrapped:
            cmd = client.config.get('command_wrap').split() + \
                  ["confidant"] + sys.argv[1:]
            # add --wrapped right after env subcommand
            cmd.insert(cmd.index('env') + 1, '--wrapped')
            os.execvpe(cmd[0], cmd, os.environ)
        elif len(args.command):
            try:
                ret = client.get_service(
                    args.service,
                    args.decrypt_blind
                )
            except Exception:
                logging.exception('An unexpected general error occurred.')
                sys.exit(-1)

            cred_pairs = {}
            try:
                creds = ret['service']['credentials']
            except KeyError:
                logging.error("Service does not exist.")
                sys.exit(-1)

            for cred in creds:
                for k, v in cred['credential_pairs'].items():
                    cred_pairs[helper.format_cred_key(k, args.prefix)] = v

            os_env = os.environ.copy()
            helper.sanitize_secrets(os_env)
            environment_vars = {**os_env, **cred_pairs}
            os.execvpe(args.command[0], args.command, environment_vars)
        sys.exit(0)
    elif args.subcommand == 'get_service':
        try:
            ret = client.get_service(
                args.service,
                args.decrypt_blind
            )
        except Exception:
            logging.exception('An unexpected general error occurred.')
    elif args.subcommand == 'create_blind_credential':
        contexts = {}
        if args.group_context:
            for region in args.blind_keys:
                contexts[region] = args.group_context
        else:
            contexts = args.blind_contexts
        try:
            ret = client.create_blind_credential(
                args.blind_keys,
                contexts,
                args.name,
                args.credential_pairs,
                args.metadata,
                args.cipher_type,
                args.cipher_version,
                args.store_keys,
                args.enabled,
                args.documentation
            )
        except Exception:
            logging.exception('An unexpected general error occurred.')
    elif args.subcommand == 'update_blind_credential':
        contexts = {}
        if args.group_context:
            for region in args.blind_keys:
                contexts[region] = args.group_context
        elif args.blind_contexts:
            contexts = args.blind_contexts
        else:
            contexts = None
        try:
            ret = client.update_blind_credential(
                args._id,
                args.blind_keys,
                contexts,
                args.name,
                args.credential_pairs,
                args.metadata,
                args.cipher_type,
                args.cipher_version,
                args.store_keys,
                args.enabled,
                args.documentation
            )
        except Exception:
            logging.exception('An unexpected general error occurred.')
    elif args.subcommand == 'get_blind_credential':
        try:
            ret = client.get_blind_credential(args._id, args.decrypt_blind)
        except Exception:
            logging.exception('An unexpected general error occurred.')
    elif args.subcommand == 'list_blind_credentials':
        try:
            ret = client.list_blind_credentials()
        except Exception:
            logging.exception('An unexpected general error occurred.')
    elif args.subcommand == 'revert_credential':
        try:
            ret = client.revert_credential(args._id, args.revision)
        except Exception:
            logging.exception('An unexpected general error occurred.')
    elif args.subcommand == 'revert_blind_credential':
        try:
            ret = client.revert_blind_credential(args._id, args.revision)
        except Exception:
            logging.exception('An unexpected general error occurred.')
    elif args.subcommand == 'revert_service':
        try:
            ret = client.revert_service(args._id, args.revision)
        except Exception:
            logging.exception('An unexpected general error occurred.')
    elif args.subcommand == 'get_certificate':
        try:
            ret = client.get_certificate(
                args.ca,
                args.cn,
                args.san,
                args.validity,
            )
        except Exception:
            logging.exception('An unexpected general error occurred.')
    elif args.subcommand == 'get_certificate_from_csr':
        try:
            ret = client.get_certificate_from_csr(
                args.ca,
                args.csr_file,
                args.validity,
            )
        except Exception:
            logging.exception('An unexpected general error occurred.')
    elif args.subcommand == 'get_ca':
        try:
            ret = client.get_ca(args.ca)
        except Exception:
            logging.exception('An unexpected general error occurred.')
    elif args.subcommand == 'list_cas':
        try:
            ret = client.list_cas()
        except Exception:
            logging.exception('An unexpected general error occurred.')
    elif args.subcommand == 'add_creds':
        try:
            ret = client.add_credentials_to_service(
                credentials=args.cred_ids,
                blind_credentials=args.blind_cred_ids,
                service=args.service_id
            )
        except Exception:
            logging.exception('An unexpected general error occurred.')
    elif args.subcommand == 'remove_creds':
        try:
            ret = client.remove_credentials_from_service(
                credentials=args.cred_ids,
                blind_credentials=args.blind_cred_ids,
                service=args.service_id
            )
        except Exception:
            logging.exception('An unexpected general error occurred.')
    elif args.subcommand == 'get_jwt':
        try:
            ret = client.get_jwt(args.environment, args.resource_id,
                                 args.expiry)
        except Exception:
            logging.exception('An unexpected general error occurred.')
    elif args.subcommand == 'get_jwks':
        try:
            ret = client.get_jwks(args.environment)
        except Exception:
            logging.exception('An unexpected general error occurred.')

    print(json.dumps(ret, sort_keys=True, indent=4, separators=(',', ': ')))
    if not ret['result']:
        sys.exit(1)


# http://stackoverflow.com/questions/20094215
class _HelpAction(argparse._HelpAction):

    def __call__(self, parser, namespace, values, option_string=None):
        parser.print_help()
        print('')

        # retrieve subparsers from parser
        subparsers_actions = [
            action for action in parser._actions
            if isinstance(action, argparse._SubParsersAction)]
        for subparsers_action in subparsers_actions:
            # get all subparsers and print help
            for choice, subparser in subparsers_action.choices.items():
                print('Subcommand \'{0}\':'.format(choice))
                subparser.print_help()

        print(
            'examples: \n'
            '  confidant env --service myservice-production env\n'
            '  confidant get_service -u'
            ' "https://confidant-production.example.com" -k'
            ' "alias/authnz-production" --from myservice-production'
            ' --to confidant-production --user-type service'
            ' --region us-west-2 --service myservice-production'
        )

        parser.exit()


if __name__ == '__main__':
    main()
