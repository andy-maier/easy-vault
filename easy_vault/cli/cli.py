# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
The entry point for the easy-vault command.
"""

from __future__ import absolute_import, print_function

import os
import sys
import getpass
import click

from ._common_options import add_options, help_option, quiet_option
from .._version import __version__ as cli_version
from .._keyring import Keyring, KeyringNotAvailable, KeyringException
from .._easy_vault import EasyVault, EasyVaultException
from .._password import get_password, set_password


@click.group()
@click.version_option(
    message='%(prog)s, version %(version)s'.format(cli_version),
    help=u'Show the version of this command.')
@add_options(help_option)
@click.pass_context
def cli(ctx):
    """
    The easy-vault command is used to encrypt and decrypt vault files.

    The passwords for the vault files are stored in the keyring service
    of the local system.
    """
    pass
    # Command will be executed automatically


@cli.command('encrypt')
@click.argument('vaultfile', type=str, metavar='VAULTFILE', required=True)
@click.option('-p', '--set-password', is_flag=True, default=False,
              help=u'Set a new password if the file needs to be encrypted. '
              u'Mutually exclusive with --no-keyring')
@click.option('-n', '--no-keyring', is_flag=True, default=False,
              help=u'Do not use the keyring service. '
              u'Mutually exclusive with --set-password')
@add_options(quiet_option)
@add_options(help_option)
def cli_encrypt(vaultfile, **options):
    """
    Encrypt a vault file, if not yet encrypted.

    If the vault file is already encrypted, nothing is done.

    If the vault file is currently decrypted, by default the keyring service is
    contacted to see whether it has a password stored for this vault file.
    If so, that password is used for encrypting the vault file.
    Otherwise, a password is prompted for, and that password is used for
    encrypting the vault file and is stored in the keyring service for future
    use as the password for this vault file.

    If the keyring service is chosen not to be used, the password is always
    prompted for and the keyring service is not contacted at all.

    If a new password is chosen to be set, that password is used for encrypting
    the vault file and is stored in the keyring service for future use as the
    password for this vault file, overwriting a possibly existing previous
    password.

    Note that these two choices are mutually exclusive.
    """
    verbose = not options['quiet']
    set_pass = options['set_password']
    no_keyring = options['no_keyring']
    if set_pass and no_keyring:
        raise click.ClickException(
            "The --set-password and --no-keyring options are mutually "
            "exclusive")

    check_exists(vaultfile)

    if EasyVault(vaultfile).is_encrypted():
        if verbose:
            click.echo("Success! Vault file had already been encrypted")
        return

    if set_pass:
        password = get_password(vaultfile, use_keyring=False,
                                verbose=verbose, echo=click.echo)
    else:
        password = get_password(vaultfile, use_keyring=not no_keyring,
                                verbose=verbose, echo=click.echo)

    vault = EasyVault(vaultfile, password)
    try:
        vault.encrypt()
    except EasyVaultException as exc:
        raise click.ClickException(str(exc))
    if verbose:
        click.echo("Success! Vault file has just been encrypted")

    set_password(vaultfile, password, use_keyring=not no_keyring,
                 verbose=verbose, echo=click.echo)


@cli.command('decrypt')
@click.argument('vaultfile', type=str, metavar='VAULTFILE', required=True)
@click.option('-p', '--set-password', is_flag=True, default=False,
              help=u'Set a new password if the file needs to be decrypted. '
              u'Mutually exclusive with --no-keyring')
@click.option('-n', '--no-keyring', is_flag=True, default=False,
              help=u'Do not use the keyring service. '
              u'Mutually exclusive with --set-password')
@add_options(help_option)
@add_options(quiet_option)
def cli_decrypt(vaultfile, **options):
    """
    Decrypt a vault file, if encrypted.

    If the vault file is already decrypted, nothing is done.

    If the vault file is currently encrypted, by default the keyring service is
    contacted to see whether it has a password stored for this vault file.
    If so, that password is used for decrypting the vault file.
    Otherwise, a password is prompted for, and that password is used for
    decrypting the vault file and is stored in the keyring service for future
    use as the password for this vault file.

    If the keyring service is chosen not to be used, the password is always
    prompted for and the keyring service is not contacted at all.

    If a new password is chosen to be set, that password is used for decrypting
    the vault file and is stored in the keyring service for future use as the
    password for this vault file, overwriting a possibly existing previous
    password.

    Note that these two choices are mutually exclusive.
    """
    verbose = not options['quiet']
    set_pass = options['set_password']
    no_keyring = options['no_keyring']
    if set_pass and no_keyring:
        raise click.ClickException(
            "The --set-password and --no-keyring options are mutually "
            "exclusive")

    check_exists(vaultfile)

    if not EasyVault(vaultfile).is_encrypted():
        if verbose:
            click.echo("Success! Vault file had already been decrypted")
        return

    if set_pass:
        password = get_password(vaultfile, use_keyring=False,
                                verbose=verbose, echo=click.echo)
    else:
        password = get_password(vaultfile, use_keyring=not no_keyring,
                                verbose=verbose, echo=click.echo)

    vault = EasyVault(vaultfile, password)
    try:
        vault.decrypt()
    except EasyVaultException as exc:
        raise click.ClickException(str(exc))
    if verbose:
        click.echo("Success! Vault file has just been decrypted")

    set_password(vaultfile, password, use_keyring=not no_keyring,
                 verbose=verbose, echo=click.echo)


@cli.command('check-encrypted')
@click.argument('vaultfile', type=str, metavar='VAULTFILE', required=True)
@add_options(quiet_option)
@add_options(help_option)
def cli_check_encrypted(vaultfile, **options):
    """
    Check whether the vault file is encrypted.

    If encrypted, the command exits with 0.
    If not encrypted, the command exits with 1.
    """
    verbose = not options['quiet']

    check_exists(vaultfile)

    if not EasyVault(vaultfile).is_encrypted():
        if verbose:
            click.echo("Error: Vault file is not encrypted")
        click.get_current_context().exit(1)

    if verbose:
        click.echo("Success! Vault file is encrypted")


@cli.command('check-keyring')
@add_options(quiet_option)
@add_options(help_option)
def cli_check_keyring(**options):
    """
    Check whether the keyring service is available.

    If available, the command exits with 0.
    If not available, the command prints an error message with some information
    about the reasons, and exits with 1.
    """
    verbose = not options['quiet']

    kr = Keyring()
    try:
        kr.check_available()
    except KeyringNotAvailable as exc:
        if verbose:
            click.echo("Error: {}".format(exc))
            click.get_current_context().exit(1)

    if verbose:
        click.echo("Success! Keyring service is available")


@cli.command('delete-password')
@click.argument('vaultfile', type=str, metavar='VAULTFILE', required=True)
@add_options(quiet_option)
@add_options(help_option)
def cli_delete_password(vaultfile, **options):
    """
    Delete the password for a vault file in the keyring service.
    """
    verbose = not options['quiet']

    kr = Keyring()
    try:
        existed = kr.delete_password(vaultfile)
    except KeyringException as exc:
        raise click.ClickException(exc)
    if verbose:
        if existed:
            click.echo("Success! Password in keyring service has been deleted")
        else:
            click.echo("Success! Password in keyring service does not exist")


def check_exists(vaultfile):
    if not os.path.exists(vaultfile):
        raise click.ClickException(
            "Vault file does not exist: {fn}".format(fn=vaultfile))
