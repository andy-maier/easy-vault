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
Click command definition for the pywbemcli command, the top level command for
the pywbemcli click tool
"""

from __future__ import absolute_import, print_function

import os
import sys
import getpass
import click

from ._common_options import add_options, help_option, prompt_option
from .._version import __version__ as cli_version
from .._key_ring_lib import KeyRingLib
from .._easy_vault import EasyVault, EasyVaultException


@click.group()
@click.version_option(
    message='%(prog)s, version %(version)s'.format(cli_version),
    help=u'Show the version of this command.')
@add_options(help_option)
@click.pass_context
def cli(ctx):
    """
    The easy-vault command is used to encrypt and decrypt vault files.
    """
    pass
    # Command will be executed automatically


@cli.command('encrypt')
@click.argument('vaultfile', type=str, metavar='VAULTFILE', required=True)
@add_options(prompt_option)
@add_options(help_option)
@click.pass_obj
def cli_encrypt(context, vaultfile, **options):
    """
    Encrypt a vault file, if not yet encrypted.
    """
    check_exists(vaultfile)
    password = get_password(vaultfile, options['prompt'])
    vault = EasyVault(vaultfile, password)
    try:
        if vault.is_encrypted():
            click.echo("Vault file was already encrypted: {fn}".
                       format(fn=vaultfile))
            return
        vault.encrypt()
    except EasyVaultException as exc:
        raise click.ClickException(str(exc))
    click.echo("Vault file has been successfully encrypted: {fn}".
               format(fn=vaultfile))
    set_password(vaultfile, password)


@cli.command('decrypt')
@click.argument('vaultfile', type=str, metavar='VAULTFILE', required=True)
@add_options(prompt_option)
@add_options(help_option)
@click.pass_obj
def cli_decrypt(context, vaultfile, **options):
    """
    Decrypt a vault file, if encrypted.
    """
    check_exists(vaultfile)
    password = get_password(vaultfile, options['prompt'])
    vault = EasyVault(vaultfile, password)
    try:
        if not vault.is_encrypted():
            click.echo("Vault file was already decrypted: {fn}".
                       format(fn=vaultfile))
            return
        vault.decrypt()
    except EasyVaultException as exc:
        raise click.ClickException(str(exc))
    click.echo("Vault file has been successfully decrypted: {fn}".
               format(fn=vaultfile))
    set_password(vaultfile, password)


def check_exists(vaultfile):
    if not os.path.exists(vaultfile):
        raise click.ClickException(
            "Vault file does not exist: {fn}".format(fn=vaultfile))


def get_password(vaultfile, prompt):
    keyringlib = KeyRingLib()
    if prompt:
        return getpass.getpass("Enter password for vault file {fn}:".
                               format(fn=vaultfile))

    password = keyringlib.get_password(vaultfile)
    if password is None:
        return getpass.getpass("Enter password for vault file {fn}:".
                               format(fn=vaultfile))

    click.echo("Using password from keyring for vault file: {fn}".
               format(fn=vaultfile))
    return password


def set_password(vaultfile, password):
    keyringlib = KeyRingLib()
    current_password = keyringlib.get_password(vaultfile)
    if current_password is None or password != current_password:
        click.echo("Setting password in keyring for vault file: {fn}".
                   format(fn=vaultfile))
        keyringlib.set_password(vaultfile, password)
