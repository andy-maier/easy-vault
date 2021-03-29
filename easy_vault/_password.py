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
Convenience functions for getting and setting the password in the keyring.
"""

from __future__ import absolute_import, print_function

import getpass
from ._key_ring_lib import KeyRingLib

__all__ = ['get_password', 'set_password']


def get_password(filepath, use_keyring=True, verbose=False, echo=print):
    """
    Get the vault password from the keyring or by prompting for it.

    This is a convenience function that uses the :class:`~easy_vault.KeyRingLib`
    class.

    In non-keyring mode, the keyring is not used, and the password is always
    prompted for.

    In keyring mode, the password is attempted to be obtained from the keyring
    and is prompted for if not available there.

    Parameters:

      filepath (:term:`unicode string`):
        Path name of the vault file.

      use_keyring (bool):
        Use keyring mode (`True`) or non-keyring mode (`False`).

      verbose (bool):
        Print additional messages. Note that the password prompt is always
        displayed.

      echo (function):
        Print function to be used for the additional messages in verbose mode.

    Returns:
      :term:`unicode string`: Password for the vault file.
    """
    keyringlib = KeyRingLib()

    if not use_keyring:
        return getpass.getpass("Enter password for vault file {fn}:".
                               format(fn=filepath))

    password = keyringlib.get_password(filepath)
    if password is None:
        return getpass.getpass("Enter password for vault file {fn}:".
                               format(fn=filepath))

    if verbose:
        echo("Using password from keyring for vault file: {fn}".
             format(fn=filepath))
    return password


def set_password(
        filepath, password, use_keyring=True, verbose=False, echo=print):
    """
    Set the password in the keyring.

    This is a convenience function that uses the :class:`~easy_vault.KeyRingLib`
    class.

    In non-keyring mode, this function does nothing.

    In keyring mode, the password is stored in the keyring. This is done by
    first getting it, and setting it only if it was not set or was different.
    This approach has been chosen in order to print the verbose message
    about setting the password only if it was really changed.

    Parameters:

      filepath (:term:`unicode string`):
        Path name of the vault file.

      password (:term:`unicode string`):
        Password for the vault file.

      use_keyring (bool):
        Use keyring mode (`True`) or non-keyring mode (`False`).

      verbose (bool):
        Print additional messages.

      echo (function):
        Print function to be used for the additional messages in verbose mode.
    """
    if use_keyring:
        keyringlib = KeyRingLib()
        current_password = keyringlib.get_password(filepath)
        if current_password is None or password != current_password:
            if verbose:
                echo("Setting password in keyring for vault file: {fn}".
                     format(fn=filepath))
            keyringlib.set_password(filepath, password)
