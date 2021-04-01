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
Convenience functions for getting and setting the password in the
keyring service.
"""

from __future__ import absolute_import, print_function

import getpass
from ._key_ring_lib import KeyRingLib

__all__ = ['get_password', 'set_password']


def get_password(
        filepath, use_keyring=True, use_prompting=True, verbose=False,
        echo=print):
    """
    Get the password for a vault file from the keyring service and if not found
    there, by interactively prompting for it.

    The use of the keyring service and the use of password prompting can be
    individually disabled, but at least one of them must be enabled.

    Note that the function may still return no password, in case prompting
    is disabled and the keyring service did not have an item for the vault file
    stored.

    This is a convenience function that uses the password methods of the
    :class:`~easy_vault.KeyRingLib` class.

    Parameters:

      filepath (:term:`unicode string`):
        Path name of the vault file. It will be normalized to identify the
        keyring item for the vault file.

      use_keyring (bool):
        Enable the use of the keyring service for getting the password.

      use_prompting (bool):
        Enable the use of password prompting for getting the password.

      verbose (bool):
        Print additional messages about where the password comes from.

      echo (function):
        Print function to be used for the additional messages in verbose mode.

    Returns:
      :term:`unicode string`: Password for the vault file, or `None`.

    Raises:
      ValueError: Use of keyring service and use of password prompting were
        both disabled.
      :exc:`KeyRingNotAvailable`: No keyring service available.
      :exc:`KeyRingError`: An error happend in the keyring service.
    """
    password = None

    if not use_keyring and not use_prompting:
        raise ValueError("use_keyring and use_prompt were both False")

    if use_keyring:
        keyringlib = KeyRingLib()
        password = keyringlib.get_password(filepath)
        if password is not None:
            if verbose:
                echo("Using password from keyring service")
            return password

    if use_prompting:
        password = getpass.getpass(
            "Enter password for vault file {fn}:".format(fn=filepath))
        return password

    return None


def set_password(
        filepath, password, use_keyring=True, verbose=False, echo=print):
    """
    Set the password for a vault file in the keyring service.

    For consistency with :func:`get_password`, the use of the keyring service
    can be disabled, in which case the function does nothing.

    This is a convenience function that uses the password methods of the
    :class:`~easy_vault.KeyRingLib` class.

    Parameters:

      filepath (:term:`unicode string`):
        Path name of the vault file. It will be normalized to identify the
        keyring item for the vault file.

      password (:term:`unicode string`):
        Password for the vault file.

      use_keyring (bool):
        Enable the use of the keyring service for setting the password.

      verbose (bool):
        Print additional messages about changes to the password in the
        keyring service.

      echo (function):
        Print function to be used for the additional messages in verbose mode.

    Raises:
      :exc:`KeyRingNotAvailable`: No keyring service available.
      :exc:`KeyRingError`: An error happend in the keyring service.
    """
    if use_keyring:
        keyringlib = KeyRingLib()
        current_password = keyringlib.get_password(filepath)
        if current_password is None:
            if verbose:
                echo("Setting new password in keyring service")
            keyringlib.set_password(filepath, password)
        elif password != current_password:
            if verbose:
                echo("Updating password in keyring service")
            keyringlib.set_password(filepath, password)
