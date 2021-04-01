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
The KeyRingLib class.
"""

from __future__ import absolute_import, print_function
import os
import keyring

__all__ = ['KeyRingLib']


# Service/app name used for keyring items:
# Version 1.0: The item value is the password
KEYRING_SERVICE = u'easy_vault/pypi.org/1.0'


class KeyRingLib(object):
    """
    Access to the keyring service of the local system for storing vault
    passwords.

    An object of this class is tied to the keyring service and can store and
    retrieve multiple vault passwords.

    The keyring items that are created have a fixed service/app name that
    starts with 'easy_vault'. There is one keyring item for each vault file.

    If no keyring service is available that is recognized by the
    keyring package, the :exc:`keyring:keyring.errors.NoKeyringError` exception
    is raised starting with keyring version 22.0, or the standard Python
    RuntimeError before that keyring version. Other errors with the keyring
    servive will be raised as exceptions that are derived from the
    :exc:`keyring:keyring.errors.KeyringError` base exception class.

    For details on the keyring service, see section :ref:`Keyring service`.
    """

    def get_password(self, filepath):
        """
        Get the password for a vault file from the keyring service.

        If the keyring service does not store a password for the vault file,
        `None` is returned.

        Parameters:

          filepath (:term:`unicode string`):
            Path name of the vault file. It will be normalized to identify the
            keyring item for the vault file.

        Returns:
          :term:`unicode string`: Password for the vault file, or `None`.

        Raises:
          :exc:`keyring:keyring.errors.NoKeyringError` or RuntimeError:
            No keyring service available
          :exc:`keyring:keyring.errors.KeyringError`: Base class for errors with
            the keyring service
        """
        return keyring.get_password(
            self.keyring_service(), self.keyring_username(filepath))

    def set_password(self, filepath, password):
        """
        Set the password for a vault file in the keyring service.

        Parameters:

          filepath (:term:`unicode string`):
            Path name of the vault file. It will be normalized to identify the
            keyring item for the vault file.

          password (:term:`unicode string`):
            Password for the vault file.

        Raises:
          :exc:`keyring:keyring.errors.NoKeyringError` or RuntimeError:
            No keyring service available
          :exc:`keyring:keyring.errors.KeyringError`: Base class for errors with
            the keyring service
        """
        keyring.set_password(
            self.keyring_service(), self.keyring_username(filepath), password)

    @staticmethod
    def keyring_service():
        """
        Return the service/app name that is used for the keyring item.

        That name is fixed within easy-vault and starts with 'easy_vault'.

        Returns:
          :term:`unicode string`: keyring service/app name.
        """
        return KEYRING_SERVICE

    @staticmethod
    def keyring_username(filepath):
        """
        Return the user/account name that is used for the keyring item.

        That name is calculated from the normalized vault file path, such that
        each different vault file uses a different item in the keyring service.

        Parameters:

          filepath (:term:`unicode string`):
            Path name of the vault file. It will be normalized to identify the
            keyring item for the vault file.

        Returns:
          :term:`unicode string`: keyring user/account name.
        """
        normpath = os.path.abspath(filepath)
        return u'file:{fn}'.format(fn=normpath)
