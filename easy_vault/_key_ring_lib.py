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


# Data stored in keyring enzry, by version:
#   1.0: The item stored is the password
KEYRING_SERVICE = u'easy_vault/pypi.org/1.0'    # Must be unique within keyring


class KeyRingLib(object):
    """
    Access to the local system keyring for storing easy-vault vault passwords.

    An object of this class is tied to the local keyring facility and can
    store and retrieve multiple vault passwords, one for each vault file.

    The keyring items that are created have a service name that starts with
    'easy_vault'. There is one keyring item for each vault file.
    """

    def get_password(self, filepath):
        """
        Get the password for the specified vault file from the keyring.

        If the keyring does not store a password for this vault file, `None`
        is returned.

        Parameters:

          filepath (:term:`unicode string`):
            Path name of the vault file. It will be normalized to identify the
            keyring entry for the vault file.

        Returns:
          :term:`unicode string`: Password for the vault file, or `None`.
        """
        return keyring.get_password(
            self.keyring_service(), self.keyring_username(filepath))

    def set_password(self, filepath, password):
        """
        Set the password for the specified vault file in the keyring.

        Parameters:

          filepath (:term:`unicode string`):
            Path name of the vault file. It will be normalized to identify the
            keyring entry for the vault file.

          password (:term:`unicode string`):
            Password for the vault file.
        """
        keyring.set_password(
            self.keyring_service(), self.keyring_username(filepath), password)

    @staticmethod
    def keyring_service():
        """
        Return the service name that is used for the :mod:`keyring` module.

        That name is fixed within easy-vault and starts with 'easy_vault'.

        Returns:
          :term:`unicode string`: keyring service name.
        """
        return KEYRING_SERVICE

    @staticmethod
    def keyring_username(filepath):
        """
        Return the user name that is used for the :mod:`keyring` module.

        That name is calculated from the normalized vault file path, such that
        each different vault file uses a different entry in the keyring.

        Parameters:

          filepath (:term:`unicode string`):
            Path name of the vault file.

        Returns:
          :term:`unicode string`: keyring user name.
        """
        normpath = os.path.abspath(filepath)
        return u'file:{fn}'.format(fn=normpath)
