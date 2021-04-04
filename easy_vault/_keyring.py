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
The Keyring class.
"""

from __future__ import absolute_import, print_function
import os
import keyring
import keyring.backends.chainer  # Required to import separately
import keyring.backends.null  # Required to import separately
import keyring.backends.fail

__all__ = ['Keyring', 'KeyringException', 'KeyringNotAvailable',
           'KeyringError']


# Service/app name used for keyring items:
# Version 1.0: The item value is the password
KEYRING_SERVICE = u'easy_vault/pypi.org/1.0'

# Exception to catch when no keyring service is available.
# Keyring version 22.0 introduced NoKeyringError and before that used
# RuntimeError.
try:
    NO_KEYRING_EXCEPTION = keyring.errors.NoKeyringError
except AttributeError:
    NO_KEYRING_EXCEPTION = RuntimeError


class KeyringException(Exception):
    """
    Base exception for all exceptions raised by the
    :class:`~easy_vault.Keyring` class.

    Derived from :exc:`~py:Exception`.
    """
    pass


class KeyringNotAvailable(KeyringException):
    """
    Exception indicating that the keyring service is not available.

    Derived from :exc:`KeyringException`.
    """
    pass


class KeyringError(KeyringException):
    """
    Exception indicating that an error happend in the keyring service.

    Derived from :exc:`KeyringException`.
    """
    pass


class Keyring(object):
    """
    Access to the keyring service of the local system for storing vault
    passwords.

    An object of this class is tied to the keyring service and can store and
    retrieve multiple vault passwords.

    The keyring items that are created have a fixed service/app name that
    starts with 'easy_vault'. There is one keyring item for each vault file.

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
          :exc:`KeyringNotAvailable`: No keyring service available.
          :exc:`KeyringError`: An error happend in the keyring service.
        """
        try:
            return keyring.get_password(
                self.keyring_service(), self.keyring_username(filepath))
        except NO_KEYRING_EXCEPTION as exc:
            new_exc = KeyringNotAvailable(str(exc))
            new_exc.__cause__ = None
            raise new_exc  # KeyringNotAvailable
        except keyring.errors.KeyringError as exc:
            new_exc = KeyringError(str(exc))
            new_exc.__cause__ = None
            raise new_exc  # KeyringError

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
          :exc:`KeyringNotAvailable`: No keyring service available.
          :exc:`KeyringError`: An error happend in the keyring service.
        """
        try:
            keyring.set_password(
                self.keyring_service(),
                self.keyring_username(filepath), password)
        except NO_KEYRING_EXCEPTION as exc:
            new_exc = KeyringNotAvailable(str(exc))
            new_exc.__cause__ = None
            raise new_exc  # KeyringNotAvailable
        except keyring.errors.KeyringError as exc:
            new_exc = KeyringError(str(exc))
            new_exc.__cause__ = None
            raise new_exc  # KeyringError

    def delete_password(self, filepath):
        """
        Delete the password for a vault file in the keyring service.

        Parameters:

          filepath (:term:`unicode string`):
            Path name of the vault file. It will be normalized to identify the
            keyring item for the vault file.

        Returns:
          bool: Indicates whether the password existed.

        Raises:
          :exc:`KeyringNotAvailable`: No keyring service available.
          :exc:`KeyringError`: An error happend in the keyring service.
        """
        service = self.keyring_service()
        username = self.keyring_username(filepath)
        try:
            pw = keyring.get_password(service, username)
        except NO_KEYRING_EXCEPTION as exc:
            new_exc = KeyringNotAvailable(str(exc))
            new_exc.__cause__ = None
            raise new_exc  # KeyringNotAvailable
        except keyring.errors.KeyringError as exc:
            new_exc = KeyringError(str(exc))
            new_exc.__cause__ = None
            raise new_exc  # KeyringError

        if pw is None:
            return False

        try:
            keyring.delete_password(service, username)
        except NO_KEYRING_EXCEPTION as exc:
            new_exc = KeyringNotAvailable(str(exc))
            new_exc.__cause__ = None
            raise new_exc  # KeyringNotAvailable
        except keyring.errors.KeyringError as exc:
            new_exc = KeyringError(str(exc))
            new_exc.__cause__ = None
            raise new_exc  # KeyringError

        return True

    def is_available(self):
        """
        Indicate whether the keyring service is available on the local system.

        This function reports this only as a boolean. If information about
        the reasons for not being available is needed, use the
        :meth:`check_available` method instead.

        Returns:
          bool: Keyring service is available on the local system.
        """
        try:
            self.check_available()
        except KeyringNotAvailable:
            return False
        return True

    @staticmethod
    def check_available():
        """
        Check whether the keyring service is available on the local system.

        If available, the method returns.

        If not available, an exception is raised with a message that provides
        some information about the keyring configuration.

        Raises:
          :exc:`KeyringNotAvailable`: No keyring service available.
        """

        # Check the cases where the keyring package indicates it has no
        # keyring service found or no backend configured.

        backend = keyring.get_keyring()

        if isinstance(backend, keyring.backends.chainer.ChainerBackend):
            if not backend.backends:
                raise KeyringNotAvailable(
                    "No keyring service found by the configured backends")

        if isinstance(backend, keyring.backends.fail.Keyring):
            raise KeyringNotAvailable(
                "No keyring service found by the configured backends")

        if isinstance(backend, keyring.backends.null.Keyring):
            raise KeyringNotAvailable(
                "Keyring service disabled by a configured null backend")

        # In theory, now the keyring service should be available.
        # We try it out to really make sure.

        kr = Keyring()
        service = kr.keyring_service()
        username = kr.keyring_username('deleteme:check_available')
        try:
            keyring.set_password(service, username, 'dummy')
        except NO_KEYRING_EXCEPTION as exc:
            new_exc = KeyringNotAvailable(
                "Keyring test call failed with: {msg}".format(msg=exc))
            new_exc.__cause__ = None
            raise new_exc  # KeyringNotAvailable
        except keyring.errors.KeyringError as exc:
            new_exc = KeyringError(str(exc))
            new_exc.__cause__ = None
            raise new_exc  # KeyringError
        try:
            keyring.delete_password(service, username)
        except Exception as exc:
            new_exc = KeyringNotAvailable(
                "Keyring cleanup call failed with: {msg}".format(msg=exc))
            new_exc.__cause__ = None
            raise new_exc  # KeyringNotAvailable

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
