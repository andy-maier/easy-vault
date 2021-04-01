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
import keyring.backends.chainer  # Required to import separately
import keyring.backends.null  # Required to import separately
import keyring.backends.fail

__all__ = ['KeyRingLib', 'KeyRingException', 'KeyRingNotAvailable',
           'KeyRingError']


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


class KeyRingException(Exception):
    """
    Base exception for all exceptions raised by the
    :class:`~easy_vault.KeyRingLib` class.

    Derived from :exc:`~py:Exception`.
    """
    pass


class KeyRingNotAvailable(KeyRingException):
    """
    Exception indicating that the keyring service is not available.

    Derived from :exc:`KeyRingException`.
    """
    pass


class KeyRingError(KeyRingException):
    """
    Exception indicating that an error happend in the keyring service.

    Derived from :exc:`KeyRingException`.
    """
    pass


class KeyRingLib(object):
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
          :exc:`KeyRingNotAvailable`: No keyring service available.
          :exc:`KeyRingError`: An error happend in the keyring service.
        """
        try:
            return keyring.get_password(
                self.keyring_service(), self.keyring_username(filepath))
        except NO_KEYRING_EXCEPTION as exc:
            raise KeyRingNotAvailable(str(exc))
        except keyring.errors.KeyringError as exc:
            raise KeyRingError(str(exc))

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
          :exc:`KeyRingNotAvailable`: No keyring service available.
          :exc:`KeyRingError`: An error happend in the keyring service.
        """
        keyring.set_password(
            self.keyring_service(), self.keyring_username(filepath), password)

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
        except KeyRingNotAvailable:
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
          :exc:`KeyRingNotAvailable`: No keyring service available.
        """

        # Check the cases where the keyring package indicates it has no
        # keyring service found or no backend configured.

        backend = keyring.get_keyring()

        if isinstance(backend, keyring.backends.chainer.ChainerBackend):
            if not backend.backends:
                raise KeyRingNotAvailable(
                    "No keyring service found by the configured backends")

        if isinstance(backend, keyring.backends.fail.Keyring):
            raise KeyRingNotAvailable(
                "No keyring service found by the configured backends")

        if isinstance(backend, keyring.backends.null.Keyring):
            raise KeyRingNotAvailable(
                "Keyring service disabled by a configured null backend")

        # In theory, now the keyring service should be available.
        # We try it out to really make sure.

        keyringlib = KeyRingLib()
        service = keyringlib.keyring_service()
        username = keyringlib.keyring_username('deleteme:check_available')
        try:
            keyring.set_password(service, username, 'dummy')
        except NO_KEYRING_EXCEPTION as exc:
            new_exc = KeyRingNotAvailable(
                "Keyring test call failed with: {msg}".format(msg=exc))
            new_exc.__cause__ = None
            raise new_exc  # KeyRingNotAvailable
        try:
            keyring.delete_password(service, username)
        except Exception as exc:
            new_exc = KeyRingNotAvailable(
                "Keyring cleanup call failed with: {msg}".format(msg=exc))
            new_exc.__cause__ = None
            raise new_exc  # KeyRingNotAvailable

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
