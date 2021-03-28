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
The EasyVault class and its exceptions.
"""

from __future__ import absolute_import, print_function
import os
import re
import tempfile
import hashlib
import base64

import yaml
import six
from cryptography.fernet import Fernet

__all__ = ['EasyVault', 'EasyVaultException', 'EasyVaultFileError',
           'EasyVaultDecryptError', 'EasyVaultEncryptError',
           'EasyVaultYamlError']


# Line width in encrypted vault file
ENCRYPTED_LINE_WIDTH = 80

# Header used in encrypted files
HEADER_MONIKER = b'EASY_VAULT'
HEADER_VERSION = b'1.0'
HEADER = b'$' + HEADER_MONIKER + b';' + HEADER_VERSION + b'\n'
HEADER_PATTERN = re.compile(
    rb'^\$(?P<moniker>[A-Z0-9_]+);(?P<version>[0-9.]+)$')


class EasyVaultException(Exception):
    """
    Base exception for all exceptions raised by the
    :class:`~easy_vault.EasyVault` class.

    Derived from :exc:`py:Exception`.
    """
    pass


class EasyVaultFileError(EasyVaultException):
    """
    Exception indicating file I/O errors with a vault file.

    Derived from :exc:`EasyVaultException`.
    """
    pass


class EasyVaultDecryptError(EasyVaultException):
    """
    Exception indicating that an encrypted vault file could not be decrypted.

    Derived from :exc:`EasyVaultException`.
    """
    pass


class EasyVaultEncryptError(EasyVaultException):
    """
    Exception indicating that an unencrypted vault file could not be encrypted.

    Derived from :exc:`EasyVaultException`.
    """
    pass


class EasyVaultYamlError(EasyVaultException):
    """
    Exception indicating that a vault file in YAML format has a format issue.

    Derived from :exc:`EasyVaultException`.
    """
    pass


class EasyVault(object):
    """
    A vault file that can be encrypted and decrypted.

    An object of this class is tied to a single vault file and a single
    vault password.

    There are no requirements for the format of the vault file. It may be a text
    file or a binary file (but the typical case for a vault file would be a text
    file, e.g. in YAML format).

    There is no size limit to the vault file. However, because the complete
    vault file is read into memory and its data is passed to the encryption and
    decryption functions in one chunk, this implementation is not well suited
    for handling huge files. It is really meant for vault files: Files that
    keep secrets, but not huge data.

    The password is converted to a symmetric key which is then used for
    encryption and decryption of the vault file.

    The encryption package used by this class is pluggable. The default
    implementation uses the :mod:`cryptography.fernet` module as an encryption
    package, and calculates the key as urlsafe_base64(SHA256(password)).

    Users who whish to use a different encryption package can do so by
    subclassing this class and implementing the following methods to use a
    different encryption package:

    * :meth:`to_key` - Calculate a symmetric key from a password.
    * :meth:`encrypt_data` - Encrypt clear data with a symmetric key.
    * :meth:`decrypt_data` - Decrypt encrypted data with a symmetric key.
    """

    def __init__(self, filepath, password):
        """
        Parameters:

          filepath (:term:`unicode string`):
            Path name of the vault file.

          password (:term:`unicode string`):
            Password for encrypting and decrypting the vault file.
        """
        self._filepath = filepath
        if not isinstance(password, six.string_types):
            raise TypeError(
                "The password argument is not a unicode string, but: {t}".
                format(t=type(password)))
        key = self.to_key(password)
        if not isinstance(key, six.binary_type):
            raise TypeError(
                "The return value of to_key() is not a byte string, but: {t}".
                format(t=type(key)))
        self._key = key

    @property
    def filepath(self):
        """
        :term:`unicode string`): Path name of the vault file.
        """
        return self._filepath

    def is_encrypted(self):
        """
        Test whether the vault file is encrypted by easy-vault.

        This is done by checking for the unique easy-vault header in the first
        line of the vault file.

        Returns:
          bool: Boolean indicating whether the vault file is encrypted by
          easy-vault.

        Raises:
          EasyVaultFileError: Error with the vault file
        """

        try:
            with open(self._filepath, 'rb') as fp:
                first_bline = fp.readline()  # Including trailing newline
        except (OSError, IOError) as exc:
            new_exc = EasyVaultFileError(
                "Cannot open vault file {fn} for reading: {exc}".
                format(fn=self._filepath, exc=exc))
            new_exc.__cause__ = None
            raise new_exc  # VaultFileOpenError

        m = HEADER_PATTERN.match(first_bline)
        if m is None:
            return False
        if m.group('moniker') != HEADER_MONIKER:
            return False
        return True

    def encrypt(self):
        """
        Encrypt the vault file.

        The vault file must be unencrypted (i.e. not encrypted by easy-vault).

        Raises:
          EasyVaultFileError: Error with the vault file or a temporary file
          EasyVaultEncryptError: Error encrypting the vault file
        """

        try:
            with open(self._filepath, 'rb', encoding=None) as fp:
                first_bline = fp.readline()  # Including trailing newline
                m = HEADER_PATTERN.match(first_bline)
                if m and m.group('moniker') == HEADER_MONIKER:
                    raise EasyVaultEncryptError(
                        "Cannot encrypt vault file {fn}: "
                        "The file is already encrypted".
                        format(fn=self._filepath))
                clear_bdata = first_bline + fp.read()
        except (OSError, IOError) as exc:
            new_exc = EasyVaultFileError(
                "Cannot open vault file {fn} for reading: {exc}".
                format(fn=self._filepath, exc=exc))
            new_exc.__cause__ = None
            raise new_exc  # EasyVaultFileError

        assert isinstance(clear_bdata, six.binary_type), type(clear_bdata)
        encrypted_bdata = self.encrypt_data(clear_bdata, self._key)
        if not isinstance(encrypted_bdata, six.binary_type):
            raise TypeError(
                "The return value of encrypt_data() is not a byte string, "
                "but: {t}".format(t=type(encrypted_bdata)))

        encrypted_blines = HEADER
        for bchunk in chunks(encrypted_bdata, ENCRYPTED_LINE_WIDTH):
            encrypted_blines += bchunk + b'\n'

        write_file(self._filepath, encrypted_blines)

    def decrypt(self):
        """
        Decrypt the vault file.

        The vault file must be encrypted by easy-vault.

        Raises:
          EasyVaultFileError: Error with the vault file or a temporary file
          EasyVaultDecryptError: Error decrypting the vault file
        """
        clear_bdata = self._get_bytes_from_encrypted()
        write_file(self._filepath, clear_bdata)

    def _get_bytes_from_encrypted(self):
        """
        Get the unencrypted data from an encrypted vault file.

        Returns:
          :term:`byte string`: Unencrypted data from the vault file.

        Raises:
          EasyVaultFileError: Error with the vault file
          EasyVaultDecryptError: Error decrypting the vault file
        """

        try:
            with open(self._filepath, 'rb') as fp:
                first_bline = fp.readline()  # Including trailing newline
                m = HEADER_PATTERN.match(first_bline)
                if m is None or m.group('moniker') != HEADER_MONIKER:
                    raise EasyVaultDecryptError(
                        "Cannot decrypt vault file {fn}: "
                        "The file is not encrypted".
                        format(fn=self._filepath))
                encrypted_blines = fp.read()
        except (OSError, IOError) as exc:
            new_exc = EasyVaultFileError(
                "Cannot open vault file {fn} for reading: {exc}".
                format(fn=self._filepath, exc=exc))
            new_exc.__cause__ = None
            raise new_exc  # EasyVaultFileError

        encrypted_bdata = b'\n'.join(encrypted_blines.split(b'\n'))
        assert isinstance(encrypted_bdata, six.binary_type), \
            type(encrypted_bdata)
        clear_bdata = self.decrypt_data(encrypted_bdata, self._key)
        if not isinstance(clear_bdata, six.binary_type):
            raise TypeError(
                "The return value of decrypt_data() is not a byte string, "
                "but: {t}".format(t=type(clear_bdata)))
        return clear_bdata

    def _get_bytes_from_clear(self):
        """
        Get the data from an unencrypted vault file.

        Returns:
          :term:`byte string`: Unencrypted data from the vault file.

        Raises:
          EasyVaultFileError: Error with the vault file
        """
        try:
            with open(self._filepath, 'rb') as fp:
                clear_bdata = fp.read()
        except (OSError, IOError) as exc:
            new_exc = EasyVaultFileError(
                "Cannot open vault file {fn} for reading: {exc}".
                format(fn=self._filepath, exc=exc))
            new_exc.__cause__ = None
            raise new_exc  # EasyVaultFileError
        return clear_bdata

    def get_bytes(self):
        """
        Get the unencrypted content of the vault file as a Byte sequence.

        The vault file may be encrypted or unencrypted.

        Returns:
          :term:`byte string`: Unencrypted content of the vault file, as a Byte
          sequence.

        Raises:
          EasyVaultFileError: Error with the vault file
          EasyVaultDecryptError: Error decrypting the vault file
        """
        if self.is_encrypted():
            return self._get_bytes_from_encrypted()
        return self._get_bytes_from_clear()

    def get_text(self):
        """
        Get the unencrypted content of the vault file as a Unicode string.

        The vault file may be encrypted or unencrypted.

        Returns:
          :term:`unicode string`: Unencrypted content of the vault file, as a
          Unicode string.

        Raises:
          EasyVaultFileError: Error with the vault file
          EasyVaultDecryptError: Error decrypting the vault file
        """
        bdata = self.get_bytes()
        udata = bdata.decode('utf-8')
        return udata

    def get_yaml(self):
        """
        Get the unencrypted content of a YAML-formatted vault file as a YAML
        object.

        The vault file may be encrypted or unencrypted.

        Returns:
          dict or list: Top-level object of the YAML-formatted vault file.

        Raises:
          EasyVaultFileError: Error with the vault file or a temporary file
          EasyVaultYamlError: YAML syntax error in the vault file
          EasyVaultDecryptError: Error decrypting the vault file
        """
        clear_bdata = self.get_bytes()
        try:
            data_obj = yaml.safe_load(clear_bdata)
        except yaml.YAMLError as exc:
            new_exc = EasyVaultYamlError(
                "Invalid YAML syntax in vault file {fn}: {exc}".
                format(fn=self._filepath, exc=exc))
            new_exc.__cause__ = None
            raise new_exc  # EasyVaultYamlError
        return data_obj

    @staticmethod
    def to_key(password):
        """
        Encryption implementation: Calculate a symmetric key from a password.

        The key must match the requirements of the encryption package that is
        used in the :meth:`encrypt_data` and :meth:`decrypt_data` methods.

        The same password must result in the same key, and different passwords
        should result in different keys.

        This method can be overwritten by users to use a different encryption
        package. Its default implementation uses the :mod:`cryptography.fernet`
        encryption package and calculates the key as
        urlsafe_base64(SHA256(password)).

        Parameters:

          password (:term:`unicode string`):
            Password for encrypting and decrypting the vault file.

        Returns:
          :term:`byte string`: The calculated key.
        """
        m = hashlib.sha256()
        m.update(password.encode('utf-8'))
        key_bytes = m.digest()  # binary string of 32 Bytes
        key_base64 = base64.urlsafe_b64encode(key_bytes)
        return key_base64

    @staticmethod
    def encrypt_data(clear_data, key):
        """
        Encryption implementation: Encrypt clear data with a symmetric key.

        This method can be overwritten by users to use a different encryption
        package. Its default implementation uses the :mod:`cryptography.fernet`
        encryption package.

        Parameters:

          clear_data (:term:`byte string`):
            The clear data to be encrypted.

          key (:term:`byte string`):
            The symmetric key to be used for the encryption.

        Returns:
          :term:`byte string`: The encrypted data.
        """
        f = Fernet(key)
        encrypted_data = f.encrypt(clear_data)
        return encrypted_data

    @staticmethod
    def decrypt_data(encrypted_data, key):
        """
        Encryption implementation: Decrypt encrypted data with a symmetric key.

        This method can be overwritten by users to use a different encryption
        package. Its default implementation uses the :mod:`cryptography.fernet`
        encryption package.

        Parameters:

          encrypted_data (:term:`byte string`):
            The encrypted data to be decrypted.

          key (:term:`byte string`):
            The encryption key to be used.

        Returns:
          :term:`byte string`: The clear data.
        """
        f = Fernet(key)
        clear_data = f.decrypt(encrypted_data)
        return clear_data


def write_file(filepath, data):
    """
    Write data to a file in a manner that is safe against keyboard breaks or
    other program aborts.

    This is done by first writing the data to a temporary file and then renaming
    the file. Since the rename operation is performed by the operating system
    as an atomic operation, it results either in the new file or the previous
    file still exists unchanged.

    Parameters:

      filepath (:term:`unicode string`):
        Path name of the file to be written.

      data (:term:`byte string`):
        The data to be written.

    Raises:
      EasyVaultFileError: Error with the vault file or a temporary file
    """
    assert isinstance(data, six.binary_type), type(data)
    try:
        with tempfile.NamedTemporaryFile(
                mode='wb', delete=False, prefix='easy_vault') as tfp:
            tfp.write(data)
            tfpath = tfp.name
    except (OSError, IOError) as exc:
        new_exc = EasyVaultFileError(
            "Cannot open temporary file {tfn} for writing: {exc}".
            format(tfn=tfp.name, exc=exc))
        new_exc.__cause__ = None
        raise new_exc  # EasyVaultFileError

    try:
        os.rename(tfpath, filepath)
    except (OSError, IOError) as exc:
        new_exc = EasyVaultFileError(
            "Cannot rename temporary file {tfn} to vault file {fn}: {exc}".
            format(tfn=tfpath, fn=filepath, exc=exc))
        new_exc.__cause__ = None
        raise new_exc  # EasyVaultFileError


def chunks(iterable, size):
    """
    Generator that yields successive equal-sized chunks from a subscriptable
    iterable (such as a string).
    """
    for i in range(0, len(iterable), size):
        yield iterable[i:i + size]
