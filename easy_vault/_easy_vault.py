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
import shutil
import base64

import yaml
import six
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

__all__ = ['EasyVault', 'EasyVaultException', 'EasyVaultFileError',
           'EasyVaultDecryptError', 'EasyVaultEncryptError',
           'EasyVaultYamlError']


# Line width in encrypted vault file
ENCRYPTED_LINE_WIDTH = 80

# Header used in encrypted files
HEADER_MONIKER = b'EASY_VAULT'
HEADER_VERSION = b'1.0'
HEADER = b'$' + HEADER_MONIKER + b';' + HEADER_VERSION + b'\n'
# Python 2.7 does not support using both 'r' and 'b', so we use 'b' only.
HEADER_PATTERN = re.compile(
    b'^\\$(?P<moniker>[A-Z0-9_]+);(?P<version>[0-9.]+)$')


class EasyVaultException(Exception):
    """
    Base exception for all exceptions raised by the
    :class:`~easy_vault.EasyVault` class.

    Derived from :exc:`~py:Exception`.
    """
    pass


class EasyVaultFileError(EasyVaultException):
    """
    Exception indicating file I/O errors with a vault file or with a temporary
    file (that is used when writing the vault file).

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
    Exception indicating that a decrypted vault file could not be encrypted.

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
    vault file is read into memory in one chunk, this implementation is not
    well suited for handling huge files. It is really meant for vault files:
    Files that keep secrets, but not huge data.

    The password may be provided or not (`None`).
    If the password is provided, it is converted to a symmetric key which is
    then used for encrypting and decrypting the vault file itself and for
    decrypting the vault file content upon access.
    If the password is not provided, encryption and decryption of the vault file
    is rejected and access to the vault file content requires that the vault
    file is in the decrypted state.

    The encryption package used by this class is pluggable. The default
    implementation uses the symmetric key support from the
    `cryptography package <https://cryptography.io/en/stable/>`_.

    Users who whish to use a different encryption package can do so by
    subclassing this class and implementing the following methods to use a
    different encryption package:

    * :meth:`generate_key` - Calculate a symmetric key from a password.
    * :meth:`encrypt_data` - Encrypt clear data with a symmetric key.
    * :meth:`decrypt_data` - Decrypt encrypted data with a symmetric key.
    """

    def __init__(self, filepath, password=None):
        """
        Parameters:

          filepath (:term:`unicode string`):
            Path name of the vault file.

          password (:term:`unicode string`):
            Password for encrypting and decrypting the vault file, or `None`
            if not provided.

        Raises:
          TypeError: Type error in arguments or in return of pluggable
            encryption function.
        """
        self._filepath = filepath
        if password is None:
            self._key = None
        else:
            if not isinstance(password, six.string_types):
                raise TypeError(
                    "The password argument is not a unicode string, but: {t}".
                    format(t=type(password)))
            key = self.generate_key(password)
            if not isinstance(key, six.binary_type):
                raise TypeError(
                    "The return value of generate_key() is not a byte string, "
                    "but: {t}".
                    format(t=type(key)))
            self._key = key

    @property
    def filepath(self):
        """
        :term:`unicode string`): Path name of the vault file.
        """
        return self._filepath

    @property
    def password_provided(self):
        """
        bool: Indicates whether a vault password was provided.
        """
        return self._key is not None

    def is_encrypted(self):
        """
        Test whether the vault file is encrypted by easy-vault.

        This is done by checking for the unique easy-vault header in the first
        line of the vault file.

        This method does not require a vault password to be provided.

        Returns:
          bool: Boolean indicating whether the vault file is encrypted by
          easy-vault.

        Raises:
          :exc:`EasyVaultFileError`: I/O error with the vault file.
        """
        try:
            with open(self._filepath, 'rb') as fp:
                first_bline = fp.readline()  # Including trailing newline
        except (OSError, IOError) as exc:
            new_exc = EasyVaultFileError(
                "Cannot open vault file {fn} for reading: {exc}".
                format(fn=self._filepath, exc=exc))
            new_exc.__cause__ = None
            raise new_exc  # EasyVaultFileError
        # On Windows, match() does not tolerate CRLF line endings
        first_bline_s = first_bline.strip(b'\n').strip(b'\r')
        m = HEADER_PATTERN.match(first_bline_s)
        if m is None:
            return False
        if m.group('moniker') != HEADER_MONIKER:
            return False
        return True

    def encrypt(self):
        """
        Encrypt the vault file.

        The vault file must be decrypted (i.e. not encrypted by easy-vault).

        This method requires a vault password to be provided.

        Raises:
          :exc:`EasyVaultFileError`: I/O error with the vault file or a
            temporary file.
          :exc:`EasyVaultEncryptError`: Error encrypting the vault file.
        """
        if not self.password_provided:
            raise EasyVaultEncryptError(
                "Cannot encrypt vault file {fn}: "
                "No password was provided".
                format(fn=self._filepath))

        try:
            with open(self._filepath, 'rb') as fp:
                first_bline = fp.readline()  # Including trailing newline
                first_bline_s = first_bline.strip(b'\n').strip(b'\r')
                # On Windows, match() does not tolerate CRLF line endings
                m = HEADER_PATTERN.match(first_bline_s)
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

        This method requires a vault password to be provided.

        Raises:
          :exc:`EasyVaultFileError`: I/O error with the vault file or a
            temporary file.
          :exc:`EasyVaultDecryptError`: Error decrypting the vault file.
        """
        clear_bdata = self._get_bytes_from_encrypted()
        write_file(self._filepath, clear_bdata)

    def _get_bytes_from_encrypted(self):
        """
        Get the content of an encrypted vault file by decrypting the content
        upon access and leaving the file unchanged.

        Returns:
          :term:`byte string`: Decrypted content of the vault file.

        Raises:
          :exc:`EasyVaultFileError`: I/O error with the vault file.
          :exc:`EasyVaultDecryptError`: Error decrypting the vault file.
        """
        if not self.password_provided:
            raise EasyVaultDecryptError(
                "Cannot decrypt vault file {fn}: "
                "No password was provided".
                format(fn=self._filepath))

        try:
            with open(self._filepath, 'rb') as fp:
                first_bline = fp.readline()  # Including trailing newline
                first_bline_s = first_bline.strip(b'\n').strip(b'\r')
                # On Windows, match() does not tolerate CRLF line endings
                m = HEADER_PATTERN.match(first_bline_s)
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
        Get the content of a decrypted vault file.

        Returns:
          :term:`byte string`: Decrypted content of the vault file.

        Raises:
          :exc:`EasyVaultFileError`: I/O error with the vault file.
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
        Get the decrypted content of the vault file as a Byte sequence.

        The vault file may be in the encrypted or decrypted state and remains
        unchanged.

        If the vault file is in the encrypted state, the object this method
        is called on must have been created with a vault password.

        Returns:
          :term:`byte string`: Decrypted content of the vault file, as a Byte
          sequence.

        Raises:
          :exc:`EasyVaultFileError`: I/O error with the vault file.
          :exc:`EasyVaultDecryptError`: Error decrypting the vault file.
        """
        if self.is_encrypted():
            return self._get_bytes_from_encrypted()
        return self._get_bytes_from_clear()

    def get_text(self):
        """
        Get the decrypted content of the vault file as a Unicode string.

        The vault file may be in the encrypted or decrypted state and remains
        unchanged.

        If the vault file is in the encrypted state, the object this method
        is called on must have been created with a vault password.

        Returns:
          :term:`unicode string`: Decrypted content of the vault file, as a
          Unicode string.

        Raises:
          :exc:`EasyVaultFileError`: I/O error with the vault file.
          :exc:`EasyVaultDecryptError`: Error decrypting the vault file.
        """
        bdata = self.get_bytes()
        udata = bdata.decode('utf-8')
        return udata

    def get_yaml(self):
        """
        Get the decrypted content of a YAML-formatted vault file as a YAML
        object.

        The vault file may be in the encrypted or decrypted state and remains
        unchanged.

        If the vault file is in the encrypted state, the object this method
        is called on must have been created with a vault password.

        Returns:
          dict or list: Top-level object of the YAML-formatted vault file.

        Raises:
          :exc:`EasyVaultFileError`: I/O error with the vault file or a
            temporary file.
          :exc:`EasyVaultYamlError`: YAML syntax error in the vault file.
          :exc:`EasyVaultDecryptError`: Error decrypting the vault file.
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
    def generate_key(password):
        """
        Encryption implementation: Calculate a symmetric key from a password.

        The key must match the requirements of the encryption package that is
        used in the :meth:`encrypt_data` and :meth:`decrypt_data` methods.

        Using this method repeatedly on the same password must result in the
        same key.

        This method can be overwritten by users to use a different encryption
        package. Its default implementation uses the
        `cryptography package <https://cryptography.io/en/stable/>`_,
        and calculates the key as a 256-bit key using 10000 iterations of
        SHA256 on the password, using a fixed salt.

        Parameters:

          password (:term:`unicode string`):
            Password for encrypting and decrypting the vault file.

        Returns:
          :term:`byte string`: The calculated key.
        """
        salt = b'fixed'
        bpassword = password.encode('utf-8')
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000,
            backend=default_backend())
        key = base64.urlsafe_b64encode(kdf.derive(bpassword))
        return key

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

    def decrypt_data(self, encrypted_data, key):
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

        Raises:
          :exc:`EasyVaultDecryptError`: Error decrypting the vault file.
        """
        f = Fernet(key)
        try:
            clear_data = f.decrypt(encrypted_data)
        except InvalidToken:
            new_exc = EasyVaultDecryptError(
                "Cannot decrypt vault file {fn}: Invalid password".
                format(fn=self._filepath))
            new_exc.__cause__ = None
            raise new_exc  # EasyVaultDecryptError
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
      :exc:`EasyVaultFileError`: I/O error with the file.
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
        # On Windows, the temp file may be on a different drive than the
        # original file, so os.rename() cannot be used.
        shutil.copy(tfpath, filepath)
        os.remove(tfpath)
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
