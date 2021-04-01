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
keyring_utils - Utilities for keyring testing.
"""

from __future__ import absolute_import

import pytest
import keyring
import keyring.backends.chainer  # Required to import separately
import keyring.backends.null  # Required to import separately
import keyring.backends.fail

from easy_vault import KeyRingLib


@pytest.fixture
def keyring_filepath():
    """
    Pytest fixture for preparing the keyring service for an entry for one
    vault file.
    """
    filepath = 'test/keyring_filepath'  # Does not need to exist
    remove_keyring_item(filepath)
    yield filepath
    remove_keyring_item(filepath)


def is_keyring_available():
    """
    Return boolean indicating whether the keyring service is available on
    the local system.
    """

    # Check some obvious cases where no keyring service is available

    backend = keyring.get_keyring()
    if isinstance(backend, keyring.backends.chainer.ChainerBackend):
        if not backend.backends:
            # Chainer backend with empty list of real backends
            return False
    if isinstance(backend, keyring.backends.fail.Keyring):
        return False
    if isinstance(backend, keyring.backends.null.Keyring):
        return False

    # In theory, now the keyring service should be available.
    # We try it out to make really sure.

    keyringlib = KeyRingLib()
    service = keyringlib.keyring_service()
    username = keyringlib.keyring_username('test/is_keyring_available')

    # Exception to catch when no keyring service is available.
    # Keyring version 22.0 introduced NoKeyringError and before that used
    # RuntimeError.
    try:
        no_keyring_exception = keyring.errors.NoKeyringError
    except AttributeError:
        no_keyring_exception = RuntimeError

    try:
        keyring.set_password(service, username, 'dummy')
    except no_keyring_exception:
        return False
    else:
        keyring.delete_password(service, username)
        return True


def remove_keyring_item(filepath):
    """
    Remove the keyring item for the specified vault file, if it exists.
    """
    keyringlib = KeyRingLib()
    service = keyringlib.keyring_service()
    username = keyringlib.keyring_username(filepath)

    if keyring.get_password(service, username) is not None:
        keyring.delete_password(service, username)
