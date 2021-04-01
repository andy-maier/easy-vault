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
    keyringlib = KeyRingLib()
    return keyringlib.is_available()


def remove_keyring_item(filepath):
    """
    Remove the keyring item for the specified vault file, if it exists.
    """
    keyringlib = KeyRingLib()
    service = keyringlib.keyring_service()
    username = keyringlib.keyring_username(filepath)

    if keyring.get_password(service, username) is not None:
        keyring.delete_password(service, username)
