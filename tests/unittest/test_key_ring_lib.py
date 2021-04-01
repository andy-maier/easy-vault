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
Test the _key_ring_lib.py module.
"""

from __future__ import absolute_import, print_function

import pytest
from easy_vault import KeyRingLib, KeyRingNotAvailable

# pylint: disable=unused-import
from ..utils.keyring_utils import keyring_filepath  # noqa: F401
from ..utils.keyring_utils import is_keyring_available


@pytest.mark.skipif(
    not is_keyring_available(), reason="No keyring service available")
# pylint: disable=redefined-outer-name
def test_keyringlib_get_set(keyring_filepath):
    """
    Test function for KeyRingLib.get_password() / set_password()
    """
    keyringlib = KeyRingLib()
    password = 'mypassword'

    # Test that the password does not exist
    act_password = keyringlib.get_password(keyring_filepath)
    assert act_password is None

    # Test that setting a password succeeds
    keyringlib.set_password(keyring_filepath, password)

    # Test that getting a password succeeds and is as expected
    act_password = keyringlib.get_password(keyring_filepath)
    assert act_password == password


def test_keyringlib_available():
    """
    Test function for KeyRingLib.is_available()
    """
    keyringlib = KeyRingLib()

    # Code to be tested
    is_avail = keyringlib.is_available()

    assert isinstance(is_avail, bool)

    check_avail = True
    try:
        # Code to be tested
        keyringlib.check_available()
    except Exception as exc:  # pylint: disable=broad-except
        assert isinstance(exc, KeyRingNotAvailable)
        check_avail = False

    assert check_avail == is_avail
