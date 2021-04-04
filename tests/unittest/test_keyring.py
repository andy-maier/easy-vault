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
Test the _keyring.py module.
"""

from __future__ import absolute_import, print_function

import pytest
from easy_vault import Keyring, KeyringNotAvailable

# pylint: disable=unused-import
from ..utils.keyring_utils import keyring_filepath  # noqa: F401
from ..utils.keyring_utils import is_keyring_available


@pytest.mark.skipif(
    not is_keyring_available(), reason="No keyring service available")
# pylint: disable=redefined-outer-name
def test_keyring_get_set_delete(keyring_filepath):
    """
    Test function for Keyring.get_password() / set_password() /
    delete_password()
    """
    kr = Keyring()
    password = 'mypassword'

    # Test that the password does not exist
    act_password = kr.get_password(keyring_filepath)
    assert act_password is None

    # Test that the password does not exist
    existed = kr.delete_password(keyring_filepath)
    assert existed is False

    # Test that setting a password succeeds
    kr.set_password(keyring_filepath, password)

    # Test that getting a password succeeds and is as expected
    act_password = kr.get_password(keyring_filepath)
    assert act_password == password

    # Delete the password
    existed = kr.delete_password(keyring_filepath)
    assert existed is True

    # Test that the password does not exist
    existed = kr.delete_password(keyring_filepath)
    assert existed is False


def test_keyring_available():
    """
    Test function for Keyring.is_available()
    """
    kr = Keyring()

    # Code to be tested
    is_avail = kr.is_available()

    assert isinstance(is_avail, bool)

    check_avail = True
    try:
        # Code to be tested
        kr.check_available()
    except Exception as exc:  # pylint: disable=broad-except
        assert isinstance(exc, KeyringNotAvailable)
        check_avail = False

    assert check_avail == is_avail
