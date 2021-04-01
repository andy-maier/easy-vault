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
Test the _password.py module.
"""

from __future__ import absolute_import, print_function

import pytest
from easy_vault import get_password, set_password

# pylint: disable=unused-import
from ..utils.keyring_utils import keyring_filepath  # noqa: F401
from ..utils.keyring_utils import is_keyring_available


@pytest.mark.skipif(
    not is_keyring_available(), reason="No keyring service available")
# pylint: disable=redefined-outer-name
def test_password_get_set(keyring_filepath):
    """
    Test function for easy_vault.get_password() / set_password()

    Since the get_password() prompts, we perform the test so that the
    password is first set and then retrieved.
    """
    password1 = 'mypassword1'
    password2 = 'mypassword2'

    # Set the password1 (create a new password)
    set_password(keyring_filepath, password1)

    # Get the password1 again
    act_password1 = get_password(keyring_filepath, use_prompting=False)
    assert act_password1 == password1

    # Set the password2 (update an existing password)
    set_password(keyring_filepath, password2)

    # Get the password2 again
    act_password2 = get_password(keyring_filepath, use_prompting=False)
    assert act_password2 == password2


@pytest.mark.skipif(
    not is_keyring_available(), reason="No keyring service available")
# pylint: disable=redefined-outer-name
def test_password_fail1(keyring_filepath):
    """
    Test function for easy_vault.get_password() / set_password()

    Failure by disabling use of both keyring service and prompting.
    """
    with pytest.raises(ValueError):
        get_password(keyring_filepath, use_keyring=False, use_prompting=False)
