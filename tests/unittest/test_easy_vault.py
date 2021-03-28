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
Test the _easy_vault.py module.
"""

from __future__ import absolute_import, print_function
import pytest
# from testfixtures import TempDirectory
from easy_vault import EasyVault

from ..utils.simplified_test_function import simplified_test_function


TEST_VAULT_FILEPATH = 'examples/vault.yml'
TEST_VAULT_PASSWORD = 'mypassword'

TESTCASES_VAULT_INIT = [

    # Testcases for EasyVault.__init__()

    # Each list item is a testcase tuple with these items:
    # * desc: Short testcase description.
    # * kwargs: Keyword arguments for the test function:
    #   * init_args: Tuple of positional arguments to EasyVault().
    #   * init_kwargs: Dict of keyword arguments to EasyVault().
    #   * exp_attrs: Dict with expected EasyVault attributes.
    # * exp_exc_types: Expected exception type(s), or None.
    # * exp_warn_types: Expected warning type(s), or None.
    # * condition: Boolean condition for testcase to run, or 'pdb' for debugger

    (
        "Order of positional parameters",
        dict(
            init_args=(
                TEST_VAULT_FILEPATH,
                TEST_VAULT_PASSWORD,
            ),
            init_kwargs=dict(),
            exp_attrs={
                'filepath': TEST_VAULT_FILEPATH,
            },
        ),
        None, None, True
    ),
    (
        "Names of keyword arguments",
        dict(
            init_args=(),
            init_kwargs=dict(
                filepath=TEST_VAULT_FILEPATH,
                password=TEST_VAULT_PASSWORD,
            ),
            exp_attrs={
                'filepath': TEST_VAULT_FILEPATH,
            },
        ),
        None, None, True
    ),
    (
        "Omitted required parameter: filepath",
        dict(
            init_args=(),
            init_kwargs=dict(
                password=TEST_VAULT_PASSWORD,
            ),
            exp_attrs=None,
        ),
        TypeError, None, True
    ),
    (
        "Omitted required parameter: password",
        dict(
            init_args=(),
            init_kwargs=dict(
                filepath=TEST_VAULT_FILEPATH,
            ),
            exp_attrs=None,
        ),
        TypeError, None, True
    ),
    (
        "Vault file does not exist (no error at init time)",
        dict(
            init_args=(),
            init_kwargs=dict(
                filepath='invalid_file',
                password=TEST_VAULT_PASSWORD,
            ),
            exp_attrs={
                'filepath': 'invalid_file',
            },
        ),
        None, None, True
    ),
]


@pytest.mark.parametrize(
    "desc, kwargs, exp_exc_types, exp_warn_types, condition",
    TESTCASES_VAULT_INIT)
@simplified_test_function
def test_vault_init(testcase, init_args, init_kwargs, exp_attrs):
    """
    Test function for EasyVault.__init__()
    """

    # The code to be tested
    act_obj = EasyVault(*init_args, **init_kwargs)

    # Ensure that exceptions raised in the remainder of this function
    # are not mistaken as expected exceptions
    assert testcase.exp_exc_types is None, \
        "Expected exception not raised: {}". \
        format(testcase.exp_exc_types)

    for attr_name in exp_attrs:
        exp_attr_value = exp_attrs[attr_name]
        assert hasattr(act_obj, attr_name), \
            "Missing attribute {0!r} in returned EasyVault object". \
            format(attr_name)
        act_attr_value = getattr(act_obj, attr_name)
        assert act_attr_value == exp_attr_value, \
            "Unexpected value for attribute {0!r}: Expected {1!r}, got {2!r}".\
            format(attr_name, exp_attr_value, act_attr_value)
