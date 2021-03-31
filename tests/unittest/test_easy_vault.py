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
import six
from easy_vault import EasyVault, EasyVaultFileError, EasyVaultEncryptError, \
    EasyVaultDecryptError

from ..utils.simplified_test_function import simplified_test_function
from ..utils.vault_utils import saved_file, assert_files_bytes_equal, \
    assert_files_text_equal, assert_content_text_equal

TEST_VAULT_DECRYPTED = 'tests/testfiles/vault_decrypted.yml'
TEST_VAULT_ENCRYPTED = 'tests/testfiles/vault_encrypted.yml'
TEST_VAULT_ERR_MONIKER = 'tests/testfiles/vault_err_moniker.yml'
TEST_VAULT_PASSWORD = 'vault'


TESTCASES_VAULT_INIT = [

    # Testcases for EasyVault.__init__() and properties

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
                TEST_VAULT_DECRYPTED,
                TEST_VAULT_PASSWORD,
            ),
            init_kwargs=dict(),
            exp_attrs={
                'filepath': TEST_VAULT_DECRYPTED,
                'password_provided': True,
            },
        ),
        None, None, True
    ),
    (
        "Names of keyword arguments",
        dict(
            init_args=(),
            init_kwargs=dict(
                filepath=TEST_VAULT_DECRYPTED,
                password=TEST_VAULT_PASSWORD,
            ),
            exp_attrs={
                'filepath': TEST_VAULT_DECRYPTED,
                'password_provided': True,
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
        "Omitted optional parameter: password",
        dict(
            init_args=(),
            init_kwargs=dict(
                filepath=TEST_VAULT_DECRYPTED,
            ),
            exp_attrs={
                'filepath': TEST_VAULT_DECRYPTED,
                'password_provided': False,
            },
        ),
        None, None, True
    ),
    (
        "Invalid type for parameter: password",
        dict(
            init_args=(),
            init_kwargs=dict(
                filepath=TEST_VAULT_DECRYPTED,
                password=42,
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
                'password_provided': True,
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
    Test function for EasyVault.__init__() and properties
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


TESTCASES_VAULT_IS_ENCRYPTED = [

    # Testcases for EasyVault.is_encrypted()

    # Each list item is a testcase tuple with these items:
    # * desc: Short testcase description.
    # * kwargs: Keyword arguments for the test function:
    #   * init_kwargs: Dict of keyword arguments to EasyVault().
    #   * exp_result: Expected result of the function that is tested.
    # * exp_exc_types: Expected exception type(s), or None.
    # * exp_warn_types: Expected warning type(s), or None.
    # * condition: Boolean condition for testcase to run, or 'pdb' for debugger

    (
        "Non-existing vault file",
        dict(
            init_kwargs=dict(
                filepath='invalid_file',
                password='password',
            ),
            exp_result=None,
        ),
        EasyVaultFileError, None, True
    ),
    (
        "Decrypted vault file",
        dict(
            init_kwargs=dict(
                filepath=TEST_VAULT_DECRYPTED,
                password=TEST_VAULT_PASSWORD,
            ),
            exp_result=False,
        ),
        None, None, True
    ),
    (
        "Encrypted vault file",
        dict(
            init_kwargs=dict(
                filepath=TEST_VAULT_ENCRYPTED,
                password=TEST_VAULT_PASSWORD,
            ),
            exp_result=True,
        ),
        None, None, True
    ),
    (
        "Encrypted vault file with incorrect moniker (detected as decrypted)",
        dict(
            init_kwargs=dict(
                filepath=TEST_VAULT_ERR_MONIKER,
                password=TEST_VAULT_PASSWORD,
            ),
            exp_result=False,
        ),
        None, None, True
    ),
]


@pytest.mark.parametrize(
    "desc, kwargs, exp_exc_types, exp_warn_types, condition",
    TESTCASES_VAULT_IS_ENCRYPTED)
@simplified_test_function
def test_vault_is_encrypted(testcase, init_kwargs, exp_result):
    """
    Test function for EasyVault.is_encrypted()
    """

    vault = EasyVault(**init_kwargs)

    # The code to be tested
    act_result = vault.is_encrypted()

    # Ensure that exceptions raised in the remainder of this function
    # are not mistaken as expected exceptions
    assert testcase.exp_exc_types is None, \
        "Expected exception not raised: {}". \
        format(testcase.exp_exc_types)

    assert act_result == exp_result


TESTCASES_VAULT_ENCRYPT = [

    # Testcases for EasyVault.encrypt()

    # Each list item is a testcase tuple with these items:
    # * desc: Short testcase description.
    # * kwargs: Keyword arguments for the test function:
    #   * filepath: Path name of vault file for the test. The file is backed
    #     up before the test and restored afterwards.
    #   * password: Password to be used for the test.
    # * exp_exc_types: Expected exception type(s), or None.
    # * exp_warn_types: Expected warning type(s), or None.
    # * condition: Boolean condition for testcase to run, or 'pdb' for debugger

    (
        "Decrypted vault file",
        dict(
            filepath=TEST_VAULT_DECRYPTED,
            password=TEST_VAULT_PASSWORD,
        ),
        None, None, True
    ),
    (
        "Encrypted vault file",
        dict(
            filepath=TEST_VAULT_ENCRYPTED,
            password=TEST_VAULT_PASSWORD,
        ),
        EasyVaultEncryptError, None, True
    ),
    (
        "Decrypted vault file but no password provided",
        dict(
            filepath=TEST_VAULT_DECRYPTED,
            password=None,
        ),
        EasyVaultEncryptError, None, True
    ),
    (
        "Non-existing vault file",
        dict(
            filepath='invalid',
            password='password',
        ),
        EasyVaultFileError, None, True
    ),
]


@pytest.mark.parametrize(
    "desc, kwargs, exp_exc_types, exp_warn_types, condition",
    TESTCASES_VAULT_ENCRYPT)
@simplified_test_function
def test_vault_encrypt(testcase, filepath, password):
    """
    Test function for EasyVault.encrypt()
    """
    vault = EasyVault(filepath, password)
    with saved_file(filepath):

        # The code to be tested
        vault.encrypt()

        # Ensure that exceptions raised in the remainder of this function
        # are not mistaken as expected exceptions
        assert testcase.exp_exc_types is None, \
            "Expected exception not raised: {}". \
            format(testcase.exp_exc_types)

        # Two encryptions of the same file content with the same password/key
        # result in different encrypted files, so we cannot verify the result
        # byte-wise. Instead, we just test whether the file has been encrypted.
        assert vault.is_encrypted()


TESTCASES_VAULT_DECRYPT = [

    # Testcases for EasyVault.decrypt()

    # Each list item is a testcase tuple with these items:
    # * desc: Short testcase description.
    # * kwargs: Keyword arguments for the test function:
    #   * filepath: Path name of vault file for the test. The file is backed
    #     up before the test and restored afterwards.
    #   * password: Password to be used for the test.
    #   * exp_filepath: Expected decrypted file content.
    # * exp_exc_types: Expected exception type(s), or None.
    # * exp_warn_types: Expected warning type(s), or None.
    # * condition: Boolean condition for testcase to run, or 'pdb' for debugger

    (
        "Encrypted vault file",
        dict(
            filepath=TEST_VAULT_ENCRYPTED,
            password=TEST_VAULT_PASSWORD,
            exp_filepath=TEST_VAULT_DECRYPTED,
        ),
        None, None, True
    ),
    (
        "Decrypted vault file",
        dict(
            filepath=TEST_VAULT_DECRYPTED,
            password=TEST_VAULT_PASSWORD,
            exp_filepath=None,
        ),
        EasyVaultDecryptError, None, True
    ),
    (
        "Encrypted vault file but no password provided",
        dict(
            filepath=TEST_VAULT_ENCRYPTED,
            password=None,
            exp_filepath=None,
        ),
        EasyVaultDecryptError, None, True
    ),
    (
        "Non-existing vault file",
        dict(
            filepath='invalid',
            password='password',
            exp_filepath=None,
        ),
        EasyVaultFileError, None, True
    ),
]


@pytest.mark.parametrize(
    "desc, kwargs, exp_exc_types, exp_warn_types, condition",
    TESTCASES_VAULT_DECRYPT)
@simplified_test_function
def test_vault_decrypt(testcase, filepath, password, exp_filepath):
    """
    Test function for EasyVault.decrypt()
    """
    vault = EasyVault(filepath, password)
    with saved_file(filepath):

        # The code to be tested
        vault.decrypt()

        # Ensure that exceptions raised in the remainder of this function
        # are not mistaken as expected exceptions
        assert testcase.exp_exc_types is None, \
            "Expected exception not raised: {}". \
            format(testcase.exp_exc_types)

        if exp_filepath:
            assert_files_text_equal(filepath, exp_filepath)


TESTCASES_VAULT_GET = [

    # Testcases for EasyVault.get_*()

    # Each list item is a testcase tuple with these items:
    # * desc: Short testcase description.
    # * kwargs: Keyword arguments for the test function:
    #   * filepath: Path name of vault file for the test. The file is backed
    #     up before the test and restored afterwards.
    #   * password: Password to be used for the test.
    #   * exp_filepath: Expected decrypted file content.
    # * exp_exc_types: Expected exception type(s), or None.
    # * exp_warn_types: Expected warning type(s), or None.
    # * condition: Boolean condition for testcase to run, or 'pdb' for debugger

    (
        "Encrypted vault file",
        dict(
            filepath=TEST_VAULT_ENCRYPTED,
            password=TEST_VAULT_PASSWORD,
            exp_filepath=TEST_VAULT_DECRYPTED,
        ),
        None, None, True
    ),
    (
        "Decrypted vault file",
        dict(
            filepath=TEST_VAULT_DECRYPTED,
            password=TEST_VAULT_PASSWORD,
            exp_filepath=TEST_VAULT_DECRYPTED,
        ),
        None, None, True
    ),
    (
        "Encrypted vault file but no password provided",
        dict(
            filepath=TEST_VAULT_ENCRYPTED,
            password=None,
            exp_filepath=None,
        ),
        EasyVaultDecryptError, None, True
    ),
    (
        "Encrypted vault file with incorrect password provided",
        dict(
            filepath=TEST_VAULT_ENCRYPTED,
            password='incorrect',
            exp_filepath=None,
        ),
        EasyVaultDecryptError, None, True
    ),
    (
        "Decrypted vault file but no password provided",
        dict(
            filepath=TEST_VAULT_DECRYPTED,
            password=None,
            exp_filepath=TEST_VAULT_DECRYPTED,
        ),
        None, None, True
    ),
    (
        "Non-existing vault file",
        dict(
            filepath='invalid',
            password='password',
            exp_filepath=None,
        ),
        EasyVaultFileError, None, True
    ),
]


@pytest.mark.parametrize(
    "desc, kwargs, exp_exc_types, exp_warn_types, condition",
    TESTCASES_VAULT_GET)
@simplified_test_function
def test_vault_get_bytes(testcase, filepath, password, exp_filepath):
    """
    Test function for EasyVault.get_bytes()
    """
    vault = EasyVault(filepath, password)
    with saved_file(filepath) as saved_filepath:

        # The code to be tested
        act_bytes = vault.get_bytes()

        # Ensure that exceptions raised in the remainder of this function
        # are not mistaken as expected exceptions
        assert testcase.exp_exc_types is None, \
            "Expected exception not raised: {}". \
            format(testcase.exp_exc_types)

        # Check that this has not modified the original file
        assert_files_bytes_equal(filepath, saved_filepath)

        assert isinstance(act_bytes, six.binary_type)

        act_text = act_bytes.decode('utf-8')
        assert_content_text_equal(act_text, exp_filepath)


@pytest.mark.parametrize(
    "desc, kwargs, exp_exc_types, exp_warn_types, condition",
    TESTCASES_VAULT_GET)
@simplified_test_function
def test_vault_get_text(testcase, filepath, password, exp_filepath):
    """
    Test function for EasyVault.get_text()
    """
    vault = EasyVault(filepath, password)
    with saved_file(filepath) as saved_filepath:

        # The code to be tested
        act_text = vault.get_text()

        # Ensure that exceptions raised in the remainder of this function
        # are not mistaken as expected exceptions
        assert testcase.exp_exc_types is None, \
            "Expected exception not raised: {}". \
            format(testcase.exp_exc_types)

        # Check that this has not modified the original file
        assert_files_bytes_equal(filepath, saved_filepath)

        assert isinstance(act_text, six.string_types)

        assert_content_text_equal(act_text, exp_filepath)


@pytest.mark.parametrize(
    "desc, kwargs, exp_exc_types, exp_warn_types, condition",
    TESTCASES_VAULT_GET)
@simplified_test_function
def test_vault_get_yaml(testcase, filepath, password, exp_filepath):
    # pylint: disable=unused-argument
    """
    Test function for EasyVault.get_yaml()
    """
    vault = EasyVault(filepath, password)
    with saved_file(filepath) as saved_filepath:

        # The code to be tested
        act_yaml = vault.get_yaml()

        # Ensure that exceptions raised in the remainder of this function
        # are not mistaken as expected exceptions
        assert testcase.exp_exc_types is None, \
            "Expected exception not raised: {}". \
            format(testcase.exp_exc_types)

        # Check that this has not modified the original file
        assert_files_bytes_equal(filepath, saved_filepath)

        assert isinstance(act_yaml, (dict, list))
