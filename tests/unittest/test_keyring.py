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
try:
    from unittest import mock
except ImportError:
    import mock

import pytest
import keyring
from easy_vault import Keyring, KeyringNotAvailable, KeyringError
from easy_vault._keyring import NO_KEYRING_EXCEPTION

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


@pytest.mark.skipif(
    not is_keyring_available(), reason="No keyring service available")
@pytest.mark.parametrize(
    "keyring_exc, exp_exc",
    [
        (NO_KEYRING_EXCEPTION, KeyringNotAvailable),
        (keyring.errors.KeyringError, KeyringError),
    ]
)
# pylint: disable=redefined-outer-name
def test_keyring_get_password_fail(keyring_filepath, keyring_exc, exp_exc):
    """
    Test function for Keyring.get_password() when it raises an exception
    """
    kr = Keyring()
    with mock.patch.object(keyring, 'get_password', side_effect=keyring_exc):
        with pytest.raises(exp_exc):
            # Code to be tested
            kr.get_password(keyring_filepath)


@pytest.mark.skipif(
    not is_keyring_available(), reason="No keyring service available")
@pytest.mark.parametrize(
    "keyring_exc, exp_exc",
    [
        (NO_KEYRING_EXCEPTION, KeyringNotAvailable),
        (keyring.errors.KeyringError, KeyringError),
    ]
)
# pylint: disable=redefined-outer-name
def test_keyring_set_password_fail(keyring_filepath, keyring_exc, exp_exc):
    """
    Test function for Keyring.set_password() when it raises an exception
    """
    kr = Keyring()
    with mock.patch.object(keyring, 'set_password', side_effect=keyring_exc):
        with pytest.raises(exp_exc):
            # Code to be tested
            kr.set_password(keyring_filepath, 'dummy')


@pytest.mark.skipif(
    not is_keyring_available(), reason="No keyring service available")
@pytest.mark.parametrize(
    "keyring_exc, exp_exc",
    [
        (NO_KEYRING_EXCEPTION, KeyringNotAvailable),
        (keyring.errors.KeyringError, KeyringError),
    ]
)
# pylint: disable=redefined-outer-name
def test_keyring_delete_password_fail1(keyring_filepath, keyring_exc, exp_exc):
    """
    Test function for Keyring.delete_password() when it raises an exception
    in keyring.get_password().
    """
    kr = Keyring()
    with mock.patch.object(keyring, 'get_password', side_effect=keyring_exc):
        with pytest.raises(exp_exc):
            # Code to be tested
            kr.delete_password(keyring_filepath)


@pytest.mark.skipif(
    not is_keyring_available(), reason="No keyring service available")
@pytest.mark.parametrize(
    "keyring_exc, exp_exc",
    [
        (NO_KEYRING_EXCEPTION, KeyringNotAvailable),
        (keyring.errors.KeyringError, KeyringError),
    ]
)
# pylint: disable=redefined-outer-name
def test_keyring_delete_password_fail2(keyring_filepath, keyring_exc, exp_exc):
    """
    Test function for Keyring.delete_password() when it raises an exception
    in keyring.delete_password().
    """
    kr = Keyring()
    kr.set_password(keyring_filepath, 'dummy')
    with mock.patch.object(keyring, 'delete_password', side_effect=keyring_exc):
        with pytest.raises(exp_exc):
            # Code to be tested
            kr.delete_password(keyring_filepath)


@pytest.mark.skipif(
    not is_keyring_available(), reason="No keyring service available")
@pytest.mark.parametrize(
    "keyring_exc, exp_result",
    [
        (NO_KEYRING_EXCEPTION, False),
        (keyring.errors.KeyringError, KeyringError),
    ]
)
def test_keyring_is_available_fail1(keyring_exc, exp_result):
    """
    Test function for Keyring.is_available() when it raises an exception
    in keyring.set_password().
    """
    kr = Keyring()
    with mock.patch.object(keyring, 'set_password', side_effect=keyring_exc):
        if isinstance(exp_result, type) and issubclass(exp_result, Exception):
            with pytest.raises(exp_result):
                # Code to be tested
                kr.is_available()
        else:
            # Code to be tested
            available = kr.is_available()
            assert available == exp_result


@pytest.mark.skipif(
    not is_keyring_available(), reason="No keyring service available")
@pytest.mark.parametrize(
    "keyring_exc",
    [
        (NO_KEYRING_EXCEPTION),
        (keyring.errors.KeyringError),
    ]
)
def test_keyring_is_available_fail2(keyring_exc):
    """
    Test function for Keyring.is_available() when it raises an exception
    in keyring.delete_password().
    """
    kr = Keyring()
    with mock.patch.object(
            keyring, 'delete_password', side_effect=keyring_exc):
        # Code to be tested
        available = kr.is_available()
        assert available is False


@pytest.mark.skipif(
    not is_keyring_available(), reason="No keyring service available")
def test_keyring_is_available_fail3():
    """
    Test function for Keyring.is_available() when the backend is the Chainer
    backend with an empty list of backends.
    """
    kr = Keyring()
    backend_class = keyring.backends.chainer.ChainerBackend
    with mock.patch.object(
            keyring, 'get_keyring', return_value=backend_class()):
        with mock.patch.object(
                backend_class, 'backends',
                new_callable=mock.PropertyMock) as backends_mock:
            backends_mock.return_value = []
            # Code to be tested
            available = kr.is_available()
            assert available is False


@pytest.mark.skipif(
    not is_keyring_available(), reason="No keyring service available")
def test_keyring_is_available_fail4():
    """
    Test function for Keyring.is_available() when the backend is the fail
    backend.
    """
    kr = Keyring()
    backend_class = keyring.backends.fail.Keyring
    with mock.patch.object(
            keyring, 'get_keyring', return_value=backend_class()):
        # Code to be tested
        available = kr.is_available()
        assert available is False


@pytest.mark.skipif(
    not is_keyring_available(), reason="No keyring service available")
def test_keyring_is_available_fail5():
    """
    Test function for Keyring.is_available() when the backend is the null
    backend.
    """
    kr = Keyring()
    backend_class = keyring.backends.null.Keyring
    with mock.patch.object(
            keyring, 'get_keyring', return_value=backend_class()):
        # Code to be tested
        available = kr.is_available()
        assert available is False


@pytest.mark.skipif(
    not is_keyring_available(), reason="No keyring service available")
@pytest.mark.parametrize(
    "keyring_exc, exp_exc",
    [
        (NO_KEYRING_EXCEPTION, KeyringNotAvailable),
        (keyring.errors.KeyringError, KeyringError),
    ]
)
def test_keyring_check_available_fail1(keyring_exc, exp_exc):
    """
    Test function for Keyring.check_available() when it raises an exception
    in keyring.set_password().
    """
    kr = Keyring()
    with mock.patch.object(
            keyring, 'set_password', side_effect=keyring_exc):
        with pytest.raises(exp_exc):
            # Code to be tested
            kr.check_available()


@pytest.mark.skipif(
    not is_keyring_available(), reason="No keyring service available")
@pytest.mark.parametrize(
    "keyring_exc",
    [
        (NO_KEYRING_EXCEPTION),
        (keyring.errors.KeyringError),
    ]
)
def test_keyring_check_available_fail2(keyring_exc):
    """
    Test function for Keyring.check_available() when it raises an exception
    in keyring.delete_password().
    """
    kr = Keyring()
    with mock.patch.object(
            keyring, 'delete_password', side_effect=keyring_exc):
        with pytest.raises(KeyringNotAvailable):
            # Code to be tested
            kr.check_available()


@pytest.mark.skipif(
    not is_keyring_available(), reason="No keyring service available")
def test_keyring_check_available_fail3():
    """
    Test function for Keyring.check_available() when the backend is the Chainer
    backend with an empty list of backends.
    """
    kr = Keyring()
    backend_class = keyring.backends.chainer.ChainerBackend
    with mock.patch.object(
            keyring, 'get_keyring', return_value=backend_class()):
        with mock.patch.object(
                backend_class, 'backends',
                new_callable=mock.PropertyMock) as backends_mock:
            backends_mock.return_value = []
            with pytest.raises(KeyringNotAvailable):
                # Code to be tested
                kr.check_available()


@pytest.mark.skipif(
    not is_keyring_available(), reason="No keyring service available")
def test_keyring_check_available_fail4():
    """
    Test function for Keyring.check_available() when the backend is the fail
    backend.
    """
    kr = Keyring()
    backend_class = keyring.backends.fail.Keyring
    with mock.patch.object(
            keyring, 'get_keyring', return_value=backend_class()):
        with pytest.raises(KeyringNotAvailable):
            # Code to be tested
            kr.check_available()


@pytest.mark.skipif(
    not is_keyring_available(), reason="No keyring service available")
def test_keyring_check_available_fail5():
    """
    Test function for Keyring.check_available() when the backend is the null
    backend.
    """
    kr = Keyring()
    backend_class = keyring.backends.null.Keyring
    with mock.patch.object(
            keyring, 'get_keyring', return_value=backend_class()):
        with pytest.raises(KeyringNotAvailable):
            # Code to be tested
            kr.check_available()
