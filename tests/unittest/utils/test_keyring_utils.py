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
Test the utils/keyring_utils.py module.
"""

from __future__ import absolute_import, print_function

import keyring
from easy_vault import KeyRingLib

from ...utils.keyring_utils import is_keyring_available


def test_utils_is_keyring_available():
    """
    Test function for utils.is_keyring_available()
    """
    keyringlib = KeyRingLib()
    service = keyringlib.keyring_service()
    username = keyringlib.keyring_username('test/utils_is_keyring_available')
    password = 'mypassword'

    available = is_keyring_available()

    backend = keyring.get_keyring()
    if isinstance(backend, keyring.backends.chainer.ChainerBackend):
        backend = backend.backends

    if available:

        try:
            keyring.set_password(service, username, password)
        except Exception as exc:
            raise AssertionError(
                "keyring.set_password() raised {} exception: {}; "
                "backend(s)={}".format(type(exc), exc, backend))

        try:
            act_password = keyring.get_password(service, username)
        except Exception as exc:
            raise AssertionError(
                "keyring.get_password() raised {} exception: {}; "
                "backend(s)={}".format(type(exc), exc, backend))

        assert act_password == password

        try:
            keyring.delete_password(service, username)
        except Exception as exc:
            raise AssertionError(
                "keyring.delete_password() raised {} exception: {}; "
                "backend(s)={}".format(type(exc), exc, backend))
