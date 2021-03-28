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
Utility Functions.
"""

from __future__ import print_function, absolute_import

import six

__all__ = []


def ensure_bytes(obj):
    """
    If the input object is a string, make sure it is returned as a Byte string,
    as follows:

    * If the input object already is a Byte string, it is returned unchanged.
    * If the input object is a Unicode string, it is converted to a Byte string
      using the UTF-8 encoding.
    * Otherwise, the input object was not a string and is returned unchanged.
    """
    if isinstance(obj, six.text_type):
        return obj.encode("utf-8")
    return obj


def ensure_unicode(obj):
    """
    If the input object is a string, make sure it is returned as a Unicode
    string, as follows:

    * If the input object already is a Unicode string, it is returned unchanged.
    * If the input object is a Byte string, it is converted to a Unicode string
      using the UTF-8 encoding.
    * Otherwise, the input object was not a string and is returned unchanged.
    """
    if isinstance(obj, six.binary_type):
        return obj.decode("utf-8")
    return obj
