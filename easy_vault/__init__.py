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
easy-vault - Secure vault files that are easy to use
"""

# There are submodules, but users shouldn't need to know about them.
# Importing just this module is enough.

from __future__ import absolute_import, print_function

from ._easy_vault import *  # noqa: F403,F401
from ._keyring import *  # noqa: F403,F401
from ._password import *  # noqa: F403,F401
from . import _version

#: The full version of this package including any development levels, as a
#: :term:`string`.
#:
#: Possible formats for this version string are:
#:
#: * "M.N.P.dev1": Development level 1 of a not yet released version M.N.P
#: * "M.N.P": A released version M.N.P
__version__ = _version.__version__
