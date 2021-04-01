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
Click options used for multiple scommands.
"""

from __future__ import absolute_import, print_function

import click

help_option = [  # pylint: disable=invalid-name
    click.help_option('-h', '--help', help=u'Show this help message.')]

quiet_option = [  # pylint: disable=invalid-name
    click.option('-q', '--quiet', is_flag=True, default=False,
                 help=u'Print no messages.')]


def add_options(options):
    """
    Decorator that adds multiple Click options.

    The list is reversed because of the way Click processes options

    Parameters:

      options: list of click.option definitions
    """

    def _add_options(func):
        """
        Reverse options list
        """
        for option in reversed(options):
            func = option(func)
        return func

    return _add_options
