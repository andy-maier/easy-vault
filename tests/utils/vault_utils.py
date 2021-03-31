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
vault_utils - Utilities for vault file testing.
"""

from __future__ import absolute_import

import os
from contextlib import contextmanager
import shutil


@contextmanager
def saved_file(filepath):
    """
    Context manager that saves and restores the input file.
    """
    if os.path.exists(filepath):
        bak_filepath = filepath + '.bak'
        shutil.copy(src=filepath, dst=bak_filepath)
        try:
            yield bak_filepath
        finally:
            shutil.copy(src=bak_filepath, dst=filepath)
            os.remove(bak_filepath)
    else:
        yield None


def assert_files_bytes_equal(act_filepath, exp_filepath):
    """
    Compare two binary files for byte-wise equality of content.
    """
    with open(act_filepath, 'rb') as act_fp:
        act_bytes = act_fp.read()
        with open(exp_filepath, 'rb') as exp_fp:
            exp_bytes = exp_fp.read()
    assert act_bytes == exp_bytes, \
        "Unexpected bytes:\n" \
        "  actual:   {!r}\n" \
        "  expected: {!r}\n". \
        format(act_bytes, exp_bytes)


def assert_files_text_equal(act_filepath, exp_filepath):
    """
    Compare two text files for line-wise equality of content, tolerating
    differences in line endings (LF vs. CRLF).
    """
    with open(act_filepath, 'r') as act_fp:
        act_text = act_fp.read()
        with open(exp_filepath, 'r') as exp_fp:
            exp_text = exp_fp.read()
    assert act_text == exp_text, \
        "Unexpected text:\n" \
        "  actual:   {!r}\n" \
        "  expected: {!r}\n". \
        format(act_text, exp_text)


def assert_content_text_equal(act_text, exp_filepath):
    """
    Compare an actual text file content and the content of an expected text
    file for line-wise equality, tolerating differences in line endings
    (LF vs. CRLF).
    """
    with open(exp_filepath, 'r') as exp_fp:
        exp_text = exp_fp.read()
    act_text = act_text.replace('\r\n', '\n')
    assert act_text == exp_text, \
        "Unexpected text:\n" \
        "  actual:   {!r}\n" \
        "  expected: {!r}\n". \
        format(act_text, exp_text)
