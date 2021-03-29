#!/usr/bin/env python
#
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
Example script that accesses a vault file that may be encrypted or decrypted.
"""

import sys
import os
from pprint import pprint
import easy_vault


def main():
    """Main function"""

    if len(sys.argv) < 2:
        print("Show content of a vault file.")
        print("Usage: {} vaultfile".format(sys.argv[0]))
        sys.exit(2)

    vault_file = os.path.normpath(sys.argv[1])

    if not os.path.exists(vault_file):
        print("Error: Vault file does not exist: {fn}".
              format(fn=vault_file))
        return 1

    password = easy_vault.get_password(vault_file)
    vault = easy_vault.EasyVault(vault_file, password)
    try:
        encrypted = "encrypted" if vault.is_encrypted() else "unencrypted"
        print("Vault file {fn} is {e}".format(fn=vault_file, e=encrypted))
        vault_obj = vault.get_yaml()
    except easy_vault.EasyVaultException as exc:
        print("Error: {}".format(exc))
        return 1
    easy_vault.set_password(vault_file, password)

    print("Content of YAML vault file {fn}:".format(fn=vault_file))
    pprint(vault_obj)
    return 0


if __name__ == '__main__':
    sys.exit(main())
