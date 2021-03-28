#!/usr/bin/env python
"""
Encrypt a vault file.
"""

import sys
import os
import getpass
import keyring
from easy_vault import EasyVault, EasyVaultException, KeyRingLib


def main():
    """Main function"""

    if len(sys.argv) < 2:
        print("Encrypt a vault file.")
        print("Usage: {} vaultfile".format(sys.argv[0]))
        sys.exit(2)

    vault_file = os.path.normpath(sys.argv[1])

    if not os.path.exists(vault_file):
        print("Error: Vault file does not exist: {fn}".
              format(fn=vault_file))
        return 1

    keyringlib = KeyRingLib()
    password = keyringlib.get_password(vault_file)
    if password is None:
        password = getpass.getpass("Enter password for vault file {fn}:".
                                   format(fn=vault_file))
        print("Setting password for vault file {fn} in keyring".
              format(fn=vault_file))
        keyringlib.set_password(vault_file, password)
    else:
        print("Using password for vault file {fn} from keyring".
              format(fn=vault_file))

    vault = EasyVault(vault_file, password)
    try:
        if vault.is_encrypted():
            print("Vault file {fn} was already encrypted".
                  format(fn=vault_file))
            return 0

        vault.encrypt()
    except EasyVaultException as exc:
        print("Error: {}".format(exc))
        return 1

    print("Vault file {fn} has been successfully encrypted".
          format(fn=vault_file))
    return 0


if __name__ == '__main__':
    sys.exit(main())
