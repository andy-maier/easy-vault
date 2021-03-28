.. Licensed under the Apache License, Version 2.0 (the "License");
.. you may not use this file except in compliance with the License.
.. You may obtain a copy of the License at
..
..    http://www.apache.org/licenses/LICENSE-2.0
..
.. Unless required by applicable law or agreed to in writing, software
.. distributed under the License is distributed on an "AS IS" BASIS,
.. WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
.. See the License for the specific language governing permissions and
.. limitations under the License.


.. _`Usage`:

Usage
=====


.. _`Supported environments`:

Supported environments
----------------------

The **easy-vault** package is supported in these environments:

* Operating Systems: Linux, Windows (native, and with UNIX-like environments),
  macOS/OS-X

* Python: 2.7, 3.4, and higher


.. _`Installation`:

Installation
------------

The following command installs the **easy-vault** package and its
prerequisite packages into the active Python environment:

.. code-block:: bash

    $ pip install easy-vault


.. _`Managing the vault file`:

Managing the vault file
-----------------------

**TODO: Write this section: encryption, decryption, keyring, password**


.. _`Accessing the secrets in a program`:

Accessing the secrets in a program
----------------------------------

The following Python code demonstrates the use case of a command line utility
that accesses the secrets in the vault:

.. code-block:: python

    import getpass
    from easy_vault import EasyVault, EasyVaultException, KeyRingLib

    vault_file = 'examples/vault.yml'  # Path name of Ansible vault file

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
        vault_obj = vault.get_yaml()
    except EasyVaultException as exc:
        . . . # handle error

    myserver_nick = 'myserver1'        # Nickname of a secret in the vault file

    myserver_secrets = vault_obj['secrets'][myserver_nick]

    session = MySession(               # A fictitious session class
        host=myserver_secrets['host'],
        username=myserver_secrets['username'],
        password=myserver_secrets['password'])

    # Do something in the server session
    . . .
