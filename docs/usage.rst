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

* Operating Systems: Linux, macOS / OS-X, native Windows, Linux subsystem in
  Windows, UNIX-like environments in Windows.

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

The **easy-vault** package comes with a command named "easy-vault" that is
used to encrypt or decrypt the vault file in place:

.. code-block:: bash

    $ easy-vault encrypt VAULTFILE
    $ easy-vault decrypt VAULTFILE

This command displays self-explanatory help, e.g.:

.. code-block:: bash

    $ easy-vault --help
    $ easy-vault encrypt --help
    $ easy-vault decrypt --help
    $ easy-vault check-keyring --help
    $ easy-vault check-encrypted --help


.. _`Accessing the secrets in a program`:

Accessing the secrets in a program
----------------------------------

The **easy-vault** package provides programmatic access to the vault file,
regardless of whether the vault file is currently encrypted or decrypted.
See the :ref:`API Reference` for details.

The following Python code demonstrates how to access the secrets in a vault file
in YAML format:

.. code-block:: python

    import easy_vault

    vault_file = 'examples/vault.yml'  # Path name of Ansible vault file

    password = easy_vault.get_password(vault_file)
    vault = easy_vault.EasyVault(vault_file, password)
    try:
        vault_obj = vault.get_yaml()
    except easy_vault.EasyVaultException as exc:
        . . . # handle error
    easy_vault.set_password(vault_file, password)

    myserver_nick = 'myserver1'        # Nickname of a secret in the vault file

    myserver_secrets = vault_obj['secrets'][myserver_nick]

    session = MySession(               # A fictitious session class
        host=myserver_secrets['host'],            # 10.11.12.13
        username=myserver_secrets['username'],    # myuser1
        password=myserver_secrets['password'])    # mypass1

    # Do something in the server session
    . . .

Here is the vault file 'examples/vault.yml' that is used in the example
code:

.. code-block:: yaml

    # Example Ansible vault file

    secrets:

      myserver1:
        host: 10.11.12.13
        username: myuser1
        password: mypass1

      myserver2:
        host: 10.11.12.14
        username: myuser2
        password: mypass2

The vault file does not need to be in YAML format; there are access functions
for accessing its raw content as a Byte string and as a Unicode string, too.


.. _`Keyring service`:

Keyring service
----------------

The **easy-vault** package accesses the keyring service of the local system
via the `keyring package`_. That package supports a number of different
keyring services and can be configured to use alternate keyring services.

By default, the following keyring services are active and will be used by
the keyring package:

* On macOS: `Keychain <https://en.wikipedia.org/wiki/Keychain_%28software%29>`_
* On Linux: depends
* On Windows: `Credential Locker <https://docs.microsoft.com/en-us/windows/uwp/security/credential-locker>`_

.. # Links:
.. _`keyring package`: https://github.com/jaraco/keyring/blob/main/README.rst
