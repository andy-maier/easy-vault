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


easy-vault - Secure vault files that are easy to use
****************************************************

The **easy-vault** Python package provides commands for encrypting and
decrypting vault files that can be in any format. It provides for programmatic
access to encrypted vault files from Python programs, so that the file itself
can stay encrypted in the file system but can still be used by the program in
clear text.

At first use on a particular vault file, the encryption command prompts for a
vault password and stores that in the keyring service of your local system
using the `keyring package`_. Subsequent encryption and decryption of the vault
file will then use the password from the keyring, avoiding any further password
prompts. Programmatic access can also be done with the password from the
keyring.

The encryption of the vault files is implemented using the symmetric key
functionality of the `cryptography package`_.

One use case for this package is for example the daily work with programs that
need the secrets from a vault to access some server or service. For that, the
program in question needs to have integrated with this package.

Another use case is testing in CI/CD systems: The encrypted vault file is
stored in a repository and the password to access it is put as a secret into
the CI/CD system (most CI/CD systems these days support storing secrets in a
secure way). The test program uses the vault password from the CI/CD secret to
get access to the vault to get to the secrets that are needed to perform the
tests. One could have put the vault secrets directly into the CI/CD system, but
if the vault file is also used for local work, or if the number of secrets is
large or has a complex structure, it is better to have the indirection of the
vault file.

The vault files stay encrypted in the file system while they are used, and are
only decrypted and re-encrypted in the file system when secrets need to be
updated/added/removed.

This package allows putting at rest the habit of having clear text files that
contain passwords, API keys and other secrets, and allows transitioning to a
secure but still easy to use approach for managing such secrets.

Why a new vault implementation: The ansible-vault command provided the
functionality we needed and was originally used (except for the keyring storage
which we added). However, Ansible does not support native Windows and that
was a requirement. Also, the ansible-vault command requires installing the
entire Ansible which is quite large. Searching Pypi for suitable vaults
that a) have commands for encrypting and decrypting and b) provide programmatic
access to the encrypted file, did not reveal anything suitable.

.. toctree::
   :maxdepth: 2
   :numbered:

   usage.rst
   api.rst
   development.rst
   appendix.rst
   changes.rst

.. # Links:

.. _`keyring package`: https://github.com/jaraco/keyring/blob/main/README.rst
.. _`cryptography package`: https://cryptography.io/en/stable/
