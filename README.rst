easy-vault - Secure vault files that are easy to use
====================================================

.. image:: https://badge.fury.io/py/easy-vault.svg
    :target: https://pypi.python.org/pypi/easy-vault/
    :alt: Version on Pypi

.. image:: https://github.com/andy-maier/easy-vault/workflows/test/badge.svg?branch=master
    :target: https://github.com/andy-maier/easy-vault/actions/
    :alt: Actions status

.. image:: https://readthedocs.org/projects/easy-vault/badge/?version=latest
    :target: https://readthedocs.org/projects/easy-vault/builds/
    :alt: Docs build status (master)

.. image:: https://coveralls.io/repos/github/andy-maier/easy-vault/badge.svg?branch=master
    :target: https://coveralls.io/github/andy-maier/easy-vault?branch=master
    :alt: Test coverage (master)


Overview
--------

The **easy-vault** Python package provides commands for encrypting and
decrypting vault files that can be in any format. It provides for programmatic
access to encrypted vault files from Python programs, so that the file itself
can stay encrypted in the file system but can still be used by the program in
clear text.

At first use on a particular vault file, the encryption command prompts for a
vault password and stores that in the keyring of your local system using the
`keyring package`_. Subsequent encryption and decryption of the vault file will
then use the key from the keyring, avoiding any further password prompts.
Programmatic access can also be done with the password from the keyring.
The use of the keyring can be disabled if that is desired.

The encryption of the vault files is implemented using the 'fernet'
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


.. _`Documentation and change log`:

Documentation and change log
----------------------------

* `Documentation`_
* `Change log`_


License
-------

The **easy-vault** package is provided under the
`Apache Software License 2.0 <https://raw.githubusercontent.com/andy-maier/easy-vault/master/LICENSE>`_.


.. # Links:

.. _`Documentation`: https://easy-vault.readthedocs.io/en/latest/
.. _`Change log`: https://easy-vault.readthedocs.io/en/latest/changes.html
.. _`keyring package`: https://pypi.org/project/keyring/
.. _`cryptography package`: https://pypi.org/project/cryptography/
