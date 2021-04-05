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


.. _`Change log`:

Change log
==========


Version 0.7.0
-------------

This version contains all fixes up to version 0.6.1.

Released: 2021-04-05

**Incompatible changes:**

* The KeyRingLib class has been renamed to Keyring, and its KeyRing...
  exception classes to Keyring... (issue #50).

**Bug fixes:**

* Fixed that the package did not contain the files for the 'easy-vault'
  command. (issue #45)

* Added missing exception handling to 'Keyring.set_password()' and improved
  exception chaining in 'Keyring.get_password()' and 'Keyring.delete_password()'.

* Fixed an UnboundLocalError when the temporary file could not be created or
  written during 'EasyVault.encrypt()' / 'decrypt()'.

**Enhancements:**

* Increased development status to beta.

* Added a 'easy-vault delete-password' command that deletes the password for
  a vault file in the keyring service. Added a corresponding
  'Keyring.delete_password()' method. (issues #33 and #35)

* Added a 'easy-vault check-encrypted' command that checks whether the vault
  file is encrypted and exits with 1 if that is ot the case. This can be used
  for example if the vault file is stored in a repository to regularly check
  whether it is encrypted to ensure it has not been committed by mistake in the
  decrypted state. (issue #57)

* Improved error messages when writing vault file during 'EasyVault.encrypt()'
  / 'decrypt()'.

* Test: Improved test coverage of Keyring and EasyVault classes.


Version 0.6.0
-------------

Released: 2021-04-02

**Incompatible changes:**

* The new optional 'use_prompting' parameter of 'easy_vault.get_password()' was
  not added at the end of the parameter list. This is incompatible for users
  who called the function with positional arguments. (related to issue #20)

* The '--prompt' option of the 'easy-vault encrypt' and 'easy-vault decrypt'
  commands was removed. (related to issue #20)

**Bug fixes:**

* Fixed the issue that an open() call used the 'encoding' argument which
  is not supported on Python 2.7.

* Fixed issues with files on Windows that have CRLF line endings.

**Enhancements:**

* In the 'EasyVault' class, added more user control for the handling of
  passwords: The init method now accepts if the password is not provided and in
  that case is restricted to operate on decrypted vault files.
  The 'easy_vault.get_password()' function got an additional 'use_prompting'
  parameter that can be used to disable the interactive prompting for
  passwords. (issue #20)

* In the 'easy-vault encrypt' and 'easy-vault decrypt' commands, removed the
  '--prompt' option and added options '--set-password' and '--no-keyring' to
  better separate the two concerns of setting a new password and disabling the
  use of the keyring service. (issue #20)

* Docs: Improved the documentation and command messages in many places.

* Added a '--quiet' option to the 'easy-vault encrypt' and 'easy-vault decrypt'
  commands that silöences the messages except for the password prompt.
  (issue #12)

* In the 'KeyRingLib' class, added methods 'is_available()' and
  'check_available() that return whether the keyring service is available
  or check that it is available. (issue #34)

* Added a new 'easy-vault check-keyring' command that checks whether the
  keyring service is available. (issue #36)

* Test: Improved test coverage. (issue #8)


Version 0.5.0
-------------

Released: 2021-03-29

Initial release.
