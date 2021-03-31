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


Version 0.6.0.dev1
------------------

Released: not yet

**Incompatible changes:**

* The new optional 'use_prompting' parameter of 'easy_vault.get_password()' was
  not added at the end of the parameter list. This is incompatible for users
  who called the function with positional arguments. (related to issue #20)

* The '--prompt' option of the 'easy-vault encrypt' and 'easy-vault decrypt'
  commands was removed. (related to issue #20)

**Deprecations:**

**Bug fixes:**

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

**Cleanup:**

**Known issues:**

* See `list of open issues`_.

.. _`list of open issues`: https://github.com/andy-maier/easy-vault/issues


Version 0.5.0
-------------

Released: 2021-03-29

Initial release.
