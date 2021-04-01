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


.. _`API Reference`:

API Reference
=============

This section describes the API of the **easy-vault** package. The API is
kept stable using the compatibility rules defined for
`semantic versioning <https://semver.org/>`_.

Any functions not described in this section are considered internal and may
change incompatibly without warning.


.. _`EasyVault class`:

EasyVault class
---------------

.. autoclass:: easy_vault.EasyVault
    :members:
    :autosummary:
    :autosummary-inherited-members:
    :special-members: __str__


.. _`KeyRingLib class`:

KeyRingLib class
----------------

.. autoclass:: easy_vault.KeyRingLib
    :members:
    :autosummary:
    :autosummary-inherited-members:
    :special-members: __str__


.. _`Password functions`:

Password functions
------------------

.. autofunction:: easy_vault.get_password

.. autofunction:: easy_vault.set_password


.. _`Exception classes`:

Exception classes
-----------------

.. autoclass:: easy_vault.EasyVaultException
    :members:
    :special-members: __str__

.. autoclass:: easy_vault.EasyVaultFileError
    :members:
    :special-members: __str__

.. autoclass:: easy_vault.EasyVaultDecryptError
    :members:
    :special-members: __str__

.. autoclass:: easy_vault.EasyVaultEncryptError
    :members:
    :special-members: __str__

.. autoclass:: easy_vault.EasyVaultYamlError
    :members:
    :special-members: __str__

.. autoclass:: easy_vault.KeyRingException
    :members:
    :special-members: __str__

.. autoclass:: easy_vault.KeyRingNotAvailable
    :members:
    :special-members: __str__

.. autoclass:: easy_vault.KeyRingError
    :members:
    :special-members: __str__


.. _`Package version`:

Package version
---------------

.. autodata:: easy_vault.__version__
