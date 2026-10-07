"""Protocol plugins: layers and their filter keys, and loading a library's hook
by name (internal).

This module imports nothing on purpose. ``_keys`` and ``_compare`` read a
registry and are used by the filter; ``_load`` imports modules because a list
names them and ``_config`` reads the list from the environment and the user's
configuration file, so each is imported only by the code that needs it.
"""

from __future__ import annotations
