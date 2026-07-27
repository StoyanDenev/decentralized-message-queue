# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Determ Contributors
"""determ_rp — the Determ relying-party / citizen SDK (Apache-2.0).

Client-side verification for Determ DApps. See `../README.md` for the planned
component map. Currently ships:
  * `d5` — D.5 government random-selection verification (verify a published
    lowest-hash draw from its DAPP_CALL streams; never a false SELECTED).
"""
from . import d5  # noqa: F401

__all__ = ["d5"]
