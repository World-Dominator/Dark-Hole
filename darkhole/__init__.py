"""Darkhole prototype package."""

__all__ = ["crypto", "dht", "sphinx"]
"""Darkhole.
This repository currently focuses on providing cryptographic foundations under
:mod:`darkhole.crypto` and packet layer encoding/decoding under :mod:`darkhole.packet`.
"""
from __future__ import annotations

__all__ = ["crypto", "packet"]

This repository contains cryptographic and packet-format primitives.
"""

__all__ = ["crypto"]
This repository currently focuses on providing cryptographic foundations under
:mod:`darkhole.crypto`.
"""

from __future__ import annotations

__all__ = ["crypto"]
"""Darkhole: A secure, decentralized networking framework."""

__version__ = "0.1.0"
__author__ = "Darkhole Team"
__email__ = "team@darkhole.dev"

from .client import Client
from .config import Config, TierConfig

__all__ = ["Client", "Config", "TierConfig"]
