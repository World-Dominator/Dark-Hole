"""Darkhole: A secure, decentralized networking framework."""

__version__ = "0.1.0"
__author__ = "Darkhole Team"
__email__ = "team@darkhole.dev"

from .client import Client
from .config import Config, TierConfig

__all__ = ["Client", "Config", "TierConfig"]