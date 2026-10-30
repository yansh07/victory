"""Compatibility package for the src-layout modules."""

from pathlib import Path

_package_dir = Path(__file__).resolve().parent
__path__ = [str(_package_dir), str(_package_dir.parent)]
