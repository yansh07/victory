"""Source-layout package shim for subprocesses started from other directories."""

from pathlib import Path

_repository_root = Path(__file__).resolve().parent.parent
_source_root = _repository_root / "src"
__path__ = [
    str(_source_root / "victory"),
    str(_source_root),
]
