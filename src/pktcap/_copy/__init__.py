"""Copying frames into a writer, and a program run for each (internal)."""

from __future__ import annotations

from ._frames import CopyResult, copy_frames
from ._hook import command_hook

__all__ = ["CopyResult", "command_hook", "copy_frames"]
