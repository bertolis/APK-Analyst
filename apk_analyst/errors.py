"""Shared exception types for the pipeline + agent."""
from __future__ import annotations


class ScanCancelled(Exception):
    """Raised when a scan is cooperatively cancelled (user pressed Stop).

    Both the extraction pipeline and the agent loop check an optional
    ``should_cancel()`` callback at safe checkpoints and raise this to unwind
    cleanly instead of leaving a half-run scan.
    """
