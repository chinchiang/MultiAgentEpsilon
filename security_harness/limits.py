"""Trusted hard ceilings. Requests may reduce these limits, never increase them."""
from dataclasses import dataclass


@dataclass(frozen=True)
class Limits:
    max_files: int = 20000
    max_file_bytes: int = 20 * 1024 * 1024
    max_input_bytes: int = 64 * 1024 * 1024
    max_expanded_bytes: int = 64 * 1024 * 1024
    max_members: int = 2000
    max_archive_depth: int = 3
    max_history_blobs: int = 20000
    max_history_bytes: int = 128 * 1024 * 1024


LIMITS = Limits()


class ResourceLimit(ValueError):
    pass
