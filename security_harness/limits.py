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

# Security worker rlimits; the report records exactly what the worker applies.
WORKER_RLIMITS = {
    "address_space_bytes": 8 * 1024**3,
    "per_process_data_bytes": 512 * 1024**2,
    "per_process_cpu_seconds": 120,
    "per_file_output_bytes": 64 * 1024**2,
    "file_descriptors": 256,
}


class ResourceLimit(ValueError):
    pass
