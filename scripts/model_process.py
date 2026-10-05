#!/usr/bin/env python3
"""Do not execute a child until its owner has durably registered its group."""
import os
import sys

if __name__ == '__main__':
    # stdin contains only the gate; AWS payloads use a sealed inherited descriptor.
    # An owner killed before registration closes this pipe: EOF means no exec.
    if os.read(0, 1) != b'G':
        raise SystemExit(1)
    os.execvpe(sys.argv[1], sys.argv[1:], os.environ)
