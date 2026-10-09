#!/usr/bin/env python3
"""受限離線測試子程序；Bounded offline test worker for trusted generated mutants."""
import os
from pathlib import Path
import resource
import sys


def main():
    root, xml, *tests = sys.argv[1:]
    sys.path.insert(0, root)
    resource.setrlimit(resource.RLIMIT_AS, (2 * 1024**3, 2 * 1024**3))
    resource.setrlimit(resource.RLIMIT_CPU, (25, 25))
    resource.setrlimit(resource.RLIMIT_FSIZE, (2 * 1024**2, 2 * 1024**2))
    resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    # 這是可信測試的離線護欄，不是惡意程式沙箱。 / Offline guard for trusted tests, not a hostile-code sandbox.
    def offline(event, args):
        if event in ('socket.connect', 'socket.getaddrinfo', 'subprocess.Popen', 'os.system'):
            raise RuntimeError('offline mutation worker denied external I/O')
    sys.addaudithook(offline)
    import pytest
    return pytest.main(['-q', '-p', 'no:cacheprovider', '--override-ini=addopts=', '--junitxml=' + xml, *tests])


if __name__ == '__main__':
    raise SystemExit(main())
