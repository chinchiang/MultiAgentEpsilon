#!/usr/bin/env python3
"""受限離線測試子程序；Bounded offline test worker for trusted generated mutants."""
import resource
import sys

# worker 須能在任何快照中獨立執行，因此上限在此定義。 / The worker must run standalone in any snapshot, so its
# ceilings live here.
RLIMITS = ((resource.RLIMIT_AS, 2 * 1024**3), (resource.RLIMIT_DATA, 1024**3), (resource.RLIMIT_CPU, 25),
           (resource.RLIMIT_FSIZE, 2 * 1024**2), (resource.RLIMIT_NOFILE, 128), (resource.RLIMIT_CORE, 0))
# 網路與任何外部程序啟動途徑。 / Network access and every external process-launch path.
DENIED_EVENTS = frozenset({'socket.connect', 'socket.getaddrinfo', 'socket.sendto', 'socket.bind',
                           'subprocess.Popen', 'os.system', 'os.exec', 'os.posix_spawn', 'os.fork',
                           'os.forkpty', 'os.spawn'})


def main():
    root, xml, *tests = sys.argv[1:]
    sys.path.insert(0, root)
    for limit, value in RLIMITS:
        resource.setrlimit(limit, (value, value))
    # 這是可信測試的離線護欄，不是惡意程式沙箱。 / Offline guard for trusted tests, not a hostile-code sandbox.
    def offline(event, args):
        if event in DENIED_EVENTS:
            raise RuntimeError('offline mutation worker denied external I/O')
    sys.addaudithook(offline)
    import pytest
    return pytest.main(['-q', '-p', 'no:cacheprovider', '--override-ini=addopts=', '--junitxml=' + xml, *tests])


if __name__ == '__main__':
    raise SystemExit(main())
