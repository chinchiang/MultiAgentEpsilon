"""Bounded subprocess I/O, also used before third-party dependencies are installed."""
import os
import selectors
import subprocess
import time


def docker_environment():
    return {k: v for k, v in os.environ.items() if k not in
            ('DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_TLS', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH')}


def bounded_output(command, payload, *, timeout=5, limit=131072, env=None):
    """Bound time and stdout even if candidate processes forge the bridge output."""
    if len(payload) > 16384:
        raise ValueError('request exceeds bridge limit')
    deadline = time.monotonic() + timeout
    with subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, env=env) as process:
        try:
            data = bytearray()
            pending = memoryview(payload)
            os.set_blocking(process.stdin.fileno(), False)
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                selector.register(process.stdin, selectors.EVENT_WRITE)
                done = False
                while not done:
                    remaining = deadline - time.monotonic()
                    events = selector.select(max(0, remaining))
                    if remaining <= 0 or not events:
                        raise TimeoutError('container HTTP deadline exceeded')
                    for key, _ in events:
                        if key.fileobj is process.stdin:
                            written = os.write(process.stdin.fileno(), pending[:4096])
                            pending = pending[written:]
                            if not pending:
                                selector.unregister(process.stdin)
                                process.stdin.close()
                        else:
                            part = os.read(process.stdout.fileno(), min(4096, limit + 1 - len(data)))
                            if not part:
                                done = True
                                break
                            data.extend(part)
                            if len(data) > limit:
                                raise ValueError('container HTTP envelope too large')
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('container HTTP deadline exceeded')
            if process.wait(timeout=remaining) != 0:
                raise RuntimeError('container HTTP request failed')
            return bytes(data)
        finally:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)


