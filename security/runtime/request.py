"""Bounded HTTP bridge. Socket resolution happens ONLY in the candidate container.

All returned bytes are untrusted; the host oracle separately checks them and DB state.
"""
import base64
import http.client
import json
import socket
import sys


def main():
    raw = sys.stdin.buffer.read(16385)
    if len(raw) > 16384:
        raise ValueError("request too large")
    request = json.loads(raw)
    conn = http.client.HTTPConnection("localhost", timeout=3)
    conn.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    conn.sock.settimeout(3)
    try:
        conn.sock.connect('/tmp/epsilon-http.sock')
        body = json.dumps(request['json']).encode() if request['json'] is not None else None
        headers = {**request['headers'], 'Connection': 'close'}
        if body is not None:
            headers['Content-Type'] = 'application/json'
        conn.request(request['method'], request['path'], body=body, headers=headers)
        response = conn.getresponse()
        if response.getheader('Content-Encoding', 'identity') != 'identity':
            raise ValueError('compressed response refused')
        content = response.read(65537)
        if len(content) > 65536:
            raise ValueError('response too large')
        print(json.dumps({'status': response.status, 'body': base64.b64encode(content).decode('ascii')}))
    finally:
        conn.close()


if __name__ == '__main__':
    try:
        main()
    except Exception:
        # No response, credentials, request or exception text leaves this boundary.
        raise SystemExit(1)
