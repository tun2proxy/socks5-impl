#!/usr/bin/env python3
import os
import signal
import socket
import struct
import subprocess
import sys
import time

SOCKS5_VERSION = 0x05
CMD_BIND = 0x02
ATYP_IPV4 = 0x01
REP_SUCCEEDED = 0x00

PROXY_ADDR = ('127.0.0.1', 1081)
TARGET_ADDR = ('127.0.0.1', 0)


def recv_exact(sock, size):
    buf = b''
    while len(buf) < size:
        chunk = sock.recv(size - len(buf))
        if not chunk:
            raise EOFError('connection closed')
        buf += chunk
    return buf


def pack_address(addr):
    host, port = addr
    ip = socket.inet_aton(host)
    return b''.join([struct.pack('!B', ATYP_IPV4), ip, struct.pack('!H', port)])


def unpack_address(data):
    atyp = data[0]
    if atyp != ATYP_IPV4:
        raise ValueError('only ipv4 supported')
    ip = socket.inet_ntoa(data[1:5])
    port = struct.unpack('!H', data[5:7])[0]
    return ip, port


def wait_for_port(addr, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            sock = socket.create_connection(addr, timeout=1.0)
            sock.close()
            return True
        except OSError:
            time.sleep(0.2)
    return False


def start_proxy(repo_root):
    env = os.environ.copy()
    args = [
        'cargo', 'run', '--features', 'server', '--example', 's5-server', '--',
        '--listen-parameters', f'socks5://127.0.0.1:{PROXY_ADDR[1]}'
    ]
    proc = subprocess.Popen(
        args,
        cwd=repo_root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        preexec_fn=os.setsid,
        env=env,
    )
    return proc


def stop_proxy(proc):
    if proc.poll() is None:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            proc.wait()


def main():
    repo_root = os.path.dirname(os.path.abspath(__file__))

    print('Building proxy example...')
    subprocess.run(
        ['cargo', 'build', '--features', 'server', '--example', 's5-server'],
        cwd=repo_root,
        check=True,
    )

    proxy_proc = start_proxy(repo_root)
    try:
        print('Waiting for proxy to listen...')
        if not wait_for_port(PROXY_ADDR, timeout=15.0):
            raise RuntimeError('proxy did not start in time')

        print('Proxy started, beginning BIND handshake')
        proxy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        proxy.settimeout(10)
        proxy.connect(PROXY_ADDR)

        proxy.sendall(struct.pack('!BBB', SOCKS5_VERSION, 1, 0))

        data = recv_exact(proxy, 2)
        ver, method = data
        assert ver == SOCKS5_VERSION and method == 0

        addr = pack_address(TARGET_ADDR)
        proxy.sendall(struct.pack('!BBB', SOCKS5_VERSION, CMD_BIND, 0) + addr)

        data = recv_exact(proxy, 10)
        assert data[0] == SOCKS5_VERSION
        assert data[1] == REP_SUCCEEDED
        bind_ip, bind_port = unpack_address(data[3:10])
        print('Proxy bind address:', bind_ip, bind_port)

        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(10)
        client.connect((bind_ip, bind_port))

        data = recv_exact(proxy, 10)
        assert data[0] == SOCKS5_VERSION
        assert data[1] == REP_SUCCEEDED
        print('Received second reply from proxy')

        hello = b'hello bind'
        client.sendall(hello)

        received = proxy.recv(1024)
        assert received == hello, f'expected {hello!r}, got {received!r}'
        print('Received on proxy stream:', received)

        proxy.close()
        client.close()
        print('BIND smoke test passed')
    finally:
        stop_proxy(proxy_proc)


if __name__ == '__main__':
    main()
