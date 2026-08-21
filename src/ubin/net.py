from __future__ import annotations

import socket


def resolve(host: str, port: int | str | None = None):
    return socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)


def tcp_connect(host: str, port: int, *, timeout: float = 10.0):
    return socket.create_connection((host, port), timeout=timeout)

__all__ = ["resolve", "tcp_connect"]
