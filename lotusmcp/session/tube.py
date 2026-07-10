"""The Tube — a persistent, expect-style channel an exploit script drives.

In production a Tube is a PTY or a socket to an in-scope, IP-pinned target
(pwntools `remote()`/`process()` semantics), opened only after the scope choke
authorizes the host:port and kept alive across script revisions so session and
protocol state (a login, a cookie jar, a negotiated key) survives iteration.

The engine only ever sees this narrow Protocol, so the whole Regime-B session
loop is exercisable offline against a `ScriptedTube` — no socket, no Kali, no
network — exactly as the Executor boundary is exercised against a FixtureBackend.
"""
from __future__ import annotations

from typing import Callable, Dict, List, Protocol, Tuple, Union


class Tube(Protocol):
    def send(self, data: str) -> None: ...
    def recv(self, timeout: float = 5.0) -> str: ...
    def close(self) -> None: ...
    @property
    def closed(self) -> bool: ...


Responder = Callable[[str, "ScriptedTube"], str]


class ScriptedTube:
    """A deterministic, offline Tube for tests and demos.

    `responder` maps (last_sent, self) -> the bytes the peer sends back; a plain
    dict {sent_line -> reply} is accepted as a convenience. `greeting` is the
    banner delivered on the first `recv` before anything has been sent. Every
    send/recv is recorded in `transcript` so the session can persist it.
    """

    def __init__(
        self,
        responder: Union[Responder, Dict[str, str], None] = None,
        greeting: str = "",
    ) -> None:
        if isinstance(responder, dict):
            table = dict(responder)
            self._responder: Responder = lambda s, _t: table.get(s.strip(), "")
        else:
            self._responder = responder or (lambda s, _t: "")
        self._greeting = greeting
        self._pending: str = greeting
        self._closed = False
        self.transcript: List[Tuple[str, str]] = []

    def send(self, data: str) -> None:
        if self._closed:
            raise ValueError("send on a closed tube")
        self.transcript.append(("send", data))
        self._pending = self._responder(data, self)

    def recv(self, timeout: float = 5.0) -> str:
        if self._closed:
            raise ValueError("recv on a closed tube")
        out, self._pending = self._pending, ""
        self.transcript.append(("recv", out))
        return out

    def close(self) -> None:
        self._closed = True

    @property
    def closed(self) -> bool:
        return self._closed
