"""Host-native Regime-B session backend.

This module deliberately uses this Kali machine directly: no Docker, Podman,
virtualenv, or pwntools dependency. The tube is a stdlib TCP socket, and client
supplied Python scripts run with the host ``python3``.

Scripts receive target metadata through environment variables:

    LOTUS_TARGET_HOST
    LOTUS_TARGET_PORT
    LOTUS_TARGET_ID
    LOTUS_TARGET_DISPLAY

The runner captures stdout + stderr and lets ``InteractiveSession`` handle the
existing redaction, budget, flag-scan, and event-log folds.
"""
from __future__ import annotations

import os
import shutil
import socket
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping, Optional

from lotusmcp.session.authoring import RunOutput, Script
from lotusmcp.session.session import InteractiveSession
from lotusmcp.session.tube import Tube


class TCPTube:
    """Persistent TCP tube to one host:port."""

    def __init__(self, host: str, port: int, timeout: float = 5.0) -> None:
        self.host = host
        self.port = int(port)
        self.timeout = timeout
        self.transcript: list[tuple[str, str]] = []
        self._sock: Optional[socket.socket] = None
        self._closed = False

    def _connect(self) -> socket.socket:
        if self._closed:
            raise ValueError("tube is closed")
        if self._sock is None:
            self._sock = socket.create_connection((self.host, self.port), self.timeout)
            self._sock.settimeout(self.timeout)
        return self._sock

    def send(self, data: str) -> None:
        sock = self._connect()
        payload = data.encode("utf-8", "replace")
        if not payload.endswith(b"\n"):
            payload += b"\n"
        sock.sendall(payload)
        self.transcript.append(("send", data))

    def recv(self, timeout: float = 5.0) -> str:
        sock = self._connect()
        old_timeout = sock.gettimeout()
        sock.settimeout(timeout)
        try:
            try:
                data = sock.recv(65536)
            except socket.timeout:
                data = b""
        finally:
            sock.settimeout(old_timeout)
        out = data.decode("utf-8", "replace")
        self.transcript.append(("recv", out))
        return out

    def close(self) -> None:
        self._closed = True
        if self._sock is not None:
            try:
                self._sock.close()
            finally:
                self._sock = None

    @property
    def closed(self) -> bool:
        return self._closed


def _scrubbed_env(extra: Optional[Mapping[str, str]] = None) -> dict[str, str]:
    env = {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONIOENCODING": "utf-8",
    }
    if extra:
        env.update({str(k): str(v) for k, v in extra.items()})
    return env


@dataclass
class HostPythonScriptRunner:
    """Run client-supplied Python scripts with host ``python3``.

    If ``script.sends`` is populated and ``script.text`` is empty, this falls
    back to expect-style tube driving for compatibility with deterministic
    author tests. Real MCP ``session_edit_run`` calls pass text and execute it.
    """

    timeout: float = 20.0
    max_output: int = 1024 * 1024
    env: Mapping[str, str] = field(default_factory=dict)

    def _target_env(self, script: Script, tube: Tube) -> dict[str, str]:
        host = str(getattr(tube, "host", ""))
        port = str(getattr(tube, "port", ""))
        return {
            "LOTUS_TARGET_HOST": host,
            "LOTUS_TARGET_PORT": port,
            "LOTUS_TARGET_ID": script.target_id,
            "LOTUS_TARGET_DISPLAY": f"{host}:{port}" if host and port else "",
        }

    def _drive_tube(self, script: Script, tube: Tube) -> RunOutput:
        chunks: list[str] = []
        banner = tube.recv()
        if banner:
            chunks.append(banner)
        for s in script.sends:
            tube.send(s)
            reply = tube.recv()
            if reply:
                chunks.append(reply)
        transcript = tuple(getattr(tube, "transcript", ()))
        return RunOutput(rev=script.rev, stdout="\n".join(chunks), ok=True,
                         transcript=transcript)

    def run(self, script: Script, tube: Tube) -> RunOutput:
        if not script.text.strip() and script.sends:
            return self._drive_tube(script, tube)
        py = shutil.which("python3") or shutil.which("python")
        if py is None:
            return RunOutput(script.rev, "python3 not found on host\n", ok=False)

        with tempfile.TemporaryDirectory(prefix="lotus_session_") as d:
            path = Path(d) / f"script.rev{script.rev}.py"
            path.write_text(script.text, encoding="utf-8")
            env = _scrubbed_env({**self._target_env(script, tube), **dict(self.env)})
            try:
                r = subprocess.run(
                    [py, str(path)],
                    shell=False,
                    check=False,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=self.timeout,
                    env=env,
                )
            except subprocess.TimeoutExpired as e:
                out = ((e.stdout or "") + "\n[TIMEOUT]\n" + (e.stderr or ""))
                return RunOutput(script.rev, out[: self.max_output], ok=False)
            stdout = (r.stdout or "")
            stderr = (r.stderr or "")
            combined = stdout if not stderr else stdout + "\n[stderr]\n" + stderr
            return RunOutput(script.rev, combined[: self.max_output],
                             ok=(r.returncode == 0))


def host_session_factory(*, case, sid, entity, goal, flag, budget, scope, phase):
    """Build an ``InteractiveSession`` backed by host TCP + host Python."""
    host = entity.get("addr") or entity.get("host")
    port = entity.get("port")
    if not isinstance(host, str) or not host or port is None:
        raise ValueError("live session target needs host/addr and port")
    from lotusmcp.session.authoring import DeterministicScriptAuthor

    return InteractiveSession(
        case=case,
        sid=sid,
        entity=entity,
        goal=goal,
        tube=TCPTube(host, int(port)),
        author=DeterministicScriptAuthor([[]], goal_note="host session"),
        runner=HostPythonScriptRunner(),
        flag=flag,
        budget=budget,
        scope=scope,
        phase=phase,
    )
