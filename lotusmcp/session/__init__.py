"""Regime-B interactive code-synthesis sessions (Phase 4).

The LLM authors and iterates a sandboxed exploit script against a persistent
tube; the server enforces only scope, budget, and redaction. Everything is
injected behind narrow interfaces (`Tube`, `ScriptAuthor`, `ScriptRunner`) so the
whole loop runs offline with no Kali, no model, and no network.
"""
from lotusmcp.session.authoring import (
    DeterministicScriptAuthor,
    DeterministicScriptRunner,
    RunOutput,
    Script,
    ScriptAuthor,
    ScriptRunner,
)
from lotusmcp.session.manager import SessionError, SessionManager
from lotusmcp.session.session import InteractiveSession, IterateResult
from lotusmcp.session.tube import ScriptedTube, Tube
from lotusmcp.session.live import HostPythonScriptRunner, TCPTube, host_session_factory

__all__ = [
    "Tube", "ScriptedTube", "TCPTube",
    "Script", "RunOutput", "ScriptAuthor", "ScriptRunner",
    "DeterministicScriptAuthor", "DeterministicScriptRunner", "HostPythonScriptRunner",
    "InteractiveSession", "IterateResult",
    "SessionManager", "SessionError", "host_session_factory",
]
