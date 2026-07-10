"""OODA engine — candidate model, EV+UCB selection, budget, phase machine,
progress tracking, and the step() loop.

Import submodules directly (e.g. ``from lotusmcp.engine.loop import Loop``).
This package ``__init__`` is intentionally import-free: ``playbooks.model``
depends on ``engine.candidate``, so eager re-exports here would create an
import cycle (engine -> loop -> selector -> playbooks -> engine).
"""
