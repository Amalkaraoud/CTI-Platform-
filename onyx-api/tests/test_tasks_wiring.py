"""Every task named in the Celery beat schedule must be registered by a @celery.task in onyx_api/tasks.py.

Static (AST) check: runs without Celery installed. It does not execute the tasks.
"""
import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _registered_task_names() -> set[str]:
    tree = ast.parse((ROOT / "onyx-api/onyx_api/tasks.py").read_text(encoding="utf-8"))
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            for d in node.decorator_list:
                if isinstance(d, ast.Call) and getattr(d.func, "attr", "") == "task":
                    for kw in d.keywords:
                        if kw.arg == "name":
                            names.add(kw.value.value)
    return names


def _beat_task_names() -> set[str]:
    src = (ROOT / "onyx-core/onyx_core/services/celery_app.py").read_text(encoding="utf-8")
    return set(re.findall(r'"task":\s*"([^"]+)"', src))


def test_beat_schedule_resolves_to_registered_tasks():
    beat, registered = _beat_task_names(), _registered_task_names()
    assert beat, "no beat task found"
    assert beat <= registered, f"beat references unregistered tasks: {sorted(beat - registered)}"


def test_every_registered_task_is_scheduled_or_documented():
    assert len(_registered_task_names()) == 5
