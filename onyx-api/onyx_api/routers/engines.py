"""
ONYX CTI - Scoring-engine endpoints.

Read-only computation over the decay, confidence and convergence engines. No data is
stored and no external call is made. Inputs are bounded (see services.analysis).
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, HTTPException, Query

from onyx_api.services import analysis

router = APIRouter(prefix="/engines", tags=["Engines"])


def _guard(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except analysis.ValidationError as e:
        raise HTTPException(status_code=422, detail=str(e))


@router.get("/meta", summary="Parameters accepted by the engines")
async def engines_meta() -> dict[str, Any]:
    return analysis.meta()


@router.post("/curve", summary="Decay of one indicator profile over time")
async def engines_curve(payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
    return _guard(analysis.curve, payload)


@router.post("/assess", summary="Freshness and composite confidence, decomposed")
async def engines_assess(payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
    return _guard(analysis.assess, payload)


@router.get("/convergence/matrix", summary="Jaccard matrix across the MITRE actor export")
async def engines_matrix(level: str = Query("technique", pattern="^(technique|parent)$")) -> dict[str, Any]:
    return _guard(lambda: analysis.matrix(analysis.load_actors(), level))


@router.get("/convergence/pair", summary="Compare two actors of the export")
async def engines_pair(a: str, b: str, level: str = Query("technique", pattern="^(technique|parent)$")) -> dict[str, Any]:
    actors = {x["name"]: x for x in analysis.load_actors()}
    if a not in actors or b not in actors:
        raise HTTPException(status_code=404, detail="Unknown actor")
    return _guard(analysis.compare, a, actors[a]["ttps"], b, actors[b]["ttps"], level)
