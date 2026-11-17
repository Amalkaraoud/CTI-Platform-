"""
ONYX CTI - detection rule generation endpoint (YARA + Sigma).

POST /api/v1/rules/generate   {name, iocs:[{type,value}], techniques:[T1059.001], level}
Analyst role or above. Pure computation: nothing is stored, no external call is made.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from onyx_api.auth.jwt import Role, require_role
from onyx_analyzers import rules as rule_engine

router = APIRouter(prefix="/rules", tags=["Detection rules"])


class IoCIn(BaseModel):
    type: str = Field(max_length=16)
    value: str = Field(max_length=2100)


class RuleRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    iocs: list[IoCIn] = Field(max_length=5000)
    techniques: list[str] = Field(default_factory=list, max_length=200)
    level: str = "high"


@router.post("/generate", summary="Generate Sigma and YARA rules from validated indicators",
             dependencies=[Depends(require_role(Role.ANALYST))])
async def generate(req: RuleRequest) -> dict[str, Any]:
    out = rule_engine.generate_rules(req.name, [i.model_dump() for i in req.iocs], req.techniques, level=req.level)
    if not out["sigma"] and out["yara"] is None:
        raise HTTPException(status_code=422, detail="No valid indicator to build a rule from")
    return out
