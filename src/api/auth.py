"""POST /auth/login (open, throttled) and GET /auth/me. Mounted by the API and by the live sensor."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from src import accounts

router = APIRouter()


class LoginBody(BaseModel):
    username: str
    password: str


@router.post("/auth/login")
async def login(body: LoginBody, request: Request):
    client = accounts.client_ip(request.client.host if request.client else "-", request.headers.get("x-forwarded-for", ""))
    res = accounts.login(body.username[:64], body.password[:256], client)
    if res is None:
        raise HTTPException(401, "invalid username or password")
    if res.get("locked"):
        raise HTTPException(429, "too many failed logins for this account from this address; try again in a few minutes")
    return res


@router.get("/auth/me")
async def me(request: Request):
    st = request.state
    return {"user": getattr(st, "user", None), "role": getattr(st, "role", None), "tenant": getattr(st, "tenant", None)}
