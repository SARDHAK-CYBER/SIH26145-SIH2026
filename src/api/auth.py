"""POST /auth/login (open, throttled) and GET /auth/me. Mounted by the API and by the live sensor."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from src import accounts

router = APIRouter()


class LoginBody(BaseModel):
    username: str
    password: str
    otp: str | None = None


class PasswordBody(BaseModel):
    current: str
    new: str


class OtpBody(BaseModel):
    otp: str


@router.post("/auth/login")
async def login(body: LoginBody, request: Request):
    client = accounts.client_ip(request.client.host if request.client else "-", request.headers.get("x-forwarded-for", ""))
    res = accounts.login(body.username[:64], body.password[:256], client, (body.otp or "")[:16] or None)
    if res is None:
        raise HTTPException(401, "invalid username, password or one-time code")
    if res.get("otp_required"):
        raise HTTPException(401, "otp required", headers={"X-OTP-Required": "1"})
    if res.get("mfa_enrollment_required"):
        raise HTTPException(403, "this role requires two-factor authentication: ask an administrator to run manage_users.py mfa-setup for you")
    if res.get("locked"):
        raise HTTPException(429, "too many failed logins for this account from this address; try again in a few minutes")
    return res


def _user_or_400(request: Request) -> str:
    st = request.state
    user = getattr(st, "user", None)
    if not user or str(user).startswith("key:"):
        raise HTTPException(400, "this operation is for signed-in users, not API keys")
    return user


@router.post("/auth/password")
async def change_password(body: PasswordBody, request: Request):
    user = _user_or_400(request)
    client = accounts.client_ip(request.client.host if request.client else "-", request.headers.get("x-forwarded-for", ""))
    r = accounts.change_password(user, body.current[:256], body.new[:256], client)
    if r == "ok":
        return {"changed": True, "note": "sign in again: earlier sessions are no longer valid"}
    if r == "locked":
        raise HTTPException(429, "too many failed attempts; try again in a few minutes")
    if r.startswith("weak:"):
        raise HTTPException(422, r[5:])
    if r == "unwritable":
        raise HTTPException(503, "the user store is read-only on this server")
    raise HTTPException(401, "current password is wrong")


@router.post("/auth/mfa/setup")
async def mfa_setup(request: Request):
    res = accounts.mfa_setup(_user_or_400(request))
    if res is None:
        raise HTTPException(404, "unknown user")
    return {**res, "next": "add it to an authenticator app, then POST /auth/mfa/enable with a current code"}


@router.post("/auth/mfa/enable")
async def mfa_enable(body: OtpBody, request: Request):
    if not accounts.mfa_enable(_user_or_400(request), body.otp):
        raise HTTPException(422, "code rejected (or no setup in progress, or the user store is read-only)")
    return {"mfa": "enabled"}


@router.get("/auth/me")
async def me(request: Request):
    st = request.state
    user = getattr(st, "user", None)
    u = accounts.users().get(user) if user and not str(user).startswith("key:") else None
    return {"user": user, "role": getattr(st, "role", None), "tenant": getattr(st, "tenant", None), "mfa": bool(u and u.get("totp_secret"))}
