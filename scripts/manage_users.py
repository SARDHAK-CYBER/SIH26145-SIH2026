"""
Manage dashboard/API users (stored in config/users.json, passwords as scrypt hashes -- never plaintext).

    python scripts/manage_users.py add alice --role analyst --tenant acme      # prompts for the password
    python scripts/manage_users.py list
    python scripts/manage_users.py passwd alice
    python scripts/manage_users.py remove alice

Roles: viewer (read-only) | analyst (+ upload/analyse) | sensor (alert ingest only) | admin (everything).
The file is re-read automatically; removing a user or changing a role invalidates that user's existing login tokens at once.
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src import accounts  # noqa: E402

PATH = Path(os.environ.get("STEALTHTAP_USERS", "config/users.json"))


def load() -> dict:
    return json.loads(PATH.read_text(encoding="utf-8")) if PATH.exists() else {"users": []}


def save(d: dict) -> None:
    PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(d, indent=1), encoding="utf-8")
    tmp.replace(PATH)


def ask_password(confirm: bool = True) -> str:
    pw = os.environ.get("STEALTHTAP_NEW_PASSWORD") or getpass.getpass("password: ")
    if len(pw) < 12:
        sys.exit("password must be at least 12 characters")
    if confirm and not os.environ.get("STEALTHTAP_NEW_PASSWORD") and getpass.getpass("again: ") != pw:
        sys.exit("passwords differ")
    return pw


def main() -> None:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("add"); a.add_argument("name"); a.add_argument("--role", choices=accounts.ROLES, required=True); a.add_argument("--tenant", default="default")
    sub.add_parser("list")
    p = sub.add_parser("passwd"); p.add_argument("name")
    r = sub.add_parser("remove"); r.add_argument("name")
    args = ap.parse_args()
    d = load()
    users = {u["name"]: u for u in d["users"]}
    if args.cmd == "add":
        if args.name in users:
            sys.exit(f"{args.name} exists (use passwd to change the password)")
        users[args.name] = {"name": args.name, "role": args.role, "tenant": args.tenant, "password_hash": accounts.hash_password(ask_password())}
    elif args.cmd == "passwd":
        if args.name not in users:
            sys.exit("no such user")
        users[args.name]["password_hash"] = accounts.hash_password(ask_password())
    elif args.cmd == "remove":
        if users.pop(args.name, None) is None:
            sys.exit("no such user")
    else:
        for u in users.values():
            print(f"{u['name']:<20} role={u['role']:<8} tenant={u.get('tenant', 'default')}")
        return
    d["users"] = list(users.values())
    save(d)
    print(f"ok ({PATH})")


if __name__ == "__main__":
    main()
