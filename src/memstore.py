"""
In-process stand-in for the Redis commands the stateful detection engines
use (ENG-01 flood / spoofed-source, ENG-02 beaconing, ENG-06 accumulated
exfiltration, ENG-13 brute force).

Why it exists: those four engines FAIL OPEN when Redis is unreachable --
i.e. they silently detect nothing. The Docker stack has a real Redis, but
a desktop install (Windows .exe, or a Linux host with no Redis) did not,
so live DDoS / C2-beacon / brute-force / exfil detection was inert there.
This store implements exactly the commands they call (RedisBloom CMS,
HyperLogLog, counters, lists, hashes, SET NX EX) with real TTL expiry so a
long-running live capture doesn't grow without bound.

Exact counting instead of approximate (CMS/HLL only ever over-estimate),
so it is marginally conservative for the flood check. Thread-safe.
"""
from __future__ import annotations

import threading
import time


class _Pipe:
    def __init__(self, store: "MemoryStore"):
        self._s, self._ops = store, []

    def __getattr__(self, name):
        def rec(*a, **k):
            self._ops.append((name, a, k))
            return self
        return rec

    def execute(self):
        out = [getattr(self._s, n)(*a, **k) for n, a, k in self._ops]
        self._ops = []
        return out


class MemoryStore:
    _SWEEP_EVERY = 20_000   # operations between expiry sweeps

    def __init__(self):
        self._lock = threading.RLock()
        self._kv, self._hll, self._lists, self._hashes, self._cms = {}, {}, {}, {}, {}
        self._exp: dict[str, float] = {}
        self._ops_since_sweep = 0

    # ---- expiry ----
    def _alive(self, key: str) -> bool:
        t = self._exp.get(key)
        if t is not None and t <= time.time():
            self._drop(key)
            return False
        return True

    def _drop(self, key: str) -> None:
        for d in (self._kv, self._hll, self._lists, self._hashes, self._cms, self._exp):
            d.pop(key, None)

    def _tick(self) -> None:
        self._ops_since_sweep += 1
        if self._ops_since_sweep >= self._SWEEP_EVERY:
            self._ops_since_sweep = 0
            now = time.time()
            for k in [k for k, t in self._exp.items() if t <= now]:
                self._drop(k)

    def expire(self, key, seconds, *a, **k):
        with self._lock:
            self._exp[key] = time.time() + float(seconds)
            return True

    # ---- connection ----
    def ping(self):
        return True

    def pipeline(self):
        return _Pipe(self)

    # ---- RedisBloom count-min sketch ----
    def execute_command(self, cmd, *args):
        cmd = str(cmd).upper()
        with self._lock:
            self._tick()
            if cmd == "CMS.INITBYDIM":
                if self._alive(args[0]):
                    if args[0] in self._cms:
                        raise RuntimeError("CMS: key already exists")
                self._cms.setdefault(args[0], {})
                return b"OK"
            if cmd == "CMS.INCRBY":
                if not self._alive(args[0]):
                    self._cms[args[0]] = {}
                d = self._cms.setdefault(args[0], {})
                d[args[1]] = d.get(args[1], 0) + int(args[2])
                return [d[args[1]]]
            if cmd == "CMS.QUERY":
                if not self._alive(args[0]):
                    return [0 for _ in args[1:]]
                return [self._cms.get(args[0], {}).get(i, 0) for i in args[1:]]
        raise NotImplementedError(cmd)

    # ---- HyperLogLog ----
    def pfadd(self, key, *vals):
        with self._lock:
            self._tick()
            self._alive(key)
            s = self._hll.setdefault(key, set())
            n = len(s)
            s.update(vals)
            return int(len(s) > n)

    def pfcount(self, key):
        with self._lock:
            return len(self._hll.get(key, ())) if self._alive(key) else 0

    # ---- strings / counters ----
    def incr(self, key, n=1):
        with self._lock:
            self._tick()
            self._alive(key)
            self._kv[key] = int(self._kv.get(key, 0)) + n
            return self._kv[key]

    def get(self, key):
        with self._lock:
            if not self._alive(key):
                return None
            v = self._kv.get(key)
            return None if v is None else str(v).encode()

    def set(self, key, val, nx=False, ex=None, **_):
        with self._lock:
            self._tick()
            self._alive(key)
            if nx and key in self._kv:
                return None
            self._kv[key] = val
            if ex is not None:
                self._exp[key] = time.time() + float(ex)
            return True

    # ---- lists ----
    def rpush(self, key, *vals):
        with self._lock:
            self._tick()
            self._alive(key)
            lst = self._lists.setdefault(key, [])
            lst.extend(vals)
            return len(lst)

    @staticmethod
    def _slice(lst, start, end):
        n = len(lst)
        s = start + n if start < 0 else start
        e = end + n if end < 0 else end
        return max(s, 0), e + 1

    def ltrim(self, key, start, end):
        with self._lock:
            lst = self._lists.get(key, []) if self._alive(key) else []
            s, e = self._slice(lst, start, end)
            self._lists[key] = lst[s:e]
            return True

    def lrange(self, key, start, end):
        with self._lock:
            lst = self._lists.get(key, []) if self._alive(key) else []
            s, e = self._slice(lst, start, end)
            return lst[s:e]

    # ---- hashes ----
    def hincrby(self, key, field, n=1):
        with self._lock:
            self._tick()
            self._alive(key)
            h = self._hashes.setdefault(key, {})
            h[field] = h.get(field, 0) + n
            return h[field]
