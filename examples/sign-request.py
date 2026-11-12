"""
Send a request signed for an hmac-guard "generic" route. Python 3.8+, standard library only.
Give this file to partners who call your client's API.

    HMAC_KEY_ID=acme-202611-ab12 HMAC_SECRET=hgs_... python sign-request.py https://hooks.example.com/hooks/partner '{"event":"lead.created"}'

Canonical string (one value per line, no trailing newline):
    v1
    <unix timestamp, seconds>
    <nonce: 32 random hex chars, new for every request>
    <HTTP method, upper case>
    <path + query exactly as sent, e.g. /hooks/partner?x=1>
    <sha256 hex of the raw body bytes>
Signature: hex HMAC-SHA256(secret, canonical), sent as "X-Guard-Signature: v1=<hex>".
"""
import hashlib
import hmac
import os
import secrets
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit


def sign(secret: str, key_id: str, method: str, url: str, body: bytes) -> dict:
    ts = str(int(time.time()))
    nonce = secrets.token_hex(16)
    parts = urlsplit(url)
    path = (parts.path or "/") + (("?" + parts.query) if parts.query else "")
    canonical = "\n".join(["v1", ts, nonce, method.upper(), path, hashlib.sha256(body).hexdigest()])
    signature = hmac.new(secret.encode(), canonical.encode(), hashlib.sha256).hexdigest()
    return {
        "X-Guard-Key-Id": key_id,
        "X-Guard-Timestamp": ts,
        "X-Guard-Nonce": nonce,
        "X-Guard-Signature": "v1=" + signature,
    }


def main() -> int:
    url = sys.argv[1]
    body = (sys.argv[2] if len(sys.argv) > 2 else '{"event":"test"}').encode()
    headers = {"Content-Type": "application/json", **sign(os.environ["HMAC_SECRET"], os.environ["HMAC_KEY_ID"], "POST", url, body)}
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            print(resp.status, resp.read().decode())
            return 0
    except urllib.error.HTTPError as e:
        # 401 = signature/clock problem, 409 = replay (same nonce twice), 429 = rate limited (see Retry-After)
        print(e.code, e.read().decode())
        return 1


if __name__ == "__main__":
    sys.exit(main())
