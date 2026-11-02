"""Trust's decision-token key (03 §C.8 (6)): RS256, published as a JWKS that Connect and Workspace verify
offline. Production takes the PEM from TRUST_SIGNING_KEY or the file TRUST_SIGNING_KEY_FILE (a mounted
secret) and never makes one; elsewhere a key file is made on first use."""

import json
import os
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from quetrust.config import get_settings

DECISION_TOKEN_TYPE = "que-trust-decision+jwt"  # noqa: S105 - a JWS media type, not a secret


@lru_cache
def signing_key() -> rsa.RSAPrivateKey:
    s = get_settings()
    pem = s.signing_key.strip()
    path = Path(s.signing_key_file)
    if not path.is_absolute():
        path = Path(__file__).resolve().parents[1] / path
    if not pem and path.exists():
        pem = path.read_text().strip()
    if not pem:
        if s.production:
            raise RuntimeError("TRUST_SIGNING_KEY or TRUST_SIGNING_KEY_FILE is required in production")
        generated = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        path.parent.mkdir(parents=True, exist_ok=True)
        pem = generated.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ).decode()
        path.write_text(pem)
        os.chmod(path, 0o600)
    key = serialization.load_pem_private_key(pem.encode(), password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise RuntimeError("Trust's signing key must be an RSA private key")
    return key


def jwks() -> dict[str, Any]:
    """GET /.well-known/jwks.json: what relying parties verify decision tokens with."""
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(signing_key().public_key()))
    return {"keys": [{**jwk, "kid": get_settings().signing_kid, "use": "sig", "alg": "RS256"}]}


def decision_token(
    *, audience: str, tenant: str, decision_id: str, action_digest: str, policy_ref: str, expires: datetime
) -> str:
    """Exactly this action, this tenant, until `expires` (the relying owner checks all of it offline)."""
    s = get_settings()
    return jwt.encode(
        {
            "iss": s.issuer,
            "aud": audience,
            "tid": tenant,
            "jti": decision_id,
            "decision": "allow",
            "action_digest": action_digest,
            "policy_ref": policy_ref,
            "exp": int(expires.timestamp()),
        },
        signing_key(),
        algorithm="RS256",
        headers={"kid": s.signing_kid, "typ": DECISION_TOKEN_TYPE},
    )
