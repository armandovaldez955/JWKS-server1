 # Armando Valdez EUID:Adv0087 ID:11524453

from datetime import datetime, timedelta, timezone
import uuid
import json
from typing import Dict, Optional, Tuple, List

from flask import Flask, jsonify, request, abort
import jwt  # PyJWT
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

HOST = "0.0.0.0"
PORT = 8080

# How many keys to generate at startup
NUM_KEYS_INITIAL = 3

# TTLs for keys — a mix of expired and valid keys for demonstration
KEY_TTLS = [
    timedelta(seconds=-3600),   # expired 1 hour ago
    timedelta(minutes=10),     # expires in 10 minutes
    timedelta(hours=24),       # expires in 24 hours
]

# default token lifetime when issuing new (non-expired) tokens
DEFAULT_TOKEN_LIFETIME = timedelta(hours=1)

# Accept any username/password for demonstration purposes
# (In real usage, replace with real auth.)
ACCEPT_ANY_CREDENTIALS = True


def utcnow() -> datetime:
    return datetime.now(timezone.utc)

def b64url_uint(i: int) -> str:

    # Convert to bytes
    b = i.to_bytes((i.bit_length() + 7) // 8 or 1, byteorder='big')
    import base64
    s = base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")
    return s

# Key container and generation
class KeyEntry:
    # Represents an RSA key pair with a kid and expiry timestamp.
    def __init__(self, private_key, kid: str, expires_at: datetime):
        self.private_key = private_key
        self.kid = kid
        self.expires_at = expires_at

    def is_expired(self) -> bool:
        return utcnow() >= self.expires_at

    def public_jwk(self) -> Dict:
        # Return public key as JWK (RSA) dict with fields n, e, kty, alg, use, kid.
        public_numbers = self.private_key.public_key().public_numbers()
        n = public_numbers.n
        e = public_numbers.e
        return {
            "kty": "RSA",
            "kid": self.kid,
            "use": "sig",
            "alg": "RS256",
            "n": b64url_uint(n),
            "e": b64url_uint(e),
        }

# In-memory key store
class KeyStore:
    def __init__(self):
        self._keys: Dict[str, KeyEntry] = {}

    def add_key(self, key_entry: KeyEntry):
        self._keys[key_entry.kid] = key_entry

    def generate_and_add_rsa(self, bits: int = 2048, ttl: timedelta = timedelta(hours=24)) -> KeyEntry:
        #Generate RSA key pair and register it with a unique kid and expiry TTL from now.
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        kid = str(uuid.uuid4())
        expires_at = utcnow() + ttl
        ke = KeyEntry(private_key=private_key, kid=kid, expires_at=expires_at)
        self.add_key(ke)
        return ke

    def get_unexpired_public_jwks(self) -> List[Dict]:
        # Return the JWKS entries for all keys that have not expired.
        jwks = []
        for ke in self._keys.values():
            if not ke.is_expired():
                jwks.append(ke.public_jwk())
        return jwks

    def pick_active_key(self) -> Optional[KeyEntry]:
       # Pick an unexpired key to sign tokens. Preference: the one with the latest expiry.
        candidates = [ke for ke in self._keys.values() if not ke.is_expired()]
        if not candidates:
            return None
        # choose key with latest expiry
        best = max(candidates, key=lambda k: k.expires_at)
        return best

    def pick_expired_key(self) -> Optional[KeyEntry]:
        
        #Pick an expired key to sign with (for the 'expired' query param behavior).
        candidates = [ke for ke in self._keys.values() if ke.is_expired()]
        if not candidates:
            return None
        # choose the expired key with the latest expiry (closest to now)
        best = max(candidates, key=lambda k: k.expires_at)
        return best

    def get_key_by_kid(self, kid: str) -> Optional[KeyEntry]:
        return self._keys.get(kid)

# Initialize keys
keystore = KeyStore()

# Generate keys per KEY_TTLS list, to have a mix of expired/valid keys
for ttl in KEY_TTLS:
    keystore.generate_and_add_rsa(bits=2048, ttl=ttl)

# If there is fewer keys than NUM_KEYS_INITIAL, generate additional valid keys
while len(keystore._keys) < NUM_KEYS_INITIAL:
    keystore.generate_and_add_rsa(bits=2048, ttl=timedelta(hours=24))

# Flask app and endpoints
app = Flask(__name__)

@app.route("/.well-known/jwks.json", methods=["GET"])
def jwks():
    # JWKS endpoint. Returns only non-expired keys in JWKS format.
    jwks = keystore.get_unexpired_public_jwks()
    return jsonify({"keys": jwks})

@app.route("/auth", methods=["POST"])
def auth():
    # Authentication endpoint that returns a signed JWT.

    # Basic payload parsing
    if not request.is_json:
        return jsonify({"error": "expected application/json"}), 400
    payload = request.get_json()

    username = payload.get("username")
    password = payload.get("password")

    # very simple "authentication" (demo mode)
    if not username or not password:
        return jsonify({"error": "username and password required"}), 400

    if not ACCEPT_ANY_CREDENTIALS:
        # placeholder for real auth: verify username/password here
        pass

    expired_flag = request.args.get("expired", None)

    if expired_flag is not None:
        # Issue a token signed by an expired key, with an expired 'exp' claim
        ke = keystore.pick_expired_key()
        if ke is None:
            return jsonify({"error": "no expired keys available to sign with"}), 404

        # set token expiration to the key's expiry (which is in the past)
        token_exp = int(ke.expires_at.timestamp())
        signing_key = ke.private_key
    else:
        # normal issuance: sign with an unexpired key
        ke = keystore.pick_active_key()
        if ke is None:
            return jsonify({"error": "no active (unexpired) signing key available"}), 503
        token_exp = int((utcnow() + DEFAULT_TOKEN_LIFETIME).timestamp())
        signing_key = ke.private_key

    # Build token claims
    claims = {
        "sub": username,
        "iat": int(utcnow().timestamp()),
        "exp": token_exp,
        # additional claims could go here
    }

    # Get private key in PEM for PyJWT
    private_pem = signing_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Sign token with RS256 and include kid in header
    headers = {"kid": ke.kid, "alg": "RS256", "typ": "JWT"}
    token = jwt.encode(claims, private_pem, algorithm="RS256", headers=headers)

    # Return token and metadata
    return jsonify({
        "token": token,
        "kid": ke.kid,
        "token_exp": datetime.fromtimestamp(token_exp, timezone.utc).isoformat()
    })

@app.route("/", methods=["GET"])
def index():
    return jsonify({
        "message": "JWKS server. Endpoints: /.well-known/jwks.json (GET), /auth (POST).",
        "note": "This server issues RS256 JWTs. For demo only — do not use as-is in production."
    })

# To run the server
if __name__ == "__main__":
    print(f"Starting JWKS server on http://{HOST}:{PORT}/")
    app.run(host=HOST, port=PORT)