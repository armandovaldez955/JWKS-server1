import pytest
import jwt
from main import app, keystore, utcnow, DEFAULT_TOKEN_LIFETIME
from flask import json
from datetime import timedelta, timezone

@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client

def test_index(client):
    resp = client.get("/")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "JWKS server" in data["message"]

def test_jwks_only_unexpired(client):
    resp = client.get("/.well-known/jwks.json")
    assert resp.status_code == 200
    data = resp.get_json()
    # All returned keys must be unexpired
    for jwk in data["keys"]:
        ke = keystore.get_key_by_kid(jwk["kid"])
        assert ke is not None
        assert not ke.is_expired()

def test_auth_requires_json(client):
    resp = client.post("/auth", data="not json", content_type="text/plain")
    assert resp.status_code == 400
    assert "error" in resp.get_json()

def test_auth_missing_credentials(client):
    resp = client.post("/auth", json={})
    assert resp.status_code == 400
    assert "username and password required" in resp.get_json()["error"]

def test_auth_valid_token(client):
    resp = client.post("/auth", json={"username": "alice", "password": "pw"})
    assert resp.status_code == 200
    data = resp.get_json()
    token = data["token"]
    kid = data["kid"]

    # The kid should exist in keystore and not be expired
    ke = keystore.get_key_by_kid(kid)
    assert ke is not None
    assert not ke.is_expired()

    # Decode the token with the matching public key
    pub_key = ke.private_key.public_key().public_bytes(
        encoding="PEM",
        format="SubjectPublicKeyInfo"
    )
    decoded = jwt.decode(token, pub_key, algorithms=["RS256"])
    assert decoded["sub"] == "alice"
    assert "exp" in decoded

def test_auth_expired_token(client):
    resp = client.post("/auth?expired=1", json={"username": "bob", "password": "pw"})
    # may be 200 if expired keys exist, else 404
    assert resp.status_code in (200, 404)
    if resp.status_code == 200:
        data = resp.get_json()
        token = data["token"]
        kid = data["kid"]
        ke = keystore.get_key_by_kid(kid)
        assert ke.is_expired()
        decoded = jwt.get_unverified_claims(token)
        assert decoded["exp"] <= int(utcnow().timestamp())

def test_jwks_invalid_method(client):
    resp = client.post("/.well-known/jwks.json")
    # Method not allowed
    assert resp.status_code == 405