import base64
import hashlib
import time
from datetime import datetime, timedelta, timezone

from flask import Flask, jsonify, request
import jwt  # PyJWT
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

app = Flask(__name__)

# This class holds all of the keys and information regarding them
class Key:
    def __init__(self, privateKey, publicKey, kid, expiresAt):
        self.privateKey = privateKey
        self.publicKey = publicKey
        self.kid = kid
        self.expiresAt = expiresAt


def generate_rsa_key(ttl_seconds: int) -> Key:
    # Generates a pair of RSA keys
    privateKey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    publicKey = privateKey.public_key()

    # Serialize public key to DER for kid generation
    pub_der = publicKey.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # First 8 bytes of SHA-256(pub_der) and make them base64url-encoded
    # This is simple way of generating a kid (Key ID)
    digest = hashlib.sha256(pub_der).digest()
    kid = base64.urlsafe_b64encode(digest[:8]).decode("ascii").rstrip("=")
    
    #gives a timeframe for keys to expire after to simulate key rotation
    expiresAt = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)

    return Key(privateKey, publicKey, kid, expiresAt)

# This function uses n (modulus) and e (exponent) from the RSA public key converts them 
# into a JWK dictionary to verify JWT signatures
def rsa_public_key_to_jwk(key: Key) -> dict:
    numbers = key.public_key.public_numbers()
    n_int = numbers.n
    e_int = numbers.e

    # Convert to big-endian bytes
    n_bytes = n_int.to_bytes((n_int.bit_length() + 7) // 8, "big")
    e_bytes = e_int.to_bytes((e_int.bit_length() + 7) // 8, "big")

    n_b64 = base64.urlsafe_b64encode(n_bytes).decode("ascii").rstrip("=")
    e_b64 = base64.urlsafe_b64encode(e_bytes).decode("ascii").rstrip("=")

    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": key.kid,
        "n": n_b64,
        "e": e_b64,
    }


# Create one active and one expired key when the program starts
currentKey = generate_rsa_key(ttl_seconds=600)   # 10 minutes until expiration
expiredKey = generate_rsa_key(ttl_seconds=-600) # expired 10 minutes ago

# Creates a list of keys based on if they are active or expired
@app.get("/.well-known/jwks.json")
def jwks():
    now = datetime.now(timezone.utc)
    keys = []

    # Only include unexpired keys
    if currentKey.expiresAt > now:
        keys.append(rsa_public_key_to_jwk(currentKey))

    # Do NOT include the expired key

    return jsonify({"keys": keys})


@app.post("/auth")
def auth():
    use_expired = "expired" in request.args

    now = datetime.now(timezone.utc)

    if use_expired:
        key = expiredKey
        exp = now - timedelta(minutes=5)  # already expired
    else:
        key = currentKey
        exp = now + timedelta(minutes=5)
    #Creates timestamps
    payload = {
        "sub": "1234567890",
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }

    # Serialize private key to PEM for PyJWT to be able to read it
    private_pem = key.private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    token = jwt.encode(
        payload,
        private_pem,
        algorithm="RS256",
        headers={"kid": key.kid},
    )

    return jsonify({"token": token})

# Run the server on port 8080
if __name__ == "__main__":
    # Run on port 8080

    app.run(host="0.0.0.0", port=8080)
