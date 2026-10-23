import hashlib
from datetime import datetime, timedelta, timezone

import cbor2
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.x509.oid import NameOID, ObjectIdentifier
from fastapi import HTTPException

from app.app_attest import AppAttestVerifier


def _der_sequence_octet_string(value: bytes) -> bytes:
    return bytes((0x30, len(value) + 4, 0xA1, len(value) + 2, 0x04, len(value))) + value


def _certificate(subject_name, issuer_name, public_key, issuer_key, *, is_ca: bool,
                 extra_extension=None):
    now = datetime.now(timezone.utc)
    builder = (x509.CertificateBuilder().subject_name(subject_name).issuer_name(issuer_name)
               .public_key(public_key).serial_number(x509.random_serial_number())
               .not_valid_before(now - timedelta(minutes=1))
               .not_valid_after(now + timedelta(days=30))
               .add_extension(x509.BasicConstraints(ca=is_ca, path_length=1 if is_ca else None), critical=True))
    if extra_extension:
        builder = builder.add_extension(extra_extension, critical=False)
    return builder.sign(issuer_key, hashes.SHA256())


def _name(common_name: str):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _test_attestation(tmp_path, challenge: bytes):
    app_id = "ABCDE12345.com.example.live"
    root_key = ec.generate_private_key(ec.SECP256R1())
    root_name = _name("Test App Attest Root")
    root = _certificate(root_name, root_name, root_key.public_key(), root_key, is_ca=True)
    intermediate_key = ec.generate_private_key(ec.SECP256R1())
    intermediate_name = _name("Test App Attest Intermediate")
    intermediate = _certificate(intermediate_name, root.subject, intermediate_key.public_key(), root_key,
                                is_ca=True)
    attested_key = ec.generate_private_key(ec.SECP256R1())
    public_bytes = attested_key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    key_id = hashlib.sha256(public_bytes).hexdigest()
    cose_key = {1: 2, 3: -7, -1: 1, -2: attested_key.public_key().public_numbers().x.to_bytes(32, "big"),
                -3: attested_key.public_key().public_numbers().y.to_bytes(32, "big")}
    credential_id = bytes.fromhex(key_id)
    authenticator_data = (hashlib.sha256(app_id.encode()).digest() + b"\x40" + b"\x00\x00\x00\x00"
                          + b"appattestdevelop" + len(credential_id).to_bytes(2, "big")
                          + credential_id + cbor2.dumps(cose_key))
    nonce = hashlib.sha256(authenticator_data + hashlib.sha256(challenge).digest()).digest()
    nonce_extension = x509.UnrecognizedExtension(ObjectIdentifier("1.2.840.113635.100.8.2"),
                                                 _der_sequence_octet_string(nonce))
    leaf = _certificate(_name("Test App Attest Key"), intermediate.subject, attested_key.public_key(),
                        intermediate_key, is_ca=False, extra_extension=nonce_extension)
    root_path = tmp_path / "root.pem"
    root_path.write_bytes(root.public_bytes(serialization.Encoding.PEM))
    statement = {"fmt": "apple-appattest", "authData": authenticator_data,
                 "attStmt": {"x5c": [leaf.public_bytes(serialization.Encoding.DER),
                                     intermediate.public_bytes(serialization.Encoding.DER)]}}
    verifier = AppAttestVerifier(app_id, "development", str(root_path))
    return verifier, key_id, cbor2.dumps(statement), attested_key, authenticator_data


def test_attestation_certificate_nonce_app_id_and_key_are_verified(tmp_path):
    challenge = b"one-time-challenge"
    verifier, key_id, attestation, _, _ = _test_attestation(tmp_path, challenge)

    result = verifier.verify_attestation(key_id, attestation, challenge)

    assert result.app_id == "ABCDE12345.com.example.live"
    assert result.environment == "development"
    assert result.validation_category is None
    assert result.bundle_version is None


def test_assertion_signature_and_counter_are_verified(tmp_path):
    verifier, key_id, _, key, _ = _test_attestation(tmp_path, b"attestation-challenge")
    request_data = b"assertion-challenge" + b'{"token_type":"activity"}'
    assertion_auth_data = (hashlib.sha256(verifier.app_id.encode()).digest() + b"\x00"
                           + (1).to_bytes(4, "big"))
    client_data_hash = hashlib.sha256(request_data).digest()
    nonce = hashlib.sha256(assertion_auth_data + client_data_hash).digest()
    signature = key.sign(nonce, ec.ECDSA(Prehashed(hashes.SHA256())))
    assertion = cbor2.dumps({"authenticatorData": assertion_auth_data, "signature": signature})
    public_key = key.public_key().public_bytes(serialization.Encoding.DER,
                                               serialization.PublicFormat.SubjectPublicKeyInfo)

    assert verifier.verify_assertion(key_id, assertion, request_data, public_key, 0) == 1
    with pytest.raises(HTTPException):
        verifier.verify_assertion(key_id, assertion, request_data, public_key, 1)
