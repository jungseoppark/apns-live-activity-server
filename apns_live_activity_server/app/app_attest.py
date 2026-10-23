"""Apple App Attest challenge, attestation, and assertion verification."""

import base64
import hashlib
import io
import logging
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi import HTTPException

from .store import TokenStore

logger = logging.getLogger("apns_api.app_attest")
NONCE_EXTENSION_OID = "1.2.840.113635.100.8.2"
APPLE_VALIDATION_CATEGORY = "apple_validation_category_01"
APPLE_BUNDLE_VERSION = "apple_bundle_version_01"
AUTH_DATA_HEADER_LENGTH = 37


def b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def b64_encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _decode_cbor(value: bytes) -> Any:
    try:
        return cbor2.loads(value)
    except (ValueError, cbor2.CBORDecodeError) as exc:
        raise ValueError("invalid CBOR data") from exc


def _decode_one(value: bytes) -> tuple[Any, int]:
    stream = io.BytesIO(value)
    try:
        decoded = cbor2.CBORDecoder(stream).decode()
    except (ValueError, cbor2.CBORDecodeError) as exc:
        raise ValueError("invalid CBOR authenticator data") from exc
    return decoded, stream.tell()


def _authenticator_data(value: bytes, *, attestation: bool) -> dict[str, Any]:
    if len(value) < AUTH_DATA_HEADER_LENGTH:
        raise ValueError("authenticator data is too short")
    rp_id_hash = value[:32]
    flags = value[32]
    counter = int.from_bytes(value[33:37], "big")
    result: dict[str, Any] = {"rp_id_hash": rp_id_hash, "flags": flags, "counter": counter}
    offset = AUTH_DATA_HEADER_LENGTH

    if attestation:
        if not flags & 0x40:
            raise ValueError("attested credential data is missing")
        if len(value) < offset + 18:
            raise ValueError("attested credential data is truncated")
        result["aaguid"] = value[offset:offset + 16]
        credential_length = int.from_bytes(value[offset + 16:offset + 18], "big")
        offset += 18
        if credential_length == 0 or len(value) < offset + credential_length:
            raise ValueError("credential ID is invalid")
        result["credential_id"] = value[offset:offset + credential_length]
        offset += credential_length
        cose_key, consumed = _decode_one(value[offset:])
        if not isinstance(cose_key, dict) or consumed == 0:
            raise ValueError("credential public key is invalid")
        result["cose_key"] = cose_key
        offset += consumed

    if flags & 0x80:
        extensions, consumed = _decode_one(value[offset:])
        if not isinstance(extensions, dict) or consumed == 0 or offset + consumed != len(value):
            raise ValueError("authenticator extensions are invalid")
        result["extensions"] = extensions
    elif offset != len(value):
        raise ValueError("unexpected authenticator data")
    return result


def _check_extensions(
    extensions: dict[str, Any] | None, environment: str
) -> tuple[int | None, str | None]:
    if not extensions:
        return None, None
    category = extensions.get(APPLE_VALIDATION_CATEGORY)
    if isinstance(category, bytes):
        if len(category) != 4:
            raise ValueError("app validation category must be a four-byte UInt32")
        category = int.from_bytes(category, "little")
    bundle_version = extensions.get(APPLE_BUNDLE_VERSION)
    allowed_categories = {3} if environment == "development" else {2, 4, 5}
    if category is not None and (
        not isinstance(category, int) or isinstance(category, bool) or category not in allowed_categories
    ):
        raise ValueError(f"app validation category {category} is not allowed for configured environment {environment}")
    if bundle_version is not None and not isinstance(bundle_version, str):
        raise ValueError("app bundle version extension is invalid")
    return category, bundle_version


def _verify_certificate_signature(certificate: x509.Certificate, issuer: x509.Certificate) -> None:
    if certificate.issuer != issuer.subject:
        raise ValueError("attestation certificate issuer mismatch")
    public_key = issuer.public_key()
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        public_key.verify(certificate.signature, certificate.tbs_certificate_bytes,
                          ec.ECDSA(certificate.signature_hash_algorithm))
    elif isinstance(public_key, rsa.RSAPublicKey):
        public_key.verify(certificate.signature, certificate.tbs_certificate_bytes,
                          padding.PKCS1v15(), certificate.signature_hash_algorithm)
    else:
        raise ValueError("unsupported Apple certificate signing key")


def _verify_certificate_chain(certificates: list[bytes], root: x509.Certificate) -> x509.Certificate:
    if len(certificates) < 2:
        raise ValueError("attestation certificate chain is incomplete")
    chain = [x509.load_der_x509_certificate(cert) for cert in certificates]
    now = datetime.now(timezone.utc)
    for cert in chain:
        if cert.not_valid_before_utc > now or cert.not_valid_after_utc < now:
            raise ValueError("attestation certificate is outside its validity period")
    if chain[0].extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
        raise ValueError("attestation credential certificate cannot be a CA")
    for cert in chain[1:]:
        if not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            raise ValueError("attestation issuer certificate is not a CA")
    if chain[-1].issuer == root.subject:
        _verify_certificate_signature(chain[-1], root)
    elif chain[-1].fingerprint(hashes.SHA256()) != root.fingerprint(hashes.SHA256()):
        raise ValueError("attestation certificate chain does not terminate at Apple root")
    for child, issuer in zip(chain, chain[1:]):
        _verify_certificate_signature(child, issuer)
    return chain[0]


def _der_octet_string(value: bytes) -> bytes:
    """Read Apple's nonce from SEQUENCE -> [1] -> OCTET STRING."""
    if len(value) < 6 or value[0] != 0x30:
        raise ValueError("attestation nonce extension is malformed")
    sequence_length, sequence_offset = _der_length(value, 1)
    if sequence_offset + sequence_length != len(value) or value[sequence_offset] != 0xA1:
        raise ValueError("attestation nonce extension is malformed")
    tagged_length, tagged_offset = _der_length(value, sequence_offset + 1)
    if tagged_offset + tagged_length != len(value) or value[tagged_offset] != 0x04:
        raise ValueError("attestation nonce extension is malformed")
    octet_length, octet_offset = _der_length(value, tagged_offset + 1)
    if octet_offset + octet_length != len(value):
        raise ValueError("attestation nonce extension is malformed")
    return value[octet_offset:]


def _der_length(value: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(value):
        raise ValueError("truncated DER length")
    first = value[offset]
    if first < 0x80:
        return first, offset + 1
    count = first & 0x7F
    if count == 0 or count > 4 or len(value) < offset + 1 + count:
        raise ValueError("invalid DER length")
    length = int.from_bytes(value[offset + 1:offset + 1 + count], "big")
    if length < 0x80:
        raise ValueError("non-minimal DER length")
    return length, offset + 1 + count


def _public_key_from_cose(cose_key: dict[Any, Any]) -> ec.EllipticCurvePublicKey:
    if cose_key.get(1) != 2 or cose_key.get(3) != -7 or cose_key.get(-1) != 1:
        raise ValueError("App Attest credential is not an ES256 P-256 key")
    x, y = cose_key.get(-2), cose_key.get(-3)
    if not isinstance(x, bytes) or not isinstance(y, bytes) or len(x) != 32 or len(y) != 32:
        raise ValueError("App Attest credential public key is malformed")
    return ec.EllipticCurvePublicNumbers(int.from_bytes(x, "big"), int.from_bytes(y, "big"),
                                         ec.SECP256R1()).public_key()


@dataclass(frozen=True)
class VerifiedAttestation:
    public_key: bytes
    app_id: str
    environment: str
    validation_category: int | None
    bundle_version: str | None


class AppAttestVerifier:
    def __init__(self, app_id: str, environment: str, root_certificate_path: str | None = None):
        self.app_id = app_id
        self.environment = environment
        root_path = Path(root_certificate_path) if root_certificate_path else Path(__file__).with_name(
            "Apple_App_Attestation_Root_CA.pem")
        self.root = x509.load_pem_x509_certificate(root_path.read_bytes())

    def verify_attestation(self, key_id: str, attestation: bytes, challenge: bytes) -> VerifiedAttestation:
        try:
            obj = _decode_cbor(attestation)
            if not isinstance(obj, dict) or obj.get("fmt") != "apple-appattest":
                raise ValueError("unsupported attestation format")
            statement = obj.get("attStmt")
            auth_data = obj.get("authData")
            if not isinstance(statement, dict) or not isinstance(auth_data, bytes):
                raise ValueError("attestation object is malformed")
            chain = statement.get("x5c")
            if not isinstance(chain, list) or not all(isinstance(cert, bytes) for cert in chain):
                raise ValueError("attestation certificate chain is missing")
            certificate = _verify_certificate_chain(chain, self.root)
            public_key = certificate.public_key()
            if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(public_key.curve,
                                                                                       ec.SECP256R1):
                raise ValueError("attestation credential is not a P-256 key")
            public_bytes = public_key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
            if hashlib.sha256(public_bytes).hexdigest() != key_id.lower():
                raise ValueError("key ID does not match attested public key")

            parsed = _authenticator_data(auth_data, attestation=True)
            expected_rp_id_hash = hashlib.sha256(self.app_id.encode("utf-8")).digest()
            if parsed["rp_id_hash"] != expected_rp_id_hash:
                raise ValueError("App Attest application identifier mismatch")
            if parsed["counter"] != 0:
                raise ValueError("initial App Attest counter must be zero")
            if parsed["credential_id"] != bytes.fromhex(key_id):
                raise ValueError("credential ID does not match key ID")
            cose_key = _public_key_from_cose(parsed["cose_key"])
            if cose_key.public_numbers() != public_key.public_numbers():
                raise ValueError("credential key mismatch")

            expected_aaguid = b"appattestdevelop" if self.environment == "development" else b"appattest" + b"\0" * 7
            if parsed["aaguid"] != expected_aaguid:
                raise ValueError("App Attest environment mismatch")
            nonce = hashlib.sha256(auth_data + hashlib.sha256(challenge).digest()).digest()
            nonce_extension = certificate.extensions.get_extension_for_oid(
                x509.ObjectIdentifier(NONCE_EXTENSION_OID)).value
            if not isinstance(nonce_extension, x509.UnrecognizedExtension):
                raise ValueError("attestation nonce extension is invalid")
            if _der_octet_string(nonce_extension.value) != nonce:
                raise ValueError("attestation challenge does not match")
            category, bundle_version = _check_extensions(parsed.get("extensions"), self.environment)
            public_der = public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
            return VerifiedAttestation(public_der, self.app_id, self.environment, category, bundle_version)
        except Exception as exc:
            # Log the validation reason without recording attestation, challenge, or key material.
            logger.info(
                "App Attest attestation rejected error_type=%s reason=%s app_id=%s environment=%s",
                type(exc).__name__, str(exc)[:240], self.app_id, self.environment,
            )
            raise HTTPException(status_code=401, detail="App Attest attestation was rejected") from exc

    def verify_assertion(self, key_id: str, assertion: bytes, client_data: bytes,
                         stored_public_key: bytes, previous_counter: int) -> int:
        client_data_hash = hashlib.sha256(client_data).digest()
        auth_data = None
        try:
            obj = _decode_cbor(assertion)
            if not isinstance(obj, dict):
                raise ValueError("assertion object is malformed")
            auth_data, signature = obj.get("authenticatorData"), obj.get("signature")
            if not isinstance(auth_data, bytes) or not isinstance(signature, bytes):
                raise ValueError("assertion fields are missing")
            parsed = _authenticator_data(auth_data, attestation=False)
            if parsed["rp_id_hash"] != hashlib.sha256(self.app_id.encode("utf-8")).digest():
                raise ValueError("App Attest application identifier mismatch")
            if parsed["counter"] <= previous_counter:
                raise ValueError("App Attest assertion counter did not increase")
            _check_extensions(parsed.get("extensions"), self.environment)
            public_key = serialization.load_der_public_key(stored_public_key)
            if not isinstance(public_key, ec.EllipticCurvePublicKey):
                raise ValueError("stored App Attest key is invalid")
            nonce = hashlib.sha256(auth_data + client_data_hash).digest()
            public_key.verify(signature, nonce, ec.ECDSA(hashes.SHA256()))
            return parsed["counter"]
        except Exception as exc:
            if isinstance(exc, InvalidSignature) and auth_data is not None and self.environment == "development":
                logger.info(
                    "App Attest assertion signature mismatch key=%s client_data_hash=%s auth_data_hash=%s",
                    key_id[:12], client_data_hash.hex()[:16], hashlib.sha256(auth_data).hexdigest()[:16],
                )
            logger.info("App Attest assertion rejected error_type=%s", type(exc).__name__)
            raise HTTPException(status_code=401, detail="App Attest assertion was rejected") from exc


class AppAttestService:
    def __init__(self, settings: Any, store: TokenStore):
        self.settings = settings
        self.store = store
        self.verifiers: dict[str, AppAttestVerifier] = {}
        fallback_app_id = getattr(settings, "resolved_app_attest_app_id", "")
        self.primary_bundle_id = getattr(settings, "apns_bundle_id", "") or (
            fallback_app_id.partition(".")[2] if "." in fallback_app_id else ""
        )
        if settings.app_attest_enabled:
            if settings.app_attest_environment not in {"development", "production"}:
                raise RuntimeError("APP_ATTEST_ENVIRONMENT must be development or production")
            bundle_ids = getattr(settings, "bundle_ids", (self.primary_bundle_id,))
            for bundle_id in bundle_ids:
                if hasattr(settings, "app_id_for_bundle"):
                    app_id = settings.app_id_for_bundle(bundle_id)
                elif bundle_id == self.primary_bundle_id and fallback_app_id:
                    app_id = fallback_app_id
                else:
                    app_id = f"{getattr(settings, 'apns_team_id', '')}.{bundle_id}"
                if not app_id or app_id.startswith(".") or app_id.endswith("."):
                    raise RuntimeError("App Attest requires an App ID prefix and Bundle ID")
                self.verifiers[bundle_id] = AppAttestVerifier(
                    app_id,
                    settings.app_attest_environment,
                    getattr(settings, "app_attest_root_certificate_path", "") or None,
                )

    def issue_challenge(
        self, purpose: str, key_id: str | None = None, bundle_id: str | None = None
    ) -> dict[str, str]:
        bundle_id = bundle_id or self.primary_bundle_id
        if bundle_id not in self.verifiers:
            raise HTTPException(status_code=404, detail="App Attest is disabled for this app")
        if purpose not in {"attestation", "assertion"}:
            raise HTTPException(status_code=422, detail="purpose must be attestation or assertion")
        if not key_id or len(key_id) != 64 or any(char not in "0123456789abcdefABCDEF" for char in key_id):
            raise HTTPException(status_code=422, detail="key_id must be a 32-byte hexadecimal key ID")
        key_id = key_id.lower()
        existing_key = self.store.get_attested_key(key_id)
        if purpose == "assertion":
            if not existing_key:
                raise HTTPException(status_code=401, detail="App Attest key is not registered")
            if existing_key["bundle_id"] != bundle_id:
                raise HTTPException(status_code=403, detail="App Attest key belongs to another app")
        elif existing_key:
            raise HTTPException(status_code=409, detail="App Attest key is already registered")

        challenge = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
        challenge_id = b64url_encode(secrets.token_bytes(24))
        self.store.create_attest_challenge(
            challenge_id,
            challenge,
            purpose,
            key_id,
            int(time.time()),
            self.settings.app_attest_challenge_ttl_seconds,
            bundle_id,
        )
        return {
            "challenge_id": challenge_id,
            "challenge": challenge,
            "purpose": purpose,
            "bundle_id": bundle_id,
        }

    def register_key(
        self, key_id: str, challenge_id: str, attestation: bytes,
        bundle_id: str | None = None,
    ) -> dict[str, str]:
        if len(key_id) != 64 or any(char not in "0123456789abcdefABCDEF" for char in key_id):
            raise HTTPException(status_code=422, detail="key_id must be a 32-byte hexadecimal key ID")
        key_id = key_id.lower()
        challenge = self.store.consume_attest_challenge_record(
            challenge_id, "attestation", key_id, int(time.time()), bundle_id
        )
        if challenge is None:
            raise HTTPException(status_code=401, detail="App Attest challenge is invalid or expired")
        bundle_id = challenge["bundle_id"]
        verifier = self.verifiers.get(bundle_id)
        if verifier is None:
            raise HTTPException(status_code=404, detail="App Attest is disabled for this app")
        try:
            challenge_bytes = base64.b64decode(challenge["challenge"], validate=True)
            verified = verifier.verify_attestation(key_id, attestation, challenge_bytes)
        except Exception as exc:
            logger.info("App Attest attestation rejected error_type=%s", type(exc).__name__)
            raise HTTPException(status_code=401, detail="App Attest attestation was rejected") from exc

        installation_id = b64url_encode(secrets.token_bytes(24))
        self.store.register_attested_key(
            key_id,
            installation_id,
            verified.public_key,
            0,
            verified.environment,
            verified.validation_category,
            verified.bundle_version,
            bundle_id,
        )
        logger.info("App Attest key registered environment=%s", verified.environment)
        return {
            "status": "attested",
            "installation_id": installation_id,
            "key_id": key_id,
            "environment": verified.environment,
            "bundle_id": bundle_id,
        }

    def verify_request(
        self, key_id: str, challenge_id: str, assertion: bytes, request_body: bytes
    ) -> tuple[str, str]:
        key = self.store.get_attested_key(key_id.lower())
        if key is None:
            raise HTTPException(status_code=401, detail="App Attest key is not registered")
        bundle_id = str(key["bundle_id"])
        verifier = self.verifiers.get(bundle_id)
        if verifier is None:
            raise HTTPException(status_code=401, detail="App Attest is disabled for this app")
        challenge = self.store.consume_attest_challenge_record(
            challenge_id, "assertion", key_id.lower(), int(time.time()), bundle_id
        )
        if challenge is None:
            raise HTTPException(status_code=401, detail="App Attest challenge is invalid or expired")
        try:
            challenge_bytes = base64.b64decode(challenge["challenge"], validate=True)
            counter = verifier.verify_assertion(
                key_id,
                assertion,
                challenge_bytes + request_body,
                key["public_key"],
                key["sign_count"],
            )
        except Exception as exc:
            logger.info("App Attest assertion rejected error_type=%s", type(exc).__name__)
            raise HTTPException(status_code=401, detail="App Attest assertion was rejected") from exc
        if not self.store.advance_attest_counter(key_id.lower(), key["sign_count"], counter):
            raise HTTPException(status_code=401, detail="App Attest assertion was already used")
        return str(key["installation_id"]), bundle_id
