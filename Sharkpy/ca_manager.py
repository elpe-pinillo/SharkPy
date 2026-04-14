# -*- coding: utf-8 -*-
"""
SharkPy CA Manager
Generates and manages the root CA used to forge per-host TLS certificates.
CA files live at  ~/.sharkpy/ca/  (ca.key, ca.crt).
Per-host SSL contexts are generated on demand and cached in memory.
"""

import os
import ssl
import shutil
import tempfile
import logging
import datetime
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

logger = logging.getLogger(__name__)

_CA_DIR = Path.home() / '.sharkpy' / 'ca'


class CAManager:

    def __init__(self, ca_dir: Path = _CA_DIR):
        self.ca_dir = ca_dir
        self.ca_dir.mkdir(parents=True, exist_ok=True)
        self.ca_key  = None
        self.ca_cert = None
        self._ssl_ctx_cache: dict = {}   # hostname -> ssl.SSLContext
        self._try_load()

    # ── public properties ─────────────────────────────────────────────────────

    @property
    def is_ready(self) -> bool:
        return self.ca_key is not None and self.ca_cert is not None

    @property
    def ca_cert_path(self) -> Path:
        return self.ca_dir / 'ca.crt'

    @property
    def ca_key_path(self) -> Path:
        return self.ca_dir / 'ca.key'

    # ── CA lifecycle ──────────────────────────────────────────────────────────

    def _try_load(self):
        if self.ca_cert_path.exists() and self.ca_key_path.exists():
            try:
                self._load()
                logger.info("Loaded SharkPy CA from %s", self.ca_dir)
            except Exception as exc:
                logger.warning("Could not load existing CA: %s", exc)

    def _load(self):
        with open(self.ca_key_path, 'rb') as f:
            self.ca_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(self.ca_cert_path, 'rb') as f:
            self.ca_cert = x509.load_pem_x509_certificate(f.read())

    def generate_ca(self):
        """Generate a new root CA and save it. Clears any cached host certs."""
        now = datetime.datetime.now(datetime.timezone.utc)

        self.ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME,              'SharkPy CA'),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME,        'SharkPy'),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, 'Network Testing'),
        ])
        self.ca_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self.ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, key_cert_sign=True, crl_sign=True,
                    content_commitment=False, key_encipherment=False,
                    data_encipherment=False, key_agreement=False,
                    encipher_only=False, decipher_only=False,
                ), critical=True)
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(self.ca_key.public_key()),
                critical=False)
            .sign(self.ca_key, hashes.SHA256())
        )

        # Persist
        with open(self.ca_key_path, 'wb') as f:
            f.write(self.ca_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            ))
        with open(self.ca_cert_path, 'wb') as f:
            f.write(self.ca_cert.public_bytes(serialization.Encoding.PEM))

        self._ssl_ctx_cache.clear()
        logger.info("Generated new SharkPy CA at %s", self.ca_dir)

    def export_ca(self, dest_path: str):
        """Copy the CA cert to dest_path so the user can install it."""
        shutil.copy2(str(self.ca_cert_path), dest_path)

    # ── Per-host certificate / SSL context ────────────────────────────────────

    def get_ssl_context(self, hostname: str) -> ssl.SSLContext:
        """Return a server-side SSLContext bearing a forged cert for hostname.
        Contexts are cached — cert is generated only once per hostname."""
        if not self.is_ready:
            raise RuntimeError("CA not initialised. Call generate_ca() first.")

        key = hostname.lower()
        if key not in self._ssl_ctx_cache:
            self._ssl_ctx_cache[key] = self._build_ctx(hostname)
        return self._ssl_ctx_cache[key]

    def _build_ctx(self, hostname: str) -> ssl.SSLContext:
        now = datetime.datetime.now(datetime.timezone.utc)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        try:
            san = x509.DNSName(hostname)
        except Exception:
            san = x509.DNSName('unknown')

        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, hostname),
            ]))
            .issuer_name(self.ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=397))
            .add_extension(
                x509.SubjectAlternativeName([san]), critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    self.ca_key.public_key()), critical=False)
            .sign(self.ca_key, hashes.SHA256())
        )

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem  = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )

        # ssl.SSLContext.load_cert_chain requires file paths
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pem') as cf:
            cf.write(cert_pem)
            cert_file = cf.name
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pem') as kf:
            kf.write(key_pem)
            key_file = kf.name
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cert_file, key_file)
        finally:
            os.unlink(cert_file)
            os.unlink(key_file)

        return ctx
