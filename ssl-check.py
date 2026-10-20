#!/usr/bin/env python3
#
# From hergla github
#
# SSL Certificate Check host/port.
#
# V0.2

import socket
import sys
import datetime
from datetime import timedelta, timezone
from argparse import ArgumentParser
import ssl
from OpenSSL import SSL, crypto

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
import ctypes
from ctypes.util import find_library
import platform

def load_libcrypto():
    system = platform.system()
    libraries = []
    if system == "Darwin":
        libraries = [
            "/usr/lib/libcrypto.3.dylib",
            "/usr/lib/libcrypto.46.dylib",
            "/usr/lib/libcrypto.44.dylib",
            "/usr/lib/libcrypto.42.dylib",
            "/usr/lib/libcrypto.0.9.8.dylib"
        ]
    if system == "Linux":
        path = find_library("crypto")
        libraries = [path]

    for lib_path in libraries:
        try:
            lib = ctypes.CDLL(lib_path)
            # Optional: Globale Prints können bei Bedarf auch reduziert werden
            return lib
        except OSError:
            continue

    return None

libcrypto = load_libcrypto()
if libcrypto:
    libcrypto.OpenSSL_version.restype = ctypes.c_char_p

def get_validation_error_text(errno):
    libcrypto.X509_verify_cert_error_string.restype = ctypes.c_char_p
    libcrypto.X509_verify_cert_error_string.argtypes = [ctypes.c_long]

    error_ptr = libcrypto.X509_verify_cert_error_string(errno)
    if error_ptr:
        return error_ptr.decode('utf-8')
    return f"Unbekannter Fehler ({errno})"

class SSLCheck:
    def __init__(self, host, port, verbose=False):
        self.host = host
        self.port = port
        self.verbose = verbose
        self.not_valid_after_utc = None
        self.errno = 0
        self.error_string = None

    def _log(self, *args, **kwargs):
        """Gibt Text nur aus, wenn verbose auf True steht."""
        if self.verbose:
            print(*args, **kwargs)

    def verify_callback(self, conn, cert, errno, depth, ok):
        if not ok:
            error_string = get_validation_error_text(errno)
            self.errno = errno
            self.error_string = error_string
        return True

    @property
    def daysValid(self):
        now_utc = datetime.datetime.now(tz=timezone.utc)
        diff = self.not_valid_after_utc - now_utc
        remain_days = diff / timedelta(days=1)
        return remain_days

    @property
    def isValid(self):
        if self.daysValid > 0 and self.errno == 0:
            return True
        return False

    @property
    def issue(self):
        if self.errno == 0:
            return "No issues found"
        else:
            return self.error_string

    def get_ciphers(self):
        context = ssl.create_default_context()
        all_ciphers = context.get_ciphers()
        self._log(all_ciphers)

    def get_cert(self):
        context = SSL.Context(SSL.TLS_CLIENT_METHOD)
        context.set_default_verify_paths()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        try:
            sock.connect((self.host, self.port))
        except Exception as e:
            self.verbose = True
            self.errno = 200
            self.error_string = e
            self._log(f"socket connect issue: {e}")
            return False
        sock.settimeout(None)

        context.set_verify(SSL.VERIFY_PEER, self.verify_callback)
        ssl_con = SSL.Connection(context=context, socket=sock)
        ssl_con.set_tlsext_host_name(self.host.encode())
        ssl_con.set_connect_state()
        ssl_con.do_handshake()

        chain = ssl_con.get_peer_cert_chain()
        cert = ssl_con.get_peer_certificate()
        tls_version = ssl_con.get_protocol_version_name()

        self._log(tls_version)
        cert_crypto = cert.to_cryptography()
        self.not_valid_after_utc = cert_crypto.not_valid_after_utc

        self._log(f"Subject: {cert_crypto.subject.rfc4514_string()}")
        san_extension = cert_crypto.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        dns_names = san_extension.value.get_values_for_type(x509.DNSName)
        self._log(f"SAN: {dns_names}")
        self._log(f"Valid until: {cert_crypto.not_valid_after_utc} - notBefore: {cert_crypto.not_valid_before_utc}")
        self._log(f"Version: {cert_crypto.version} Serial:{cert_crypto.serial_number}")
        self._log(f"Issuer: {cert_crypto.issuer.rfc4514_string()}")

        pub_key = cert_crypto.public_key()
        key_size = f"{pub_key.key_size}" if hasattr(pub_key, 'key_size') else 'N/A'
        self._log(f"Keysize: {key_size}")

        if isinstance(pub_key, rsa.RSAPublicKey):
            key_type = f"RSA {key_size} bit"
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            key_type = f"ECDSA {pub_key.curve.name} ({pub_key.key_size} bit)"
        else:
            key_type = f"Other Key ({pub_key.key_size} bit)"

        self._log(f"Key Type: {key_type}")

        sig_alg = cert_crypto.signature_algorithm_oid._name if cert_crypto.signature_hash_algorithm else "N/A"
        self._log(f"Signature Algorithm: {sig_alg}")

        self._log("\nCA Chain:")
        for cert_openssl in chain:
            cert_crypto = cert_openssl.to_cryptography()
            try:
                bc = cert_crypto.extensions.get_extension_for_class(x509.BasicConstraints)
            except x509.ExtensionNotFound:
                continue

            issuer = cert_crypto.issuer.rfc4514_string()
            subject = cert_crypto.subject.rfc4514_string()
            if issuer == subject:
                self._log("Root CA:")
            else:
                self._log("Intermediate CA:")
            self._log(f"Not valid after: {cert_crypto.not_valid_after_utc}")
            pem_ca = cert_crypto.public_bytes(encoding=serialization.Encoding.PEM)
            self._log(pem_ca.decode('utf-8'))

        ssl_con.close()
        return True

def parseargs():
    parser = ArgumentParser(prog="ssl-check.py", description="SSL Certificate Checker.")
    parser.add_argument('-s', '--server', dest="host", type=str,
                        help="Hostname to check (FQDN)", default='www.google.com')
    parser.add_argument('-p', '--port', dest='port', default=443, help="TCP Port (default=443)")
    parser.add_argument('-c', '--checkdays', dest='checkdays', default=0, type=int, help="Check for days until invalid (default=0)")
    parser.add_argument('-v', '--verbose', action='store_true', help="Verbose-Mode")
    args = parser.parse_args()
    return args


if __name__ == "__main__":
    args = parseargs()

    sc = SSLCheck(host=args.host, port=int(args.port), verbose=args.verbose)

    if not sc.get_cert():
        sys.exit(1)

    if args.checkdays > 0:
        print("Checkdays. ", end="")
        if sc.daysValid < args.checkdays:
            print(f"Expires in {int(sc.daysValid)} days.")
            sys.exit(1)
        else:
            print(f"Okay for {int(sc.daysValid)} days.")
        sys.exit(0)

    if sc.isValid:
        print("Certificate okay. ", end="")
    elif sc.daysValid < 0:
        print(f"Certificate expired. ", end="")
    else:
        print("Certificate has issue(s):")
        print(f"Issue: {sc.issue}")
        sys.exit(2)
    print(f"Days until invalid: {sc.daysValid:.2f}")

    if not sc.isValid:
        sys.exit(1)
    sys.exit(0)

