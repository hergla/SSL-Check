#!/usr/bin/env python3
#
#
# From hergla github
#
# SSL Certificate Check host/port.
#

import socket
import sys
import datetime
from datetime import timedelta, timezone
from argparse import ArgumentParser
import ssl
from OpenSSL import SSL, crypto

from cryptography import x509
#from cryptography.hazmat.backends import default_backend
#from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
import ctypes
from ctypes.util import find_library
import platform

def load_libcrypto():
    system = platform.system()
    libraries = []
    if system == "Darwin":
        # Liste der möglichen versionierten Pfade unter macOS
        # Die unversionierte 'libcrypto.dylib' führt zum Crash!
        # Zeigt alle Bibliotheken an, die das 'ssh' Tool benutzt
        # otool -L /usr/bin/ssh | grep libcrypto
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
            print(f"Erfolgreich geladen: {lib_path}")
            return lib
        except OSError:
            continue
            
    return None

libcrypto = load_libcrypto()
libcrypto.OpenSSL_version.restype = ctypes.c_char_p
print(f"Version Info: {libcrypto.OpenSSL_version(0).decode('utf-8')}")

def get_validation_error_text(errno):
    # Definition der C-Funktions-Signatur
    libcrypto.X509_verify_cert_error_string.restype = ctypes.c_char_p
    libcrypto.X509_verify_cert_error_string.argtypes = [ctypes.c_long]

    error_ptr = libcrypto.X509_verify_cert_error_string(errno)
    if error_ptr:
        return error_ptr.decode('utf-8')
    return f"Unbekannter Fehler ({errno})"

class SSLCheck:
    def __init__(self, host, port):
       self.host = host
       self.port = port
       self.not_valid_after_utc = None
       self.errno = 0
       self.error_string = None


    def verify_callback(self, conn, cert, errno, depth, ok):
        # Wir geben immer True zurueck. Damit werden Cert Fehler ignoriert.
        # Aber wir koennen den Fehler abfangen.
        if not ok:
            error_string = get_validation_error_text(errno)
            #print(errno, error_string)
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
        if self.daysValid > 0  and self.errno == 0:
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
        print(all_ciphers)


    def get_cert(self):
        context = SSL.Context(SSL.TLS_CLIENT_METHOD)
        context.set_default_verify_paths()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((self.host, self.port))
        sock.settimeout(None)

        # Wir wollen verify und den Fehler abfangen.
        # Durch den True return im callback geht es also weiter.
        context.set_verify(SSL.VERIFY_PEER, self.verify_callback)
        ssl_con = SSL.Connection(context=context, socket=sock)
        ssl_con.set_tlsext_host_name(self.host.encode())
        ssl_con.set_connect_state()
        ssl_con.do_handshake()

        chain = ssl_con.get_peer_cert_chain()
        cert = ssl_con.get_peer_certificate()
        tls_version = ssl_con.get_protocol_version_name()

        print(tls_version)
        #print(cert.get_notAfter())
        cert_crypto = cert.to_cryptography()
        self.not_valid_after_utc = cert_crypto.not_valid_after_utc
        print(f"Subject: {cert_crypto.subject.rfc4514_string()}")
        san_extension = cert_crypto.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        dns_names = san_extension.value.get_values_for_type(x509.DNSName)
        print(f"SAN: {dns_names}")
        print(f"Valid until: {cert_crypto.not_valid_after_utc} - notBefore: {cert_crypto.not_valid_before_utc}")
        print(f"Version: {cert_crypto.version} Serial:{cert_crypto.serial_number}")
        print(f"Issuer: {cert_crypto.issuer.rfc4514_string()}")

        print("\nCA Chain:")
        for cert_openssl in chain:
            cert_crypto = cert_openssl.to_cryptography()
            try:   # CA enthaelt Basic Constraint. Ein Cert aber nicht.
                bc = cert_crypto.extensions.get_extension_for_class(x509.BasicConstraints)
            except x509.ExtensionNotFound:
                continue
            # Check if Intermediate
            issuer = cert_crypto.issuer.rfc4514_string()
            subject = cert_crypto.subject.rfc4514_string()
            if issuer == subject:
                print("Root CA:")
            else:
                print("Intermediate CA:")
            pem_ca = cert_crypto.public_bytes(encoding=serialization.Encoding.PEM)
            print(pem_ca.decode('utf-8'))
        ssl_con.close()

def parseargs():
    parser = ArgumentParser(prog="ssl-check.py", description="SSL Certificte Checker.")
    parser.add_argument('-s', '--server', dest="host", type=str,
                        help="Hostname to check (FQDN)",  default='www.google.com')  # required=True)
    parser.add_argument('-p', '-port', dest='port', default=443, help="TCP Port (default=443)")
    args = parser.parse_args()
    return args


if __name__ == "__main__":
    args = parseargs()

    sc = SSLCheck(host=args.host, port=int(args.port))
    #sc.get_ciphers()
    sc.get_cert()
    if sc.isValid:
        print("Certificate okay.")
    else:
        print("Certificate has issue(s):")
        print(f"Issue: {sc.issue}")
    print(f"Days until invalid: {sc.daysValid:.2f}")


    if not sc.isValid:
        sys.exit(1)
    sys.exit(0)
