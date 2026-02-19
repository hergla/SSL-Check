#!/usr/bin/env python3
import socket
import datetime
import subprocess
import select
from datetime import timezone, timedelta
from flask import Flask, render_template, request
from OpenSSL import SSL, crypto
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec

app = Flask(__name__)

class SSLCheck:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.results = {}
        self.chain_info = []
        self.errno = 0
        self.error_string = ""

    def get_extension_details(self, cert_obj):
        """Extrahiert CRL und OCSP Links aus den Zertifikat-Erweiterungen"""
        crls = []
        ocsps = []
        try:
            crl_ext = cert_obj.extensions.get_extension_for_class(x509.CRLDistributionPoints)
            for point in crl_ext.value:
                for full_name in point.full_name:
                    crls.append(full_name.value)
        except: pass
        
        try:
            aia = cert_obj.extensions.get_extension_for_class(x509.AuthorityInformationAccess)
            for desc in aia.value:
                if desc.access_method == x509.AuthorityInformationAccessOID.OCSP:
                    ocsps.append(desc.access_location.value)
        except: pass
        return crls, ocsps

    def verify_callback(self, conn, cert, errno, depth, ok):
        if not ok:
            self.errno = errno
            # Wir nutzen das FFI (Foreign Function Interface) von OpenSSL
            # um die C-Funktion direkt anzusprechen
            error_ptr = SSL._lib.X509_verify_cert_error_string(errno)
            if error_ptr:
                self.error_string = SSL._ffi.string(error_ptr).decode('utf-8')
            else:
                self.error_string = f"Unknown Error ({errno})"
        return True   # Immer True. Auch wenn wir dem Cert nicht trauen.

    def get_cert(self):
        context = SSL.Context(SSL.TLS_CLIENT_METHOD)
        context.set_default_verify_paths()
        context.set_verify(SSL.VERIFY_PEER, self.verify_callback)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        try:
            sock.connect((self.host, self.port))
            ssl_con = SSL.Connection(context=context, socket=sock)
            ssl_con.set_tlsext_host_name(self.host.encode())
            ssl_con.set_connect_state()

            while True:
                try:
                    ssl_con.do_handshake()
                    break
                except (SSL.WantReadError, SSL.WantWriteError):
                    select.select([sock], [sock], [], 1)
        except Exception as e:
            raise Exception(f"Verbindungsfehler: {str(e)}")

        cert = ssl_con.get_peer_certificate()
        c_crypt = cert.to_cryptography()

        now = datetime.datetime.now(tz=timezone.utc)
        days = (c_crypt.not_valid_after_utc - now) / timedelta(days=1)

        # SANs extrahieren
        try:
            san_ext = c_crypt.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            sans = san_ext.value.get_values_for_type(x509.DNSName)
        except: sans = []

        # Key Usage
        usages = []
        try:
            u_ext = c_crypt.extensions.get_extension_for_class(x509.KeyUsage)
            props = [('digital_signature', 'Digital Signature'), ('key_encipherment', 'Key Encipherment'), ('key_agreement', 'Key Agreement')]
            for attr, name in props:
                if getattr(u_ext.value, attr): usages.append(name)
        except: pass

        # Dynamische Key-Erkennung & OpenSSL Style Namen
        pub_key = c_crypt.public_key()
        if isinstance(pub_key, rsa.RSAPublicKey):
            pk_algo, k_info = "rsaEncryption", f"RSA {pub_key.key_size} bit"
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            pk_algo = "id-ecPublicKey"
            c_name = pub_key.curve.name
            if c_name == "secp256r1": c_name = "P-256 / prime256v1"
            k_info = f"ECDSA {c_name} ({pub_key.key_size} bit)"
        else:
            pk_algo, k_info = "unknown", "Unbekannt"

        # Seriennummer formatieren (AA:BB:CC...)
        raw_hex = format(c_crypt.serial_number, 'x').upper()
        if len(raw_hex) % 2 != 0: raw_hex = '0' + raw_hex
        formatted_serial = ":".join(raw_hex[i:i+2] for i in range(0, len(raw_hex), 2))

        # Sperrinformationen (End-Entity)
        crl_list, ocsp_list = self.get_extension_details(c_crypt)

        self.results = {
            "tls": ssl_con.get_protocol_version_name(),
            "subject": c_crypt.subject.rfc4514_string(),
            "issuer": c_crypt.issuer.rfc4514_string(),
            "until": c_crypt.not_valid_after_utc.strftime('%d.%m.%Y %H:%M:%S'),
            "days": round(days, 1),
            "valid": days > 0 and self.errno == 0,
            "errno": self.errno,
            "error_msg": self.error_string,
            "serial": formatted_serial,
            "sans": sans,
            "pk_algo": pk_algo,
            "key_info": k_info,
            "sig_alg": c_crypt.signature_algorithm_oid._name,
            "usage": usages,
            "crls": crl_list,
            "ocsps": ocsp_list,
            "version": c_crypt.version.name
        }

        # Kette verarbeiten
        chain = ssl_con.get_peer_cert_chain()
        if chain:
            for c_os in chain:
                c_c = c_os.to_cryptography()
                c_crl, c_ocsp = self.get_extension_details(c_c)
                self.chain_info.append({
                    "sub": c_c.subject.rfc4514_string(),
                    "iss": c_c.issuer.rfc4514_string(),
                    "pem": c_c.public_bytes(serialization.Encoding.PEM).decode('utf-8'),
                    "crls": c_crl,
                    "ocsps": c_ocsp
                })

        ssl_con.close()
        sock.close()

    def get_nmap_ciphers(self):
        """Führt nmap ssl-enum-ciphers aus und gibt das Ergebnis zurück"""
        try:
            # -p gibt den Port an, --script das NSE Script
            
            cmd = ["/usr/bin/nmap", "-Pn", "--script", "ssl-enum-ciphers", "-p", str(self.port), self.host]
            print(cmd)
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            # Wir suchen nur den relevanten Teil der Ausgabe (ab 'ssl-enum-ciphers:')
            output = result.stdout
            if "ssl-enum-ciphers:" in output:
                return output.split("ssl-enum-ciphers:")[1].split("|_")[0].strip()
            return "No cipher information found. Is the port open?"
        except subprocess.TimeoutExpired:
            return "Nmap scan timed out."
        except Exception as e:
            return f"Error running nmap: {str(e)}"


@app.route('/', methods=['GET', 'POST'])
def index():
    h, d, c, e = None, None, None, None
    p = 443
    nmap_res = None
    if request.method == 'POST':
        h = request.form.get('server_host')
        p_raw = request.form.get('server_port', '443')
        try:
            p = int(p_raw) if p_raw.isdigit() else 443
            sc = SSLCheck(h, p)
            sc.get_cert()
            d, c = sc.results, sc.chain_info

            nmap_res = sc.get_nmap_ciphers()

        except Exception as ex: e = str(ex)
    return render_template('index.html', host=h, port=p, data=d, chain=c, error=e, 
            nmap_data=nmap_res, now=datetime.datetime.now().strftime('%d.%m.%Y %H:%M:%S'))

if __name__ == '__main__':
    # Flask mit SSL starten
    app.run(host="0.0.0.0", debug=True, port=5000, ssl_context=('/etc/olbcert/fullchain.pem', '/etc/olbcert/server.key'))

