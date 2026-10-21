#!/usr/bin/env python3
import socket
import datetime
import subprocess
import select
import sqlite3
from datetime import timezone, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash
from OpenSSL import SSL, crypto
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec

app = Flask(__name__)
app.secret_key = 'super-secret-key-change-this'  # Für Flash-Messages benötigt

DB_FILE = 'database/servers.db'

def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS servers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host TEXT NOT NULL,
            port INTEGER NOT NULL DEFAULT 443,
            email TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(host, port, email)
        )
    ''')
    conn.commit()
    conn.close()

# Datenbank beim Start initialisieren
init_db()

class SSLCheck:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.results = {}
        self.chain_info = []
        self.errno = 0
        self.error_string = ""

    def get_extension_details(self, cert_obj):
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
            error_ptr = SSL._lib.X509_verify_cert_error_string(errno)
            if error_ptr:
                self.error_string = SSL._ffi.string(error_ptr).decode('utf-8')
            else:
                self.error_string = f"Unknown Error ({errno})"
        return True

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

        try:
            san_ext = c_crypt.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            sans = san_ext.value.get_values_for_type(x509.DNSName)
        except: sans = []

        usages = []
        try:
            u_ext = c_crypt.extensions.get_extension_for_class(x509.KeyUsage)
            props = [('digital_signature', 'Digital Signature'), ('key_encipherment', 'Key Encipherment'), ('key_agreement', 'Key Agreement')]
            for attr, name in props:
                if getattr(u_ext.value, attr): usages.append(name)
        except: pass

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

        raw_hex = format(c_crypt.serial_number, 'x').upper()
        if len(raw_hex) % 2 != 0: raw_hex = '0' + raw_hex
        formatted_serial = ":".join(raw_hex[i:i+2] for i in range(0, len(raw_hex), 2))

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

        chain = ssl_con.get_peer_cert_chain()
        if chain:
            for c_os in chain:
                c_c = c_os.to_cryptography()
                c_crl, c_ocsp = self.get_extension_details(c_c)
                self.chain_info.append({
                    "sub": c_c.subject.rfc4514_string(),
                    "iss": c_c.issuer.rfc4514_string(),
                    "notValidAfter": c_c.not_valid_after_utc,
                    "pem": c_c.public_bytes(serialization.Encoding.PEM).decode('utf-8'),
                    "crls": c_crl,
                    "ocsps": c_ocsp
                })

        ssl_con.close()
        sock.close()

    def get_nmap_ciphers(self):
        try:
            cmd = ["/usr/bin/nmap", "-Pn", "--script", "ssl-enum-ciphers", "-p", str(self.port), self.host]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            output = result.stdout
            if "ssl-enum-ciphers:" in output:
                return output.split("ssl-enum-ciphers:")[1].split("|_")[0].strip()
            return "No cipher information found. Is the port open?"
        except subprocess.TimeoutExpired:
            return "Nmap scan timed out."
        except Exception as e:
            return f"Error running nmap: {str(e)}"

def validate_server_host(host, port, email=None, exclude_id=None):
    """Prüft FQDN, DNS, Port-Erreichbarkeit, TLS und Dubletten"""

    # 0. FQDN-Prüfung: Muss mindestens einen Punkt enthalten
    if '.' not in host:
        return False, f"Ungültiger FQDN: '{host}' muss einen Domain-Anteil enthalten (z. B. mit einem Punkt)."

    # 1. Dubletten-Prüfung in der Datenbank
    if email:
        conn = get_db_connection()
        if exclude_id:
            existing = conn.execute(
                'SELECT id FROM servers WHERE host = ? AND port = ? AND email = ? AND id != ?',
                (host, port, email, exclude_id)
            ).fetchone()
        else:
            existing = conn.execute(
                'SELECT id FROM servers WHERE host = ? AND port = ? AND email = ?',
                (host, port, email)
            ).fetchone()
        conn.close()
        if existing:
            return False, f"Der Server {host} mit Port {port} und der E-Mail {email} ist bereits registriert."

    # 2. DNS / FQDN Auflösungsprüfung
    try:
        socket.gethostbyname(host)
    except socket.gaierror:
        return False, f"DNS-Fehler: Der Host '{host}' konnte nicht aufgelöst werden (FQDN ungültig oder nicht vorhanden)."

    # 3. Port-Erreichbarkeit prüfen
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((host, port))
        sock.close()
    except Exception as e:
        return False, f"Verbindungsfehler: Server ist unter {host}:{port} nicht erreichbar (Port geschlossen oder Timeout)."

    # 4. TLS Checken
    try:
        checker = SSLCheck(host, port)
        checker.get_cert()
    except Exception as e:
        return False, f"TLS-Prüfung fehlgeschlagen: Unter {host}:{port} konnte kein gültiger TLS-Handshake durchgeführt werden ({str(e)})."

    return True, ""


def get_page_links(current_page, total_pages):
    """Erzeugt eine saubere Liste von Seitenzahlen und Auslassungen für die Paginierung"""
    if total_pages <= 7:
        return list(range(1, total_pages + 1))

    pages = []
    for p in range(1, total_pages + 1):
        if p == 1 or p == total_pages or (current_page - 2 <= p <= current_page + 2):
            pages.append(p)
        elif pages[-1] != '...':
            pages.append('...')
    return pages


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

@app.route('/servers', methods=['GET', 'POST'])
def servers():
    conn = get_db_connection()
    search_query = request.args.get('search', '').strip()

    # Paginierungs-Parameter
    try:
        page = int(request.args.get('page', 1))
    except ValueError:
        page = 1

    PER_PAGE = 25  # Anzahl der Einträge pro Seite
    offset = (page - 1) * PER_PAGE

    form_host = ''
    form_port = 443
    form_email = ''

    if request.method == 'POST':
        action = request.form.get('action')
        form_host = request.form.get('host', '').strip()
        port_raw = request.form.get('port', '443')
        form_email = request.form.get('email', '').strip()

        try:
            form_port = int(port_raw) if port_raw.isdigit() else 443
        except:
            form_port = 443

        if action == 'add':
            if form_host and form_email:
                is_valid, error_message = validate_server_host(form_host, form_port, form_email)
                if not is_valid:
                    flash(error_message, 'danger')
                else:
                    conn.execute('INSERT INTO servers (host, port, email) VALUES (?, ?, ?)', (form_host, form_port, form_email))
                    conn.commit()
                    flash('Server erfolgreich überprüft und hinzugefügt.', 'success')
            else:
                flash('Bitte alle Pflichtfelder ausfüllen.', 'warning')

        elif action == 'edit':
            server_id = request.form.get('id')
            if server_id and form_host and form_email:
                is_valid, error_message = validate_server_host(form_host, form_port, form_email, exclude_id=server_id)
                if not is_valid:
                    flash(f"Änderung verworfen: {error_message}", 'danger')
                else:
                    conn.execute('UPDATE servers SET host = ?, port = ?, email = ? WHERE id = ?', (form_host, form_port, form_email, server_id))
                    conn.commit()
                    flash('Server-Eintrag aktualisiert und verifiziert.', 'success')
                    conn.close()
                    return redirect(url_for('servers', search=search_query, page=page))

        elif action == 'delete':
            server_id = request.form.get('id')
            if server_id:
                conn.execute('DELETE FROM servers WHERE id = ?', (server_id,))
                conn.commit()
            conn.close()
            return redirect(url_for('servers', search=search_query, page=page))

    # SQL Abfragen mit Filter, Limit und Offset
    if search_query:
        count_query = 'SELECT COUNT(*) FROM servers WHERE host LIKE ? OR email LIKE ? OR CAST(port AS TEXT) LIKE ?'
        param = f'%{search_query}%'
        total_count = conn.execute(count_query, (param, param, param)).fetchone()[0]

        data_query = 'SELECT * FROM servers WHERE host LIKE ? OR email LIKE ? OR CAST(port AS TEXT) LIKE ? ORDER BY host LIMIT ? OFFSET ?'
        server_list = conn.execute(data_query, (param, param, param, PER_PAGE, offset)).fetchall()
    else:
        total_count = conn.execute('SELECT COUNT(*) FROM servers').fetchone()[0]
        data_query = 'SELECT * FROM servers ORDER BY host LIMIT ? OFFSET ?'
        server_list = conn.execute(data_query, (PER_PAGE, offset)).fetchall()


    # Gesamtanzahl Seiten berechnen
    total_pages = max(1, (total_count + PER_PAGE - 1) // PER_PAGE)
    page_links = get_page_links(page, total_pages)
    conn.close()

    return render_template('servers.html',
                           servers=server_list,
                           search=search_query,
                           page=page,
                           total_pages=total_pages,
                           total_count=total_count,
                           page_links = page_links,
                           form_host=form_host,
                           form_port=form_port,
                           form_email=form_email,
                           now=datetime.datetime.now().strftime('%d.%m.%Y %H:%M:%S'))

if __name__ == '__main__':
    app.run(host="0.0.0.0", debug=True, port=5001, ssl_context=('/etc/olbcert/fullchain.pem', '/etc/olbcert/server.key'))
