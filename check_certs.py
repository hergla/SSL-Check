#!/usr/bin/env python3
import sqlite3
import socket
import sys
import os
import time
import platform
import datetime
from datetime import timezone, timedelta
import ssl
from OpenSSL import SSL, crypto
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import argparse

# --- KONFIGURATION ---
DB_FILE = 'database/servers.db'
SMTP_SERVER = 'localhost'  # Ggf. an euren internen Mail-Relay anpassen
SMTP_PORT = 25

# Generischer Standard-Absender für GitHub (ohne interne Domains)
DEFAULT_SENDER_EMAIL = 'ssl-monitor@example.com'

# Entwicklungs-Modus Master-Schalter:
# Steht dies auf True, wird der Debug-Modus automatisch erzwungen (kein E-Mail-Versand).
DEBUG = False
# ------------------------------

class SSLCheck:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.not_valid_after_utc = None
        self.errno = 0
        self.error_string = None

    def verify_callback(self, conn, cert, errno, depth, ok):
        if not ok:
            self.errno = errno
            self.error_string = f"Zertifikatsfehler (Code {errno})"
        return True

    @property
    def daysValid(self):
        if not self.not_valid_after_utc:
            return -999
        now_utc = datetime.datetime.now(tz=timezone.utc)
        diff = self.not_valid_after_utc - now_utc
        return diff / timedelta(days=1)

    def check(self):
        context = SSL.Context(SSL.TLS_CLIENT_METHOD)
        context.set_default_verify_paths()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(4)
        try:
            sock.connect((self.host, self.port))
        except Exception as e:
            self.errno = 500
            self.error_string = f"Verbindungsfehler: {e}"
            return False
        sock.settimeout(None)

        context.set_verify(SSL.VERIFY_PEER, self.verify_callback)
        ssl_con = SSL.Connection(context=context, socket=sock)
        ssl_con.set_tlsext_host_name(self.host.encode())
        ssl_con.set_connect_state()

        try:
            ssl_con.do_handshake()
            cert = ssl_con.get_peer_certificate()
            cert_crypto = cert.to_cryptography()
            self.not_valid_after_utc = cert_crypto.not_valid_after_utc
        except Exception as e:
            self.errno = 501
            self.error_string = f"TLS-Handshake fehlgeschlagen: {e}"
            ssl_con.close()
            sock.close()
            return False

        ssl_con.close()
        sock.close()
        return True

def get_server_mappings():
    """Liest alle Server aus und gruppiert die Empfänger pro (host, port)"""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    rows = conn.execute('SELECT host, port, email FROM servers').fetchall()
    conn.close()

    mapping = {}
    for row in rows:
        key = (row['host'], int(row['port']))
        email = row['email'].strip()
        if key not in mapping:
            mapping[key] = []
        if email and email not in mapping[key]:
            mapping[key].append(email)

    return mapping

def send_summary_email(recipient, issues, warning_days, debug_mode, sender_email):
    """Sendet oder simuliert die zusammenfassende E-Mail an einen Empfänger"""
    if not issues:
        return

    checking_host = platform.node() or socket.gethostname()
    script_name = os.path.basename(sys.argv[0])

    subject = f"SSL-Zertifikats-Warnung: {len(issues)} * Handlungsbedarf"

    body = f"Hallo,\n\n"
    body += f"folgende SSL-Zertifikate erfordern Ihre Aufmerksamkeit (Ablauf in < {warning_days} Tagen oder Fehler).\n"
    body += f"Prüfung durchgeführt durch Script: {script_name} auf Host: {checking_host}\n\n"

    for host, port, reason in issues:
        body += f" - Server: {host}:{port}     Grund: {reason}\n\n"

    body += "Keep it running...."

    if debug_mode:
        print("\n" + "="*60)
        print(f"[DEBUG-MODUS] E-Mail-Simulation von: {sender_email} an Empfänger: {recipient}")
        print(f"Betreff: {subject}")
        print("-"*60)
        print(body)
        print("="*60 + "\n")
        return

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = recipient
    msg['Subject'] = subject
    msg['X-Priority'] = '1'          # 1 = Highest, 3 = Normal, 5 = Lowest
    msg['X-MSMail-Priority'] = 'High'
    msg['Importance'] = 'High'
    msg.attach(MIMEText(body, 'plain'))

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.sendmail(sender_email, [recipient], msg.as_string())
        print(f"[E-Mail gesendet] Von {sender_email} An {recipient} mit {len(issues)} Meldung(en).")
    except Exception as e:
        print(f"[Fehler beim E-Mail-Versand] An {recipient}: {e}")

def parse_args():
    parser = argparse.ArgumentParser(description="Automatisierte SSL-Zertifikatsüberwachung aus SQLite-DB.")
    parser.add_argument('-w', '--warning-days', type=int, default=7,
                        help="Warnschwelle in Tagen vor Ablauf (Standard: 7)")
    parser.add_argument('-e', '--email', type=str, default=None,
                        help="Nur Server prüfen, die dieser E-Mail-Adresse zugeordnet sind")
    parser.add_argument('-f', '--from-email', type=str, default=DEFAULT_SENDER_EMAIL,
                        help=f"Absender-E-Mail-Adresse (Standard: {DEFAULT_SENDER_EMAIL})")
    parser.add_argument('--debug', action='store_true', default=False,
                        help="Aktiviert den Debug-Modus (E-Mails nur auf Konsole ausgeben)")

    args = parser.parse_args()

    if DEBUG:
        args.debug = True

    return args

def main():
    args = parse_args()
    checking_host = platform.node() or socket.gethostname()
    script_name = os.path.basename(sys.argv[0])

    print(f"Starte SSL-Prüfungslauf ({script_name} auf {checking_host})...")
    print(f"Konfiguration -> Schwellenwert: {args.warning_days} Tage | Absender: {args.from_email} | Filter-E-Mail: {args.email or 'Alle'} | DEBUG-Modus: {args.debug}\n")

    server_mapping = get_server_mappings()

    if args.email:
        target_email = args.email.strip().lower()
        server_mapping = {
            k: emails for k, emails in server_mapping.items()
            if any(target_email == e.lower() for e in emails)
        }
        print(f"Gefilterte Server/Port-Kombinationen für '{args.email}': {len(server_mapping)}")
    else:
        print(f"Gefundene eindeutige Server/Port-Kombinationen in DB: {len(server_mapping)}")

    if not server_mapping:
        print("Keine Server für die angegebenen Kriterien gefunden.")
        return

    recipient_issues = {}

    for (host, port), emails in server_mapping.items():
        print(f"Prüfe {host}:{port} ... ", end="", flush=True)
        checker = SSLCheck(host, port)
        success = checker.check()

        issue_reason = None

        if not success:
            issue_reason = checker.error_string
        else:
            days = checker.daysValid
            if days < 0:
                issue_reason = f"Zertifikat bereits seit {abs(int(days))} Tag(en) abgelaufen!"
            elif days <= args.warning_days:
                issue_reason = f"Zertifikat läuft in {int(days)} Tag(en) ab (am {checker.not_valid_after_utc.strftime('%Y-%m-%d')})"

        if issue_reason:
            print(f"PROBLEM: {issue_reason}")
            for email in emails:
                if args.email and email.strip().lower() != args.email.strip().lower():
                    continue
                if email not in recipient_issues:
                    recipient_issues[email] = []
                recipient_issues[email].append((host, port, issue_reason))
        else:
            print(f"OK (Gültig noch für {int(checker.daysValid)} Tage)")

        time.sleep(0.4)

    print("\n--- E-Mail-Auswertung ---")
    if not recipient_issues:
        print("Keine Probleme gefunden.")
    else:
        for recipient, issues in recipient_issues.items():
            send_summary_email(recipient, issues, args.warning_days, args.debug, args.from_email)

if __name__ == '__main__':
    main()

