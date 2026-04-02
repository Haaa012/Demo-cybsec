#!/usr/bin/env python3
"""
scanner_discover.py — Découverte de ports et services (format nmap)
Affiche UNIQUEMENT : PORT  STATE  SERVICE  VERSION
Usage : python3 scanner_discover.py http://127.0.0.1:5000
"""
import socket, re, subprocess, sys
from urllib.parse import urlparse

raw = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:5000"
if not re.match(r'^https?://', raw):
    raw = 'http://' + raw
p      = urlparse(raw)
host   = p.hostname or '127.0.0.1'
scheme = p.scheme   or 'http'
p_exp  = p.port

WEB = [(80,'http'),(443,'https'),(8080,'http'),
       (8443,'https'),(5000,'http'),(3000,'http'),(8000,'http')]
if p_exp:
    WEB = [(p_exp, scheme)] + [x for x in WEB if x[0] != p_exp]

OTHER = [(22,'ssh'),(21,'ftp'),(23,'telnet'),
         (3306,'mysql'),(5432,'postgres')]

def tcp_open(h, port, t=2):
    try:
        s = socket.socket(); s.settimeout(t)
        ok = s.connect_ex((h, port)) == 0; s.close(); return ok
    except: return False

def get_banner(h, port, sc, t=5):
    try:
        import urllib.request, urllib.error
        req = urllib.request.Request(f'{sc}://{h}:{port}/',
            headers={'User-Agent': 'Mozilla/5.0'})
        try:
            resp = urllib.request.urlopen(req, timeout=t)
            return resp.status, dict(resp.headers)
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers)
    except: return None, {}

def identify(hdrs):
    srv = hdrs.get('Server', hdrs.get('server', ''))
    xpb = hdrs.get('X-Powered-By', hdrs.get('x-powered-by', ''))
    txt = (srv + xpb).lower()
    if 'werkzeug' in txt or 'flask' in txt:
        m = re.search(r'werkzeug[\s/]+([\d.]+)', txt)
        return f'http    Werkzeug httpd {m.group(1) if m else "?"} (Python/Flask)'
    if 'jetty'   in txt:
        m = re.search(r'jetty[\s/]+([\d.]+)', txt)
        return f'http    Jetty {m.group(1) if m else "?"}'
    if 'nginx'   in txt:
        m = re.search(r'nginx[\s/]+([\d.]+)', txt)
        return f'http    nginx {m.group(1) if m else "?"}'
    if 'apache'  in txt:
        m = re.search(r'apache[\s/]+([\d.]+)', txt)
        return f'http    Apache httpd {m.group(1) if m else "?"}'
    if 'django'  in txt: return 'http    Django (Python)'
    if 'express' in txt: return 'http    Express (Node.js)'
    if srv:              return f'http    {srv[:50]}'
    return               'http    HTTP service'

print(f'Scan report for {host}')
print(f'Host is up.')
print()
print(f'PORT      STATE  SERVICE  VERSION')

found = []

for port, sc in WEB:
    if tcp_open(host, port):
        status, hdrs = get_banner(host, port, sc)
        banner = identify(hdrs) if status is not None else 'http    HTTP service'
        print(f'{port}/tcp   open  {banner}')
        found.append(port)

for port, svc in OTHER:
    if tcp_open(host, port, t=1):
        print(f'{port}/tcp   open  {svc}')
        found.append(port)

try:
    r = subprocess.run(['ping','-c','1','-W','1',host],
                       capture_output=True, text=True, timeout=3)
    m = re.search(r'ttl=(\d+)', r.stdout, re.I)
    if m:
        ttl = int(m.group(1))
        os_g = 'Linux/Unix' if ttl<=64 else ('Windows' if ttl<=128 else 'Inconnu')
        print(); print(f'OS details: {os_g} (TTL={ttl})')
except: pass

print()
print(f'Nmap done: 1 IP address (1 host up) scanned')
if not found:
    print("Note: Aucun port ouvert — lancez web_vulnerable.py d'abord.")
