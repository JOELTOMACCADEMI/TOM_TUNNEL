#!/usr/bin/env python3
"""Per-account ZiVPN adapter for TOM_TUNNEL.

Each account receives a dedicated UDP port and a dedicated zivpn server process.
iptables byte counters on that port provide per-account traffic attribution.
conntrack entries are sampled for best-effort IP/flow limits. The upstream ZiVPN
binary remains unchanged; this adapter requires a build that accepts a custom
listen port in config.json and permits multiple server processes.
"""
from __future__ import annotations
import argparse, json, os, re, shutil, subprocess, sys
from pathlib import Path
from datetime import datetime, timedelta, timezone

BASE = Path('/etc/zivpn/accounts')
CONF = Path('/etc/zivpn/config.json')
UNIT = Path('/etc/systemd/system/zivpn-user@.service')
PORT_MIN, PORT_MAX = 20000, 29999
USER_RE = re.compile(r'^[A-Za-z0-9_-]{1,32}$')


def run(args, timeout=20):
    try:
        return subprocess.run(args, text=True, capture_output=True, timeout=timeout, check=False)
    except FileNotFoundError as exc:
        return subprocess.CompletedProcess(args, 127, '', str(exc))
    except subprocess.TimeoutExpired as exc:
        return subprocess.CompletedProcess(args, 124, '', str(exc))


def engine():
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from account_engine import get_engine
    return get_engine()


def ensure_unit():
    UNIT.parent.mkdir(parents=True, exist_ok=True)
    content = '''[Unit]\nDescription=ZiVPN isolated account %i\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nUser=root\nWorkingDirectory=/etc/zivpn/accounts/%i\nExecStart=/usr/local/bin/zivpn server -c /etc/zivpn/accounts/%i/config.json\nRestart=on-failure\nRestartSec=2\nNoNewPrivileges=true\nCapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW\nAmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW\n\n[Install]\nWantedBy=multi-user.target\n'''
    if not UNIT.exists() or UNIT.read_text() != content:
        UNIT.write_text(content)
        run(['systemctl', 'daemon-reload'])


def allocate_port(user):
    used = set()
    sock = run(['ss','-H','-lun'])
    if sock and sock.returncode == 0:
        for line in sock.stdout.splitlines():
            m=re.search(r':(\d+)\s', line + ' ')
            if m: used.add(int(m.group(1)))
    for p in BASE.glob('*/account.json'):
        try: used.add(int(json.loads(p.read_text()).get('port', 0)))
        except Exception: pass
    for port in range(PORT_MIN, PORT_MAX + 1):
        if port not in used:
            return port
    raise RuntimeError('Plage de ports ZiVPN individuelle épuisée')


def firewall_add(user, port):
    # Counters are placed in INPUT/OUTPUT before terminal policy rules.
    added = False
    for chain, flag, comment in (('INPUT', '--dport', f'TOMZIVPN_{user}_IN'), ('OUTPUT', '--sport', f'TOMZIVPN_{user}_OUT')):
        check = run(['iptables', '-C', chain, '-p', 'udp', flag, str(port), '-m', 'comment', '--comment', comment, '-j', 'ACCEPT'])
        if check.returncode != 0:
            r = run(['iptables', '-I', chain, '1', '-p', 'udp', flag, str(port), '-m', 'comment', '--comment', comment, '-j', 'ACCEPT'])
            if r.returncode != 0: raise RuntimeError(r.stderr.strip() or f'iptables {chain} failed')
            added = True
    if added:
        run(['ufw', 'allow', f'{port}/udp'])


def firewall_block(user, port):
    comment=f'TOMZIVPN_{user}_BLOCK'
    check=run(['iptables','-C','INPUT','-p','udp','--dport',str(port),'-m','comment','--comment',comment,'-j','DROP'])
    if check.returncode != 0:
        run(['iptables','-I','INPUT','1','-p','udp','--dport',str(port),'-m','comment','--comment',comment,'-j','DROP'])
    run(['conntrack','-D','-p','udp','--orig-port-dst',str(port)])


def firewall_unblock(user, port):
    comment=f'TOMZIVPN_{user}_BLOCK'
    run(['iptables','-D','INPUT','-p','udp','--dport',str(port),'-m','comment','--comment',comment,'-j','DROP'])


def firewall_remove(user, port):
    firewall_unblock(user,port)
    for chain, flag, suffix in (('INPUT', '--dport', 'IN'), ('OUTPUT', '--sport', 'OUT')):
        comment = f'TOMZIVPN_{user}_{suffix}'
        run(['iptables', '-D', chain, '-p', 'udp', flag, str(port), '-m', 'comment', '--comment', comment, '-j', 'ACCEPT'])
    run(['ufw', 'delete', 'allow', f'{port}/udp'])


def ensure_account_firewall(user):
    if not USER_RE.fullmatch(user or ''): raise ValueError('Nom ZiVPN invalide')
    meta=json.loads((BASE/user/'account.json').read_text())
    firewall_add(user,int(meta['port']))
    return {'username':user,'port':int(meta['port']),'firewall':'ready'}


def create(user, password, days, quota=0, ip_limit=0, conn_limit=0, created_by=None):
    if not USER_RE.fullmatch(user or ''): raise ValueError('Nom ZiVPN invalide')
    if not password or re.search(r'\s', password) or len(password) > 128: raise ValueError('Mot de passe ZiVPN invalide')
    days, quota, ip_limit, conn_limit = int(days), float(quota), int(ip_limit), int(conn_limit)
    if days < 1 or days > 3650 or quota < 0 or ip_limit < 0 or conn_limit < 0: raise ValueError('Paramètres invalides')
    if not CONF.is_file(): raise RuntimeError('/etc/zivpn/config.json absent : installer ZiVPN avant de créer un compte')
    if not shutil.which('iptables') or not shutil.which('iptables-save'):
        raise RuntimeError('iptables/iptables-save requis pour mesurer le trafic ZiVPN')
    if (ip_limit > 0 or conn_limit > 0) and not shutil.which('conntrack'):
        raise RuntimeError('conntrack requis pour appliquer les limites IP/flux ; installez le paquet conntrack')
    root = BASE / user
    if root.exists() or engine().get_account(user, 'zivpn'): raise ValueError('Compte ZiVPN déjà existant')
    cfg = json.loads(CONF.read_text())
    if not isinstance(cfg.get('auth', {}).get('config', []), list): raise RuntimeError('auth.config invalide')
    port = allocate_port(user)
    root.mkdir(parents=True, mode=0o700)
    try:
        cfg['listen'] = f':{port}'
        cfg.setdefault('auth', {})['mode'] = 'passwords'
        cfg['auth']['config'] = [password]
        # Reuse existing TLS material; do not duplicate private keys.
        (root / 'config.json').write_text(json.dumps(cfg, indent=2) + '\n')
        os.chmod(root / 'config.json', 0o600)
        expires = (datetime.now(timezone.utc) + timedelta(days=days)).strftime('%Y-%m-%d')
        (root / 'account.json').write_text(json.dumps({'username':user,'port':port,'expiry':expires}, indent=2)+'\n')
        os.chmod(root / 'account.json', 0o600)
        ensure_unit(); firewall_add(user, port)
        r = run(['systemctl', 'enable', '--now', f'zivpn-user@{user}.service'], 35)
        if r.returncode != 0: raise RuntimeError(r.stderr.strip() or 'Démarrage ZiVPN impossible')
        eng = engine()
        eng.create_account(user, 'zivpn', password=password, days=days, quota_gb=quota,
                           ip_limit=ip_limit, conn_limit=conn_limit, created_by=created_by,
                           extra_data={'port':port,'instance':'zivpn-user@'+user+'.service','meter':'iptables'})
        return {'username':user,'password':password,'port':port,'expiry':expires,'quota_gb':quota,'ip_limit':ip_limit,'conn_limit':conn_limit}
    except Exception:
        run(['systemctl','disable','--now',f'zivpn-user@{user}.service'])
        if root.exists(): shutil.rmtree(root, ignore_errors=True)
        try: firewall_remove(user, port)
        except Exception: pass
        raise


def _iptables_counters(user, port):
    r = run(['iptables-save','-c'])
    if r.returncode != 0: raise RuntimeError('iptables-save indisponible')
    found = {'IN':0,'OUT':0}
    for line in r.stdout.splitlines():
        for direction in ('IN','OUT'):
            if f'TOMZIVPN_{user}_{direction}' in line:
                m = re.match(r'^\[(\d+):(\d+)\]', line)
                if m: found[direction] = int(m.group(2))
    return found


def parse_conntrack_lines(text, port):
    rows=[]
    for i,line in enumerate((text or '').splitlines()):
        src=re.search(r'\bsrc=([^ ]+)',line); sport=re.search(r'\bsport=(\d+)',line)
        if src and sport:
            rows.append({'ip':src.group(1),'sport':sport.group(1),'id':f"{port}:{src.group(1)}:{sport.group(1)}:{i}", 'line':line})
    return rows


def counter_delta(current, previous):
    current=max(0,int(current)); previous=max(0,int(previous))
    return current-previous if current>=previous else current


def _conntrack(port):
    r = run(['conntrack','-L','-p','udp','--orig-port-dst',str(port)])
    if r is None or r.returncode not in (0,1): return []
    return parse_conntrack_lines(r.stdout, port)


def collect_and_enforce():
    eng=engine(); report={'updated':0,'denied':0,'errors':[]}; all_live={}
    from account_engine import _db_connection
    with _db_connection(eng.db_path) as db:
        flag=db.execute("SELECT value FROM engine_meta WHERE key='proto_disabled:zivpn'").fetchone()
    protocol_disabled=bool(flag and str(flag['value'])=='1')
    for acc in eng.list_accounts(protocol='zivpn'):
        user=acc['username']; root=BASE/user
        try:
            meta=json.loads((root/'account.json').read_text()); port=int(meta['port'])
            firewall_add(user,port)  # restore counters/rules after reboot or firewall reload
            counters=_iptables_counters(user,port)
            key=f'zivpn_counter:{user}'
            from account_engine import _db_connection
            with _db_connection(eng.db_path) as db:
                row=db.execute('SELECT value FROM engine_meta WHERE key=?',(key,)).fetchone()
                old=json.loads(row['value']) if row else {'IN':0,'OUT':0}
                delta_in=counter_delta(counters['IN'],old.get('IN',0))
                delta_out=counter_delta(counters['OUT'],old.get('OUT',0))
                db.execute('INSERT OR REPLACE INTO engine_meta(key,value) VALUES(?,?)',(key,json.dumps(counters)))
                db.commit()
            if delta_in or delta_out:
                eng.add_traffic(user,'zivpn',bytes_up=delta_in,bytes_down=delta_out,source='zivpn-iptables')
                report['updated']+=1
            current=eng.get_account(user,'zivpn')
            active=(current and current.get('status')=='active' and not protocol_disabled)
            if active:
                firewall_unblock(user,port)
                service=f'zivpn-user@{user}.service'
                state=run(['systemctl','is-active',service])
                if not state or state.stdout.strip()!='active':
                    run(['systemctl','start',service],30)
                flows=_conntrack(port)
                # Dedicated port identifies this account. Sample active conntrack
                # flows and reject excess flows at the next collector interval.
                ip_cap=int(current.get('ip_limit') or 0); flow_cap=int(current.get('conn_limit') or 0)
                if (ip_cap or flow_cap) and not shutil.which('conntrack'):
                    raise RuntimeError('conntrack absent : limites IP/flux non appliquées')
                allowed_ips=set(); kept=0
                for flow in flows:
                    ip=flow['ip']; deny=(ip_cap>0 and ip not in allowed_ips and len(allowed_ips)>=ip_cap) or (flow_cap>0 and kept>=flow_cap)
                    if deny:
                        run(['conntrack','-D','-p','udp','--orig-src',ip,'--orig-port-src',flow['sport'], '--orig-port-dst',str(port)])
                        report['denied']+=1
                    else:
                        allowed_ips.add(ip); kept+=1
                        all_live[flow['id']]=(user,ip)
            else:
                firewall_block(user,port)
                run(['systemctl','stop',f'zivpn-user@{user}.service'])
        except Exception as e: report['errors'].append(f'{user}: {e}')
    eng.sync_sessions('zivpn',all_live)
    return report


def renew(user, days):
    eng=engine(); acc=eng.get_account(user,'zivpn')
    if not acc: raise ValueError('Compte ZiVPN introuvable')
    days=int(days)
    if days<1 or days>3650: raise ValueError('Durée invalide')
    updated=eng.renew(user,'zivpn',days)
    root=BASE/user; meta=json.loads((root/'account.json').read_text())
    meta['expiry']=updated.get('expires_at')
    (root/'account.json').write_text(json.dumps(meta,indent=2)+'\n')
    os.chmod(root/'account.json',0o600)
    return {'username':user,'expiry':meta['expiry'],'port':meta['port']}


def delete(user):
    eng=engine(); acc=eng.get_account(user,'zivpn')
    root=BASE/user
    port=None
    if root.exists():
        try: port=int(json.loads((root/'account.json').read_text()).get('port'))
        except Exception: pass
    run(['systemctl','disable','--now',f'zivpn-user@{user}.service'])
    if port: firewall_remove(user,port)
    shutil.rmtree(root,ignore_errors=True)
    eng.delete_account(user,'zivpn')
    return bool(acc)


def main():
    p=argparse.ArgumentParser(); sub=p.add_subparsers(dest='cmd',required=True)
    c=sub.add_parser('create'); c.add_argument('username'); c.add_argument('password'); c.add_argument('days',type=int); c.add_argument('--quota',type=float,default=0); c.add_argument('--ip-limit',type=int,default=0); c.add_argument('--conn-limit',type=int,default=0); c.add_argument('--created-by')
    d=sub.add_parser('delete'); d.add_argument('username')
    f=sub.add_parser('firewall'); f.add_argument('username')
    r=sub.add_parser('renew'); r.add_argument('username'); r.add_argument('days',type=int)
    sub.add_parser('collect')
    sub.add_parser('list')
    a=p.parse_args()
    try:
        if a.cmd=='create': result=create(a.username,a.password,a.days,a.quota,a.ip_limit,a.conn_limit,a.created_by)
        elif a.cmd=='delete': result={'deleted':delete(a.username)}
        elif a.cmd=='firewall': result=ensure_account_firewall(a.username)
        elif a.cmd=='renew': result=renew(a.username,a.days)
        elif a.cmd=='list':
            result=engine().list_accounts(protocol='zivpn')
            legacy=Path('/etc/zivpn/user.db')
            known={x.get('username') for x in result}
            if legacy.is_file():
                for line in legacy.read_text(errors='ignore').splitlines():
                    parts=line.split()
                    if len(parts)>=3 and parts[0] not in known:
                        result.append({'username':parts[0],'protocol':'zivpn','status':'legacy_shared','expires_at':parts[2],'quota_gb':0,'used_gb':0,'ip_limit':0,'conn_limit':0,'extra_data':'{}'})
        else: result=collect_and_enforce()
        print(json.dumps({'ok':True,'data':result}))
    except Exception as e:
        print(json.dumps({'ok':False,'error':str(e)})); sys.exit(1)

if __name__=='__main__': main()
