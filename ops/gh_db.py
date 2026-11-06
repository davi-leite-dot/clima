#!/usr/bin/env python3
"""Atualiza só os bancos cifrados do Painel OFI Clima neste repositório (GitHub Pages).

Não tem segredo dentro: a senha vem da variável OFI_PW e o sal vem de k.json. Cada coleção fica em
<painel>/db/<coleção>.json.enc (gzip + AES-256-GCM). O Netlify (ofi-clima-monte-pascoal.netlify.app) lê estes
mesmos arquivos daqui na hora em que a página abre, então atualizar o repositório atualiza os dois sites.

Uso (na raiz do repositório):
  OFI_PW=... python3 ops/gh_db.py apply plan_painel.json plan_skysat_1.json ...   (rotina de hora em hora)
  OFI_PW=... python3 ops/gh_db.py apply --wf plan.json                            (rotina de 3 h: iss/obs/radar/wk/enso -> wf_*)
  OFI_PW=... python3 ops/gh_db.py dump <pasta com <coleção>/<doc>.json>           (reescreve tudo a partir de uma leitura completa)

Os planos são as listas "writes" do ArtifactData batch ({op, collection, doc_id, file_path|data}); o script aplica
set, update e delete do mesmo jeito que o banco do artifact, recorta as coleções como as páginas pedem e refaz os
bancos derivados do EON Weather Pepper (pepper/db) e do Drone Voo (drone/db).
"""
import base64, datetime as dt, glob, gzip, hashlib, json, os, sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

TRIM = {'skysat': ('ts', 30), 'fc': ('issued', 36), 'f18': ('d', 15), 'sat': ('day', 10), 'sun': ('d', 60), 'vime': ('run', 1)}
WF = {'iss': 'wf_iss', 'obs': 'wf_obs', 'radar': 'wf_radar', 'wk': 'wf_wk', 'enso': 'wf_enso'}
DIRS = {'clima': 'db', 'pepper': 'pepper/db', 'drone': 'drone/db'}


def key():
    m = json.load(open('k.json'))
    pw = os.environ.get('OFI_PW', '').strip().lower()
    k = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=base64.b64decode(m['salt']), iterations=m['iter']).derive(pw.encode())
    if dec(k, base64.b64decode(m['check'])) != b'ok':
        sys.exit('OFI_PW errada para este k.json')
    return k


def dec(k, b):
    return gzip.decompress(AESGCM(k).decrypt(b[:12], b[12:], None))


def enc(k, b):
    iv = os.urandom(12)
    return iv + AESGCM(k).encrypt(iv, gzip.compress(b, 9, mtime=0), None)


def load(k, d, c):
    p = f'{d}/{c}.json.enc'
    return json.loads(dec(k, open(p, 'rb').read())) if os.path.exists(p) else {}


def trim(c, m):
    if c not in TRIM or not m:
        return m
    f, n = TRIM[c]
    ids = sorted(m, key=lambda i: (m[i] or {}).get(f) or '', reverse=True)[:n]
    return {i: m[i] for i in ids}


def save_all(k, d, colls):
    os.makedirs(d, exist_ok=True)
    vp = f'{d}/_v.json.enc'
    v = json.loads(dec(k, open(vp, 'rb').read())) if os.path.exists(vp) else {}
    for c, m in colls.items():
        b = json.dumps(m, ensure_ascii=False, separators=(',', ':')).encode()
        h = hashlib.sha1(b).hexdigest()[:12]
        if v.get(c) == h and os.path.exists(f'{d}/{c}.json.enc'):
            continue
        open(f'{d}/{c}.json.enc', 'wb').write(enc(k, b))
        v[c] = h
    v['_at'] = dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    open(vp, 'wb').write(enc(k, json.dumps(v).encode()))


def derived(k, cc):
    """Pepper e Drone saem do banco do Clima Monte Pascoal (a rotina grava os mesmos documentos nos três)."""
    need = ['obs', 'hours', 'now', 'fcnow', 'status', 'm30', 'wf_wk', 'sun', 'wf_iss', 'wf_obs', 'wf_radar', 'wf_enso']
    for c in need:
        if c not in cc:
            cc[c] = load(k, 'db', c)
    fz = lambda m: {i: v for i, v in (m or {}).items() if i.startswith('FAZMP')}
    pep = {'obs': fz(cc['obs']), 'hours': fz(cc['hours']), 'now': fz(cc['now']), 'fcnow': cc['fcnow'], 'status': cc['status'],
           'm30': cc['m30'], 'wk': cc['wf_wk'], 'sun': dict(list(trim('sun', cc['sun']).items())[:40])}
    dr = {'iss': cc['wf_iss'], 'obs': cc['wf_obs'], 'radar': cc['wf_radar'], 'enso': cc['wf_enso'], 'wk': cc['wf_wk']}
    save_all(k, DIRS['pepper'], pep)
    save_all(k, DIRS['drone'], dr)


def apply(paths, wf=False):
    k = key()
    cc, changed = {}, set()
    for p in paths:
        writes = json.load(open(p))
        if isinstance(writes, dict):
            writes = writes.get('writes') or []
        for e in writes:
            c, i, op = e['collection'], e['doc_id'], e.get('op', 'set')
            if wf:
                if c == 'radar' and i != 'CR':
                    continue
                c = WF.get(c, c)
            if c not in cc:
                cc[c] = load(k, 'db', c)
            if op == 'delete':
                cc[c].pop(i, None)
            else:
                data = e.get('data')
                if data is None and e.get('file_path'):
                    data = json.load(open(e['file_path']))
                if data is None:
                    continue
                if op == 'update' and isinstance(cc[c].get(i), dict):
                    cc[c][i] = {**cc[c][i], **data}
                else:
                    cc[c][i] = data
            changed.add(c)
    save_all(k, DIRS['clima'], {c: trim(c, cc[c]) for c in changed})
    derived(k, cc)
    print('coleções atualizadas:', ', '.join(sorted(changed)) or 'nenhuma')


def dump(src):
    k = key()
    cc = {}
    for d in sorted(glob.glob(f'{src}/*')):
        if not os.path.isdir(d):
            continue
        c = os.path.basename(d)
        m = {}
        for f in sorted(glob.glob(f'{d}/*.json')):
            m[os.path.basename(f)[:-5]] = json.load(open(f))
        cc[c] = trim(c, m)
    save_all(k, DIRS['clima'], cc)
    derived(k, cc)
    print('coleções gravadas:', ', '.join(sorted(cc)))


if __name__ == '__main__':
    a = sys.argv[1:]
    if not a:
        sys.exit(__doc__)
    if a[0] == 'apply':
        wf = '--wf' in a
        apply([x for x in a[1:] if x != '--wf'], wf)
    elif a[0] == 'dump':
        dump(a[1])
    else:
        sys.exit(__doc__)
