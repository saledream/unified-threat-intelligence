"""Persistent local intelligence state. Public feeds are plaintext; user results are encrypted."""
import base64
import hashlib
import json
import os
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from cryptography.fernet import Fernet, InvalidToken

SCHEMA = '''
CREATE TABLE IF NOT EXISTS cache (key TEXT PRIMARY KEY, expires REAL NOT NULL, body BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS records (source TEXT NOT NULL, record_id TEXT NOT NULL, kind TEXT NOT NULL,
 value TEXT NOT NULL, title TEXT NOT NULL, body TEXT NOT NULL, source_url TEXT NOT NULL,
 retrieved REAL NOT NULL, observed TEXT, PRIMARY KEY(source,record_id,kind,value));
CREATE INDEX IF NOT EXISTS record_value ON records(kind,value);
CREATE INDEX IF NOT EXISTS record_source ON records(source,retrieved);
CREATE TABLE IF NOT EXISTS syncs (source TEXT PRIMARY KEY, status TEXT NOT NULL, updated REAL NOT NULL, count INTEGER NOT NULL, detail TEXT);
CREATE TABLE IF NOT EXISTS approvals (id TEXT PRIMARY KEY, requester TEXT NOT NULL, operation TEXT NOT NULL,
 status TEXT NOT NULL, payload BLOB NOT NULL, created REAL NOT NULL, expires REAL NOT NULL,
 approved_by TEXT, result BLOB, digest TEXT NOT NULL);
'''

@contextmanager
def connection():
    path=Path(os.getenv('INTEL_STATE_DB','data/state/intelligence.sqlite3'))
    path.parent.mkdir(parents=True,exist_ok=True)
    db=sqlite3.connect(path,timeout=10)
    db.row_factory=sqlite3.Row
    try:
        db.execute('PRAGMA busy_timeout=10000')
        db.execute('PRAGMA journal_mode=WAL')
        db.executescript(SCHEMA)
        with db:
            yield db
    finally:
        db.close()


def cipher():
    key=os.getenv('INTEL_STORAGE_KEY','')
    if not key:
        secret=os.getenv('JWT_SECRET_KEY','')
        if len(secret)<32:
            raise RuntimeError('INTEL_STORAGE_KEY or a strong JWT secret is required for protected storage')
        key=base64.urlsafe_b64encode(hashlib.sha256(('mmcy-storage:'+secret).encode()).digest()).decode()
    return Fernet(key.encode())


def seal(value):
    return cipher().encrypt(json.dumps(value,separators=(',',':'),ensure_ascii=False).encode())


def unseal(value):
    return json.loads(cipher().decrypt(value))


def cache_get(key):
    with connection() as db:
        db.execute('DELETE FROM cache WHERE expires<=?',(time.time(),))
        row=db.execute('SELECT body FROM cache WHERE key=?',(key,)).fetchone()
        if row:
            try:return unseal(row['body'])
            except (InvalidToken,ValueError):
                db.execute('DELETE FROM cache WHERE key=?',(key,))
    return None


def cache_put(key,value,ttl):
    body=seal(value)
    with connection() as db:
        db.execute('INSERT OR REPLACE INTO cache VALUES (?,?,?)',(key,time.time()+ttl,body))
        db.execute('DELETE FROM cache WHERE expires<=?',(time.time(),))
        # A hard bound protects small personal deployments in addition to TTL.
        db.execute('DELETE FROM cache WHERE key IN (SELECT key FROM cache ORDER BY expires DESC LIMIT -1 OFFSET 5000)')


def upsert_records(source,records,replace=False):
    now=time.time()
    with connection() as db:
        if replace:db.execute('DELETE FROM records WHERE source=?',(source,))
        rows=[]
        for r in records:
            rows.append((source,str(r['id']),r['kind'],str(r['value']) if r['kind']=='url' else str(r['value']).lower(),str(r.get('title') or r['value']),
                         json.dumps(r.get('data',{}),ensure_ascii=False),r.get('source_url',''),now,r.get('observed')))
        db.executemany('INSERT OR REPLACE INTO records VALUES (?,?,?,?,?,?,?,?,?)',rows)
        if source.startswith('feed:'):
            db.execute('DELETE FROM records WHERE source=? AND retrieved<?',(source,now-30*86400))
            db.execute('DELETE FROM records WHERE rowid IN (SELECT rowid FROM records WHERE source=? ORDER BY retrieved DESC LIMIT -1 OFFSET 50000)',(source,))
        db.execute('INSERT OR REPLACE INTO syncs VALUES (?,?,?,?,?)',(source,'success',now,len(rows),None))
    return len(rows)


def sync_status(source,status,count=0,detail=None):
    with connection() as db:
        db.execute('INSERT OR REPLACE INTO syncs VALUES (?,?,?,?,?)',(source,status,time.time(),count,detail))


def feed_status():
    with connection() as db:
        rows=db.execute('SELECT s.*, (SELECT COUNT(*) FROM records r WHERE r.source=s.source) AS stored_count FROM syncs s ORDER BY source').fetchall()
        return [dict(r) for r in rows]


def search_records(query='',kind=None,source=None,limit=10,since=None,exact=False):
    limit=min(max(int(limit),1),50)
    conditions=[];args=[]
    if query:
        if exact:
            conditions.append('value=?');args.append(query if kind=='url' else query.lower())
        else:
            # LIKE metacharacters are escaped; the query is data, never SQL.
            escaped=query.lower().replace('\\','\\\\').replace('%','\\%').replace('_','\\_')
            conditions.append("(lower(title) LIKE ? ESCAPE '\\' OR lower(value) LIKE ? ESCAPE '\\' OR lower(body) LIKE ? ESCAPE '\\')")
            args.extend(['%'+escaped+'%']*3)
    if kind:conditions.append('kind=?');args.append(kind)
    if source:conditions.append('source=?');args.append(source)
    if since:conditions.append('retrieved>=?');args.append(since)
    where=' WHERE '+' AND '.join(conditions) if conditions else ''
    with connection() as db:
        rows=db.execute('SELECT * FROM records'+where+' ORDER BY retrieved DESC LIMIT ?',[*args,limit]).fetchall()
    out=[]
    for row in rows:
        item=dict(row);item['data']=json.loads(item.pop('body'));out.append(item)
    return out
