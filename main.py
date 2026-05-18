import os, secrets, string
from datetime import datetime, timedelta
from contextlib import asynccontextmanager

import aiosqlite
from fastapi import FastAPI, HTTPException, Header, Depends, Body
from fastapi.middleware.cors import CORSMiddleware

DB_PATH   = os.environ.get("DB_PATH",        "licenses.db")
ADMIN_KEY = os.environ.get("ADMIN_API_KEY",  "changeme")


async def _init_db():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS licenses (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                license_key TEXT    UNIQUE NOT NULL,
                plan        TEXT    NOT NULL DEFAULT 'standard',
                hwid        TEXT,
                owner_note  TEXT    DEFAULT '',
                active      INTEGER DEFAULT 1,
                created_at  TEXT    DEFAULT (datetime('now')),
                expires_at  TEXT,
                last_seen   TEXT
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS announcements (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                version    TEXT    NOT NULL,
                message    TEXT    NOT NULL DEFAULT '',
                link       TEXT    NOT NULL DEFAULT '',
                active     INTEGER DEFAULT 1,
                created_at TEXT    DEFAULT (datetime('now'))
            )
        """)
        # Migrazione: aggiungi colonna link se non esiste
        try:
            await db.execute("ALTER TABLE announcements ADD COLUMN link TEXT NOT NULL DEFAULT ''")
            await db.commit()
        except Exception:
            pass
        await db.commit()


async def _get_active_announcement() -> dict:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM announcements WHERE active=1 ORDER BY id DESC LIMIT 1"
        ) as c:
            row = await c.fetchone()
    return dict(row) if row else {}


@asynccontextmanager
async def lifespan(app):
    await _init_db()
    yield


app = FastAPI(title="EmAutomation License Server", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]
)


# ── Auth admin ───────────────────────────────────────────────────────────────
def _admin(x_api_key: str = Header(...)):
    if x_api_key != ADMIN_KEY:
        raise HTTPException(403, "API key non valida")


def _gen_key() -> str:
    c = string.ascii_uppercase + string.digits
    return "-".join("".join(secrets.choice(c) for _ in range(5)) for _ in range(5))


def _row(r) -> dict:
    return dict(r) if r else {}


# ── Verifica licenza (chiamata da EmAutomation al login) ─────────────────────
@app.post("/verify")
async def verify(body: dict = Body(...)):
    hwid = (body.get("hwid") or "").strip()
    key  = (body.get("license_key") or "").strip().upper()
    if not hwid or not key:
        return {"valid": False, "reason": "Parametri mancanti"}

    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM licenses WHERE license_key=?", (key,)) as c:
            lic = _row(await c.fetchone())

    if not lic:
        return {"valid": False, "reason": "Chiave licenza non trovata"}
    if not lic["active"]:
        return {"valid": False, "reason": "Licenza revocata"}
    if lic["expires_at"]:
        if datetime.utcnow() > datetime.fromisoformat(lic["expires_at"]):
            return {"valid": False, "reason": f"Licenza scaduta il {lic['expires_at'][:10]}"}

    # Prima attivazione: lega HWID
    if not lic["hwid"]:
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute(
                "UPDATE licenses SET hwid=?, last_seen=datetime('now') WHERE license_key=?",
                (hwid, key))
            await db.commit()
    elif lic["hwid"] != hwid:
        return {"valid": False, "reason": "Licenza associata a un'altra macchina"}
    else:
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute(
                "UPDATE licenses SET last_seen=datetime('now') WHERE license_key=?", (key,))
            await db.commit()

    ann = await _get_active_announcement()
    return {
        "valid":        True,
        "plan":         lic["plan"],
        "expires_at":   lic["expires_at"],
        "reason":       "",
        "announcement": {"version": ann["version"], "message": ann["message"], "link": ann.get("link","")} if ann else None,
    }


# ── Admin: lista licenze ──────────────────────────────────────────────────────
@app.get("/admin/licenses")
async def list_licenses(_=Depends(_admin)):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
                "SELECT * FROM licenses ORDER BY created_at DESC") as c:
            rows = await c.fetchall()
    return [dict(r) for r in rows]


# ── Admin: crea licenza ────────────────────────────────────────────────────────
@app.post("/admin/licenses")
async def create_license(body: dict = Body(...), _=Depends(_admin)):
    key  = (body.get("license_key") or _gen_key()).upper().strip()
    plan = body.get("plan", "standard")
    days = int(body.get("days", 365))
    note = body.get("owner_note", "")
    exp  = (datetime.utcnow() + timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S")
    async with aiosqlite.connect(DB_PATH) as db:
        try:
            await db.execute(
                "INSERT INTO licenses (license_key,plan,expires_at,owner_note) VALUES (?,?,?,?)",
                (key, plan, exp, note))
            await db.commit()
        except Exception as e:
            raise HTTPException(400, str(e))
    return {"ok": True, "license_key": key, "plan": plan, "expires_at": exp}


# ── Admin: singola licenza ────────────────────────────────────────────────────
@app.get("/admin/licenses/{key}")
async def get_license(key: str, _=Depends(_admin)):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
                "SELECT * FROM licenses WHERE license_key=?", (key.upper(),)) as c:
            r = await c.fetchone()
    if not r:
        raise HTTPException(404, "Licenza non trovata")
    return dict(r)


# ── Admin: aggiorna licenza ────────────────────────────────────────────────────
@app.put("/admin/licenses/{key}")
async def update_license(key: str, body: dict = Body(...), _=Depends(_admin)):
    allowed = {"plan", "active", "owner_note", "expires_at", "hwid"}
    sets, vals = [], []
    for f in allowed:
        if f in body:
            sets.append(f"{f}=?")
            vals.append(body[f])
    if not sets:
        raise HTTPException(400, "Nessun campo valido da aggiornare")
    vals.append(key.upper())
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            f"UPDATE licenses SET {', '.join(sets)} WHERE license_key=?", vals)
        await db.commit()
    return {"ok": True}


# ── Admin: revoca ─────────────────────────────────────────────────────────────
@app.post("/admin/licenses/{key}/revoke")
async def revoke(key: str, _=Depends(_admin)):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "UPDATE licenses SET active=0 WHERE license_key=?", (key.upper(),))
        await db.commit()
    return {"ok": True}


# ── Admin: ripristina ─────────────────────────────────────────────────────────
@app.post("/admin/licenses/{key}/restore")
async def restore(key: str, _=Depends(_admin)):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "UPDATE licenses SET active=1 WHERE license_key=?", (key.upper(),))
        await db.commit()
    return {"ok": True}


# ── Admin: sblocca HWID ────────────────────────────────────────────────────────
@app.post("/admin/licenses/{key}/unbind")
async def unbind(key: str, _=Depends(_admin)):
    """Rimuove il binding HWID — permette di spostare la licenza su altra macchina."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "UPDATE licenses SET hwid=NULL WHERE license_key=?", (key.upper(),))
        await db.commit()
    return {"ok": True}


# ── Admin: rinnova scadenza ────────────────────────────────────────────────────
@app.post("/admin/licenses/{key}/renew")
async def renew(key: str, body: dict = Body(default={}), _=Depends(_admin)):
    days = int(body.get("days", 365))
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
                "SELECT expires_at FROM licenses WHERE license_key=?", (key.upper(),)) as c:
            r = await c.fetchone()
    if not r:
        raise HTTPException(404, "Licenza non trovata")
    base = datetime.fromisoformat(r["expires_at"]) if r["expires_at"] else datetime.utcnow()
    if base < datetime.utcnow():
        base = datetime.utcnow()
    new_exp = (base + timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S")
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "UPDATE licenses SET expires_at=? WHERE license_key=?",
            (new_exp, key.upper()))
        await db.commit()
    return {"ok": True, "expires_at": new_exp}


# ── Admin: elimina ─────────────────────────────────────────────────────────────
@app.delete("/admin/licenses/{key}")
async def delete_license(key: str, _=Depends(_admin)):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "DELETE FROM licenses WHERE license_key=?", (key.upper(),))
        await db.commit()
    return {"ok": True}


# ── Admin: annunci aggiornamento ──────────────────────────────────────────────
@app.put("/admin/announcement")
async def set_announcement(body: dict = Body(...), _=Depends(_admin)):
    version = (body.get("version") or "").strip()
    message = (body.get("message") or "").strip()
    link    = (body.get("link")    or "").strip()
    active  = int(body.get("active", 1))
    if not version:
        raise HTTPException(400, "version obbligatorio")
    async with aiosqlite.connect(DB_PATH) as db:
        # Disattiva tutti i precedenti
        await db.execute("UPDATE announcements SET active=0")
        if active:
            await db.execute(
                "INSERT INTO announcements (version, message, link, active) VALUES (?,?,?,1)",
                (version, message, link))
        await db.commit()
    return {"ok": True}


@app.get("/admin/announcement")
async def get_announcement(_=Depends(_admin)):
    ann = await _get_active_announcement()
    return ann if ann else {"version": "", "message": "", "active": 0}


# ── Health check ───────────────────────────────────────────────────────────────
@app.get("/health")
async def health():
    return {"ok": True}
