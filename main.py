from fastapi import FastAPI, HTTPException, Depends
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr
from typing import Dict, List, Optional
import uvicorn
import time
import asyncio
from pathlib import Path
import sqlite3
import uuid
import os
import base64
import hashlib
import hmac
import json
import urllib.request

from jose import jwt, JWTError

app = FastAPI()
DB_PATH = "app.db"

JWT_SECRET = os.environ.get("JWT_SECRET")  # set this in your shell
JWT_ALGORITHM = "HS256"
JWT_EXPIRES_SECONDS = 60 * 60 * 24 * 7  # 7 days
FCM_SERVER_KEY = os.environ.get("FCM_SERVER_KEY")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

# -----------------------
# Password hashing (PBKDF2)
# -----------------------
_PBKDF2_ITERATIONS = 210_000  # reasonable baseline; can tune later


def _hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        _PBKDF2_ITERATIONS,
        dklen=32,
    )
    salt_b64 = base64.urlsafe_b64encode(salt).decode("ascii").rstrip("=")
    dk_b64 = base64.urlsafe_b64encode(dk).decode("ascii").rstrip("=")
    return f"pbkdf2_sha256${_PBKDF2_ITERATIONS}${salt_b64}${dk_b64}"


def _verify_password(password: str, stored: str) -> bool:
    try:
        algo, iter_s, salt_b64, dk_b64 = stored.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        iterations = int(iter_s)

        def _b64pad(s: str) -> str:
            return s + "=" * ((4 - (len(s) % 4)) % 4)

        salt = base64.urlsafe_b64decode(_b64pad(salt_b64).encode("ascii"))
        expected = base64.urlsafe_b64decode(_b64pad(dk_b64).encode("ascii"))

        actual = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            iterations,
            dklen=len(expected),
        )
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def _create_access_token(user_id: str) -> str:
    if not JWT_SECRET:
        raise RuntimeError("JWT_SECRET is not set (export JWT_SECRET='<your-strong-secret>')")
    now = int(time.time())
    payload = {"sub": user_id, "iat": now, "exp": now + JWT_EXPIRES_SECONDS}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


async def get_current_user_id(token: str = Depends(oauth2_scheme)) -> str:
    try:
        payload = jwt.decode(token, JWT_SECRET or "", algorithms=[JWT_ALGORITHM])
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=401, detail="invalid token")
        return str(user_id)
    except JWTError:
        raise HTTPException(status_code=401, detail="invalid token")

# -----------------------
# Database Utilities
# -----------------------
def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def _init_db() -> None:
    with _get_conn() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
              id TEXT PRIMARY KEY,
              name TEXT NOT NULL,
              email TEXT NOT NULL UNIQUE,
              password_hash TEXT NOT NULL,
              created_at REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS groups (
              id TEXT PRIMARY KEY,
              name TEXT
            );

            CREATE TABLE IF NOT EXISTS group_members (
              group_id TEXT NOT NULL,
              user_id  TEXT NOT NULL,
              PRIMARY KEY (group_id, user_id),
              FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE,
              FOREIGN KEY (user_id)  REFERENCES users(id)  ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS group_join_requests (
              group_id TEXT NOT NULL,
              user_id  TEXT NOT NULL,
              created_at REAL NOT NULL,
              PRIMARY KEY (group_id, user_id),
              FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE,
              FOREIGN KEY (user_id)  REFERENCES users(id)  ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS user_group_sharing (
              user_id  TEXT NOT NULL,
              group_id TEXT NOT NULL,
              enabled  INTEGER NOT NULL DEFAULT 0,
              PRIMARY KEY (user_id, group_id),
              FOREIGN KEY (user_id)  REFERENCES users(id)  ON DELETE CASCADE,
              FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS user_push_tokens (
              user_id TEXT NOT NULL,
              token TEXT NOT NULL,
              created_at REAL NOT NULL,
              PRIMARY KEY (user_id, token),
              FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS group_messages (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              group_id TEXT NOT NULL,
              user_id TEXT NOT NULL,
              body TEXT NOT NULL,
              created_at REAL NOT NULL,
              FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE,
              FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )

        # Migration: add owner_user_id to groups (SQLite doesn't support IF NOT EXISTS for columns)
        try:
            conn.execute("ALTER TABLE groups ADD COLUMN owner_user_id TEXT")
        except sqlite3.OperationalError:
            # column already exists
            pass

        # Migration: add name to groups (SQLite doesn't support IF NOT EXISTS for columns)
        try:
            conn.execute("ALTER TABLE groups ADD COLUMN name TEXT")
        except sqlite3.OperationalError:
            # column already exists
            pass

        # Optional: index for owner lookups
        try:
            conn.execute("CREATE INDEX idx_groups_owner ON groups(owner_user_id)")
        except sqlite3.OperationalError:
            # index already exists
            pass

        try:
            conn.execute(
                "CREATE INDEX idx_group_messages_group_created ON group_messages(group_id, created_at)"
            )
        except sqlite3.OperationalError:
            # index already exists
            pass


async def _db_call(fn, *args, **kwargs):
    return await asyncio.to_thread(fn, *args, **kwargs)


# -----------------------
# Models
# -----------------------
class UserCreate(BaseModel):
    name: str
    email: EmailStr
    password: str


class UserPublic(BaseModel):
    id: str
    name: str
    email: EmailStr


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class UserLocation(BaseModel):
    user_id: str
    username: str
    lat: float
    lon: float
    heading: Optional[float] = None
    last_seen: float = 0.0


class GroupCreate(BaseModel):
    id: Optional[str] = None
    name: Optional[str] = None


class GroupPublic(BaseModel):
    id: str
    name: Optional[str] = None
    owner_user_id: Optional[str] = None


class ShareUpdate(BaseModel):
    enabled: bool


class PushTokenPayload(BaseModel):
    token: str


class ChatMessageCreate(BaseModel):
    body: str


class ChatMessagePublic(BaseModel):
    id: int
    group_id: str
    user_id: str
    username: str
    body: str
    created_at: float


# -----------------------
# User CRUD
# -----------------------
def _create_user(name: str, email: str, password: str) -> UserPublic:
    user_id = str(uuid.uuid4())
    password_hash = _hash_password(password)
    now = time.time()
    try:
        with _get_conn() as conn:
            conn.execute(
                "INSERT INTO users(id, name, email, password_hash, created_at) VALUES (?, ?, ?, ?, ?)",
                (user_id, name, email, password_hash, now),
            )
    except sqlite3.IntegrityError:
        raise ValueError("email_already_exists")
    return UserPublic(id=user_id, name=name, email=email)


def _get_user_by_email(email: str) -> Optional[sqlite3.Row]:
    with _get_conn() as conn:
        return conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()


def _get_user_by_id(user_id: str) -> Optional[sqlite3.Row]:
    with _get_conn() as conn:
        return conn.execute("SELECT id, name, email FROM users WHERE id = ?", (user_id,)).fetchone()


def _user_exists(user_id: str) -> bool:
    with _get_conn() as conn:
        return conn.execute("SELECT 1 FROM users WHERE id = ?", (user_id,)).fetchone() is not None


# -----------------------
# Group DB ops
# -----------------------
def _group_exists(group_id: str) -> bool:
    with _get_conn() as conn:
        return conn.execute("SELECT 1 FROM groups WHERE id = ?", (group_id,)).fetchone() is not None


def _get_group_owner_id(group_id: str) -> Optional[str]:
    with _get_conn() as conn:
        row = conn.execute("SELECT owner_user_id FROM groups WHERE id = ?", (group_id,)).fetchone()
        if not row:
            return None
        return row["owner_user_id"]

def _set_group_owner(group_id: str, owner_user_id: str) -> None:
    with _get_conn() as conn:
        conn.execute(
            "UPDATE groups SET owner_user_id = ? WHERE id = ? AND (owner_user_id IS NULL OR owner_user_id = '')",
            (owner_user_id, group_id),
        )



def _create_group_with_owner(group_id: str, owner_user_id: str, name: Optional[str] = None) -> GroupPublic:
    with _get_conn() as conn:
        # create the group if it doesn't exist
        conn.execute("INSERT OR IGNORE INTO groups(id, name) VALUES (?, ?)", (group_id, name))
        if name:
            conn.execute(
                """
                UPDATE groups
                SET name = ?
                WHERE id = ? AND (name IS NULL OR name = '')
                """,
                (name, group_id),
            )

        # if owner isn't set yet, set it (first creator becomes owner)
        conn.execute(
            """
            UPDATE groups
            SET owner_user_id = ?
            WHERE id = ? AND (owner_user_id IS NULL OR owner_user_id = '')
            """,
            (owner_user_id, group_id),
        )

        # ensure owner is a member of the group
        conn.execute(
            "INSERT OR IGNORE INTO group_members(group_id, user_id) VALUES (?, ?)",
            (group_id, owner_user_id),
        )

        row = conn.execute("SELECT id, name FROM groups WHERE id = ?", (group_id,)).fetchone()

    return GroupPublic(id=row["id"], name=row["name"] if row else name, owner_user_id=owner_user_id)


def _create_group(group_id: str, name: Optional[str] = None) -> GroupPublic:
    with _get_conn() as conn:
        conn.execute("INSERT OR IGNORE INTO groups(id, name) VALUES (?, ?)", (group_id, name))
        if name:
            conn.execute(
                "UPDATE groups SET name = ? WHERE id = ? AND (name IS NULL OR name = '')",
                (name, group_id),
            )
        row = conn.execute("SELECT id, name FROM groups WHERE id = ?", (group_id,)).fetchone()
    return GroupPublic(id=row["id"], name=row["name"] if row else name, owner_user_id=owner_user_id)


def _list_groups() -> List[dict]:
    with _get_conn() as conn:
        rows = conn.execute("SELECT id, name, owner_user_id FROM groups ORDER BY id").fetchall()
        return [
            {"id": r["id"], "name": r["name"], "owner_user_id": r["owner_user_id"]}
            for r in rows
        ]


def _list_group_ids() -> List[str]:
    with _get_conn() as conn:
        rows = conn.execute("SELECT id FROM groups ORDER BY id").fetchall()
        return [r["id"] for r in rows]


def _add_member(group_id: str, user_id: str) -> None:
    with _get_conn() as conn:
        conn.execute("INSERT OR IGNORE INTO groups(id) VALUES (?)", (group_id,))
        conn.execute(
            "INSERT OR IGNORE INTO group_members(group_id, user_id) VALUES (?, ?)",
            (group_id, user_id),
        )


def _remove_member(group_id: str, user_id: str) -> int:
    with _get_conn() as conn:
        cur = conn.execute(
            "DELETE FROM group_members WHERE group_id = ? AND user_id = ?",
            (group_id, user_id),
        )
        return cur.rowcount


def _set_group_sharing(user_id: str, group_id: str, enabled: bool) -> None:
    with _get_conn() as conn:
        # Ensure the user is at least a member of the group before allowing sharing toggle.
        # (Optional rule, but usually makes sense.)
        is_member = conn.execute(
            "SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?",
            (group_id, user_id),
        ).fetchone()
        if not is_member:
            raise ValueError("not_a_member")

        conn.execute(
            """
            INSERT INTO user_group_sharing(user_id, group_id, enabled)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id, group_id) DO UPDATE SET enabled = excluded.enabled
            """,
            (user_id, group_id, 1 if enabled else 0),
        )


def _get_share_enabled_member_ids(group_id: str) -> List[str]:
    with _get_conn() as conn:
        rows = conn.execute(
            """
            SELECT gm.user_id AS user_id
            FROM group_members gm
            JOIN user_group_sharing s
              ON s.user_id = gm.user_id AND s.group_id = gm.group_id
            WHERE gm.group_id = ?
              AND s.enabled = 1
            ORDER BY gm.user_id
            """,
            (group_id,),
        ).fetchall()
        return [r["user_id"] for r in rows]


def _add_push_token(user_id: str, token: str) -> None:
    with _get_conn() as conn:
        now = time.time()
        conn.execute(
            "INSERT OR IGNORE INTO user_push_tokens(user_id, token, created_at) VALUES (?, ?, ?)",
            (user_id, token, now),
        )


def _list_push_tokens(user_id: str) -> List[str]:
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT token FROM user_push_tokens WHERE user_id = ? ORDER BY created_at DESC",
            (user_id,),
        ).fetchall()
        return [r["token"] for r in rows]


def _remove_push_token(user_id: str, token: str) -> int:
    with _get_conn() as conn:
        cur = conn.execute(
            "DELETE FROM user_push_tokens WHERE user_id = ? AND token = ?",
            (user_id, token),
        )
        return cur.rowcount

def _list_members(group_id: str) -> List[str]:
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT user_id FROM group_members WHERE group_id = ? ORDER BY user_id",
            (group_id,),
        ).fetchall()
        return [r["user_id"] for r in rows]


def _list_members_with_names(group_id: str) -> List[dict]:
    with _get_conn() as conn:
        rows = conn.execute(
            """
            SELECT u.id AS id, u.name AS name
            FROM group_members gm
            JOIN users u ON u.id = gm.user_id
            WHERE gm.group_id = ?
            ORDER BY u.name, u.id
            """,
            (group_id,),
        ).fetchall()
        return [{"id": r["id"], "name": r["name"]} for r in rows]


def _is_member(group_id: str, user_id: str) -> bool:
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?",
            (group_id, user_id),
        ).fetchone()
        return row is not None


def _count_members(group_id: str) -> int:
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS count FROM group_members WHERE group_id = ?",
            (group_id,),
        ).fetchone()
        return int(row["count"] if row else 0)


def _create_join_request(group_id: str, user_id: str) -> None:
    with _get_conn() as conn:
        now = time.time()
        conn.execute(
            "INSERT OR IGNORE INTO group_join_requests(group_id, user_id, created_at) VALUES (?, ?, ?)",
            (group_id, user_id, now),
        )


def _list_join_requests_with_names(group_id: str) -> List[dict]:
    with _get_conn() as conn:
        rows = conn.execute(
            """
            SELECT u.id AS id, u.name AS name, r.created_at AS created_at
            FROM group_join_requests r
            JOIN users u ON u.id = r.user_id
            WHERE r.group_id = ?
            ORDER BY r.created_at ASC
            """,
            (group_id,),
        ).fetchall()
        return [
            {"id": r["id"], "name": r["name"], "created_at": r["created_at"]}
            for r in rows
        ]


def _list_group_messages(group_id: str, limit: int = 50, before: Optional[float] = None) -> List[dict]:
    with _get_conn() as conn:
        if before is None:
            rows = conn.execute(
                """
                SELECT gm.id, gm.group_id, gm.user_id, u.name AS username, gm.body, gm.created_at
                FROM group_messages gm
                JOIN users u ON u.id = gm.user_id
                WHERE gm.group_id = ?
                ORDER BY gm.created_at DESC
                LIMIT ?
                """,
                (group_id, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT gm.id, gm.group_id, gm.user_id, u.name AS username, gm.body, gm.created_at
                FROM group_messages gm
                JOIN users u ON u.id = gm.user_id
                WHERE gm.group_id = ? AND gm.created_at < ?
                ORDER BY gm.created_at DESC
                LIMIT ?
                """,
                (group_id, before, limit),
            ).fetchall()
        messages = [
            {
                "id": r["id"],
                "group_id": r["group_id"],
                "user_id": r["user_id"],
                "username": r["username"],
                "body": r["body"],
                "created_at": r["created_at"],
            }
            for r in rows
        ]
        return list(reversed(messages))


def _add_group_message(group_id: str, user_id: str, body: str) -> dict:
    created_at = time.time()
    with _get_conn() as conn:
        conn.execute(
            """
            INSERT INTO group_messages(group_id, user_id, body, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (group_id, user_id, body, created_at),
        )
        row = conn.execute(
            """
            SELECT gm.id, gm.group_id, gm.user_id, u.name AS username, gm.body, gm.created_at
            FROM group_messages gm
            JOIN users u ON u.id = gm.user_id
            WHERE gm.group_id = ? AND gm.user_id = ? AND gm.created_at = ?
            ORDER BY gm.id DESC
            LIMIT 1
            """,
            (group_id, user_id, created_at),
        ).fetchone()
        if not row:
            raise RuntimeError("message_insert_failed")
        return {
            "id": row["id"],
            "group_id": row["group_id"],
            "user_id": row["user_id"],
            "username": row["username"],
            "body": row["body"],
            "created_at": row["created_at"],
        }


def _remove_join_request(group_id: str, user_id: str) -> int:
    with _get_conn() as conn:
        cur = conn.execute(
            "DELETE FROM group_join_requests WHERE group_id = ? AND user_id = ?",
            (group_id, user_id),
        )
        return cur.rowcount


def _send_expo_push(tokens: List[str], title: str, body: str, data: dict) -> None:
    if not tokens:
        return
    messages = [
        {"to": token, "title": title, "body": body, "data": data, "sound": "default"}
        for token in tokens
    ]
    payload = json.dumps(messages).encode("utf-8")
    req = urllib.request.Request(
        "https://exp.host/--/api/v2/push/send",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as response:
        response.read()


async def _send_expo_push_async(tokens: List[str], title: str, body: str, data: dict) -> None:
    try:
        await asyncio.to_thread(_send_expo_push, tokens, title, body, data)
    except Exception as exc:
        print("Failed to send Expo push:", exc)


def _send_fcm_push(tokens: List[str], title: str, body: str, data: dict) -> None:
    if not tokens or not FCM_SERVER_KEY:
        return
    payload = json.dumps(
        {
            "registration_ids": tokens,
            "notification": {"title": title, "body": body},
            "data": data,
            "priority": "high",
        }
    ).encode("utf-8")
    req = urllib.request.Request(
        "https://fcm.googleapis.com/fcm/send",
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"key={FCM_SERVER_KEY}",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as response:
        response.read()


async def _send_fcm_push_async(tokens: List[str], title: str, body: str, data: dict) -> None:
    try:
        await asyncio.to_thread(_send_fcm_push, tokens, title, body, data)
    except Exception as exc:
        print("Failed to send FCM push:", exc)


# -----------------------
# Routes: Users + Auth
# -----------------------
@app.get("/users/{user_id}", response_model=UserPublic)
async def get_user(user_id: str):
    row = await _db_call(_get_user_by_id, user_id)
    if not row:
        raise HTTPException(status_code=404, detail="user not found")
    return {"id": row["id"], "name": row["name"], "email": row["email"]}


@app.get("/users/by-email/{email}", response_model=UserPublic)
async def get_user_by_email(email: EmailStr, current_user_id: str = Depends(get_current_user_id)):
    row = await _db_call(_get_user_by_email, str(email))
    if not row:
        raise HTTPException(status_code=404, detail="user not found")
    return {"id": row["id"], "name": row["name"], "email": row["email"]}


@app.post("/users/{user_id}/push-token")
async def register_push_token(
    user_id: str,
    payload: PushTokenPayload,
    current_user_id: str = Depends(get_current_user_id),
):
    if current_user_id != user_id:
        raise HTTPException(status_code=403, detail="cannot register token for another user")
    if not payload.token:
        raise HTTPException(status_code=400, detail="token required")
    await _db_call(_add_push_token, user_id, payload.token)
    return {"status": "ok"}


@app.post("/users", response_model=UserPublic)
async def create_user(payload: UserCreate):
    try:
        return await _db_call(_create_user, payload.name, str(payload.email), payload.password)
    except ValueError as e:
        if str(e) == "email_already_exists":
            raise HTTPException(status_code=409, detail="email already exists")
        raise


@app.post("/auth/login")
async def login(payload: "LoginRequest"):
    row = await _db_call(_get_user_by_email, str(payload.email))
    if not row or not _verify_password(payload.password, row["password_hash"]):
        raise HTTPException(status_code=401, detail="invalid credentials")

    token = _create_access_token(row["id"])
    return {"access_token": token, "token_type": "bearer"}

# -----------------------
# Routes: Groups
# -----------------------
@app.post("/groups", response_model=GroupPublic)
async def create_group(payload: GroupCreate, current_user_id: str = Depends(get_current_user_id)):
    group_id = payload.id or str(uuid.uuid4())
    return await _db_call(_create_group_with_owner, group_id, current_user_id, payload.name)


@app.get("/groups")
async def list_groups():
    groups = await _db_call(_list_groups)
    return {"groups": groups}

@app.get("/groups/ids")
async def list_group_ids_get(current_user_id: str = Depends(get_current_user_id)):
    groups = await _db_call(_list_group_ids)
    return {"groups": groups}

@app.post("/groups/{group_id}/requests")
async def request_to_join_group(
    group_id: str,
    current_user_id: str = Depends(get_current_user_id),
):
    if not await _db_call(_group_exists, group_id):
        raise HTTPException(status_code=404, detail="group not found")
    # prevent duplicate membership
    members = await _db_call(_list_members, group_id)
    if current_user_id in members:
        return {"status": "already_member", "group_id": group_id, "user_id": current_user_id}
    await _db_call(_create_join_request, group_id, current_user_id)
    owner_id = await _db_call(_get_group_owner_id, group_id)
    if owner_id and owner_id != current_user_id:
        tokens = await _db_call(_list_push_tokens, owner_id)
        if tokens:
            requester = await _db_call(_get_user_by_id, current_user_id)
            requester_name = requester["name"] if requester else "Uusi käyttäjä"
            title = "Liittymispyyntö"
            body = f"{requester_name} haluaa liittyä ryhmään {group_id}."
            data = {"group_id": group_id, "user_id": current_user_id}
            asyncio.create_task(_send_expo_push_async(tokens, title, body, data))
    return {"status": "requested", "group_id": group_id, "user_id": current_user_id}


@app.get("/groups/{group_id}/requests")
async def list_join_requests(
    group_id: str,
    current_user_id: str = Depends(get_current_user_id),
):
    owner_id = await _db_call(_get_group_owner_id, group_id)
    if not owner_id:
        raise HTTPException(status_code=404, detail="group not found")
    if owner_id != current_user_id:
        raise HTTPException(status_code=403, detail="only group owner can view requests")
    requests = await _db_call(_list_join_requests_with_names, group_id)
    return {"group_id": group_id, "requests": requests}


@app.post("/groups/{group_id}/requests/{user_id}/approve")
async def approve_join_request(
    group_id: str,
    user_id: str,
    current_user_id: str = Depends(get_current_user_id),
):
    owner_id = await _db_call(_get_group_owner_id, group_id)
    if not owner_id:
        raise HTTPException(status_code=404, detail="group not found")
    if owner_id != current_user_id:
        raise HTTPException(status_code=403, detail="only group owner can approve requests")
    if not await _db_call(_user_exists, user_id):
        raise HTTPException(status_code=404, detail="user not found")
    await _db_call(_add_member, group_id, user_id)
    await _db_call(_remove_join_request, group_id, user_id)
    return {"status": "approved", "group_id": group_id, "user_id": user_id}


@app.delete("/groups/{group_id}/requests/{user_id}")
async def reject_join_request(
    group_id: str,
    user_id: str,
    current_user_id: str = Depends(get_current_user_id),
):
    owner_id = await _db_call(_get_group_owner_id, group_id)
    if not owner_id:
        raise HTTPException(status_code=404, detail="group not found")
    if owner_id != current_user_id:
        raise HTTPException(status_code=403, detail="only group owner can reject requests")
    removed = await _db_call(_remove_join_request, group_id, user_id)
    if removed == 0:
        raise HTTPException(status_code=404, detail="request not found")
    return {"status": "rejected", "group_id": group_id, "user_id": user_id}


@app.post("/groups/{group_id}/members/{user_id}")
async def add_user_to_group(
    group_id: str,
    user_id: str,
    current_user_id: str = Depends(get_current_user_id),
):
    if not await _db_call(_group_exists, group_id):
        raise HTTPException(status_code=404, detail="group not found")

    owner_id = await _db_call(_get_group_owner_id, group_id)
    if not owner_id:
        # legacy group without owner: allow self-join and claim ownership
        if current_user_id == user_id:
            await _db_call(_set_group_owner, group_id, current_user_id)
            await _db_call(_add_member, group_id, user_id)
            return {"status": "ok", "group_id": group_id, "user_id": user_id}
        raise HTTPException(status_code=404, detail="group not found")

    # allow self-join, owner adds others
    is_self_join = current_user_id == user_id
    if not is_self_join and owner_id != current_user_id:
        raise HTTPException(status_code=403, detail="only group owner can add members")

    if not await _db_call(_user_exists, user_id):
        raise HTTPException(status_code=404, detail="user not found")

    await _db_call(_add_member, group_id, user_id)
    return {"status": "ok", "group_id": group_id, "user_id": user_id}


@app.delete("/groups/{group_id}/members/{user_id}")
async def remove_user_from_group(
    group_id: str,
    user_id: str,
    current_user_id: str = Depends(get_current_user_id),
):
    if not await _db_call(_group_exists, group_id):
        raise HTTPException(status_code=404, detail="group not found")

    owner_id = await _db_call(_get_group_owner_id, group_id)
    if not owner_id:
        raise HTTPException(status_code=404, detail="group not found")

    # allow self-leave, owner removes others
    is_self_leave = current_user_id == user_id
    if not is_self_leave and owner_id != current_user_id:
        raise HTTPException(status_code=403, detail="only group owner can remove members")

    # prevent owner leaving if others still exist
    if is_self_leave and user_id == owner_id:
        member_count = await _db_call(_count_members, group_id)
        if member_count > 1:
            raise HTTPException(status_code=400, detail="owner cannot leave while other members exist")

    removed = await _db_call(_remove_member, group_id, user_id)
    if removed == 0:
        raise HTTPException(status_code=404, detail="membership not found")

    # delete group if no members left
    remaining = await _db_call(_count_members, group_id)
    if remaining == 0:
        with _get_conn() as conn:
            conn.execute("DELETE FROM groups WHERE id = ?", (group_id,))
        return {"status": "deleted", "group_id": group_id, "user_id": user_id}

    return {"status": "ok", "group_id": group_id, "user_id": user_id}


@app.get("/groups/{group_id}/members")
async def list_group_members(
    group_id: str,
    with_names: bool = False,
    current_user_id: str = Depends(get_current_user_id),
):
    if not await _db_call(_group_exists, group_id):
        raise HTTPException(status_code=404, detail="group not found")
    if not await _db_call(_is_member, group_id, current_user_id):
        raise HTTPException(status_code=403, detail="not a member of this group")

    if with_names:
        members = await _db_call(_list_members_with_names, group_id)
        return {"group_id": group_id, "members": members}

    members = await _db_call(_list_members, group_id)
    return {"group_id": group_id, "members": members}


@app.get("/groups/{group_id}/messages", response_model=List[ChatMessagePublic])
async def list_group_messages(
    group_id: str,
    limit: int = 50,
    before: Optional[float] = None,
    current_user_id: str = Depends(get_current_user_id),
):
    if not await _db_call(_group_exists, group_id):
        raise HTTPException(status_code=404, detail="group not found")
    if not await _db_call(_is_member, group_id, current_user_id):
        raise HTTPException(status_code=403, detail="not a member of this group")
    limit = max(1, min(200, limit))
    messages = await _db_call(_list_group_messages, group_id, limit, before)
    return messages


@app.post("/groups/{group_id}/messages", response_model=ChatMessagePublic)
async def create_group_message(
    group_id: str,
    payload: ChatMessageCreate,
    current_user_id: str = Depends(get_current_user_id),
):
    if not await _db_call(_group_exists, group_id):
        raise HTTPException(status_code=404, detail="group not found")
    if not await _db_call(_is_member, group_id, current_user_id):
        raise HTTPException(status_code=403, detail="not a member of this group")
    body = payload.body.strip()
    if not body:
        raise HTTPException(status_code=400, detail="message body required")
    message = await _db_call(_add_group_message, group_id, current_user_id, body)
    if FCM_SERVER_KEY:
        member_ids = await _db_call(_list_members, group_id)
        target_ids = [uid for uid in member_ids if uid != current_user_id]
        tokens: List[str] = []
        for uid in target_ids:
            tokens.extend(await _db_call(_list_push_tokens, uid))
        if tokens:
            deduped = list(dict.fromkeys(tokens))
            title = message["username"]
            body_preview = message["body"][:160]
            data = {
                "group_id": group_id,
                "sender_id": current_user_id,
                "message_id": str(message["id"]),
                "body": message["body"],
            }
            asyncio.create_task(_send_fcm_push_async(deduped, title, body_preview, data))
    return message


@app.put("/users/{user_id}/sharing/groups/{group_id}")
async def set_group_sharing(user_id: str, group_id: str, payload: ShareUpdate):
    if not await _db_call(_user_exists, user_id):
        raise HTTPException(status_code=404, detail="user not found")
    if not await _db_call(_group_exists, group_id):
        raise HTTPException(status_code=404, detail="group not found")

    try:
        await _db_call(_set_group_sharing, user_id, group_id, payload.enabled)
    except ValueError as e:
        if str(e) == "not_a_member":
            raise HTTPException(status_code=403, detail="user is not a member of this group")
        raise

    return {"status": "ok", "user_id": user_id, "group_id": group_id, "enabled": payload.enabled}


@app.get("/groups/{group_id}/locations", response_model=List[UserLocation])
async def get_group_locations(group_id: str):
    try:
        if not await _db_call(_group_exists, group_id):
            raise HTTPException(status_code=404, detail="group not found")

        allowed_ids = set(await _db_call(_get_share_enabled_member_ids, group_id))
        # Only return users who are both allowed AND currently have a live location in memory
        return [loc for uid, loc in user_store.items() if uid in allowed_ids]
    except Exception as exc:
        print(f"ERROR in /groups/{group_id}/locations:", exc)
        raise HTTPException(status_code=500, detail=str(exc))


# -----------------------
# CORS
# -----------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------
# User Location Tracking
# -----------------------
user_store: Dict[str, UserLocation] = {}


@app.post("/update-location")
async def update_location(location: UserLocation):
    location.last_seen = time.time()
    user_store[location.user_id] = location
    print(f"📍 Location update: {location.username} ({location.user_id}) -> {location.lat}, {location.lon}")
    return {"status": "ok"}


# -----------------------
# Startup Event: init DB + cleanup
# -----------------------
@app.on_event("startup")
async def startup_event():
    await _db_call(_init_db)

    async def cleanup_inactive_users():
        while True:
            await asyncio.sleep(10)
            now = time.time()
            removed = [uid for uid, loc in user_store.items() if now - loc.last_seen > 300]
            for uid in removed:
                user = user_store.pop(uid)
                print(f"🗑️ Removed inactive user: {user.username} ({uid})")

    asyncio.create_task(cleanup_inactive_users())


# -----------------------
# Serve HTML
# -----------------------
@app.get("/", response_class=HTMLResponse)
async def read_root():
    return Path("src/map.html").read_text()


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5656)
