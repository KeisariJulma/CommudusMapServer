from fastapi import FastAPI, HTTPException, Depends, Request, UploadFile
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr
from typing import Dict, List, Optional
import uvicorn
import time
import asyncio
from pathlib import Path
import sqlite3
import uuid
import shutil
import os
import base64
import hashlib
import hmac
import json
import math
import secrets
import smtplib
import urllib.request
import urllib.parse
import urllib.error
from email.message import EmailMessage

from jose import jwt, JWTError
import firebase_admin
from firebase_admin import credentials as firebase_credentials
from firebase_admin import messaging as firebase_messaging

app = FastAPI()
DB_PATH = "app.db"
UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
MML_API_KEY = os.environ.get("MML_API_KEY", "6ca6d0d1-33bb-4cf4-8840-f6da4874929d")
app.mount("/uploads", StaticFiles(directory=str(UPLOAD_DIR)), name="uploads")

JWT_SECRET = os.environ.get("JWT_SECRET")  # set this in your shell
JWT_ALGORITHM = "HS256"
JWT_EXPIRES_SECONDS = 60 * 60 * 24 * 365 * 10   # 7 days
PASSWORD_RESET_EXPIRES_SECONDS = int(os.environ.get("PASSWORD_RESET_EXPIRES_SECONDS", "3600"))
PUBLIC_APP_URL = os.environ.get("PUBLIC_APP_URL", "https://exclusionzone.org")
SMTP_HOST = os.environ.get("SMTP_HOST")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USERNAME = os.environ.get("SMTP_USERNAME")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD")
SMTP_FROM = os.environ.get("SMTP_FROM", SMTP_USERNAME or "no-reply@exclusionzone.org")
FIREBASE_WEB_API_KEY = os.environ.get("FIREBASE_WEB_API_KEY")
FIREBASE_PASSWORD_RESET_CONTINUE_URL = os.environ.get("FIREBASE_PASSWORD_RESET_CONTINUE_URL")
FIREBASE_PASSWORD_RESET_ANDROID_PACKAGE_NAME = os.environ.get(
    "FIREBASE_PASSWORD_RESET_ANDROID_PACKAGE_NAME"
)
FIREBASE_PASSWORD_RESET_IOS_BUNDLE_ID = os.environ.get("FIREBASE_PASSWORD_RESET_IOS_BUNDLE_ID")
FCM_SERVICE_ACCOUNT_FILE = os.environ.get("FCM_SERVICE_ACCOUNT_FILE") or os.environ.get(
    "GOOGLE_APPLICATION_CREDENTIALS"
)
_fcm_app = None

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


def _parse_optional_float(value: object) -> Optional[float]:
    if value is None:
        return None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    if isinstance(value, str):
        cleaned = value.strip()
        if not cleaned:
            return None
        try:
            return float(cleaned)
        except ValueError:
            return None
    return None


def _parse_finite_number(value: object) -> Optional[float]:
    number_value = _parse_optional_float(value)
    if number_value is None:
        return None
    if not math.isfinite(number_value):
        return None
    return number_value


def _parse_passipaikka_coords(value: Dict[str, object]) -> Optional[tuple[float, float]]:
    coords = value.get("coords")
    if isinstance(coords, list) and len(coords) >= 2:
        lon = _parse_finite_number(coords[0])
        lat = _parse_finite_number(coords[1])
        if lon is not None and lat is not None:
            return lon, lat

    coordinates = value.get("coordinates")
    if isinstance(coordinates, list) and len(coordinates) >= 2:
        lon = _parse_finite_number(coordinates[0])
        lat = _parse_finite_number(coordinates[1])
        if lon is not None and lat is not None:
            return lon, lat

    lat_value = value.get("lat")
    if lat_value is None:
        lat_value = value.get("latitude")
    lon_value = value.get("lon")
    if lon_value is None:
        lon_value = value.get("lng")
    if lon_value is None:
        lon_value = value.get("longitude")
    lat = _parse_finite_number(lat_value)
    lon = _parse_finite_number(lon_value)
    if lat is None or lon is None:
        return None
    return lon, lat


def _normalize_passipaikka_payload(value: object, index: int) -> Optional[dict]:
    if not isinstance(value, dict):
        return None
    coords = _parse_passipaikka_coords(value)
    if coords is None:
        return None

    raw_number = value.get("number")
    if raw_number is None:
        raw_number = value.get("numero")
    if raw_number is None:
        raw_number = value.get("label")
    number_value = _parse_finite_number(raw_number)
    lon, lat = coords
    return {
        "id": str(value.get("id") or value.get("passipaikka_id") or f"passipaikka-{index + 1}"),
        "number": int(number_value) if number_value is not None else index + 1,
        "lon": lon,
        "lat": lat,
        "position": index,
    }


def _extract_passipaikat_payload(value: object) -> List[dict]:
    if isinstance(value, dict):
        raw_points = value.get("points")
        if not isinstance(raw_points, list):
            raw_points = value.get("passipaikat")
        if not isinstance(raw_points, list):
            raw_points = value.get("stands")
        if not isinstance(raw_points, list):
            lists = value.get("lists") or value.get("passipaikka_lists")
            if isinstance(lists, list) and lists:
                first_list = lists[0]
                if isinstance(first_list, dict):
                    raw_points = first_list.get("points")
                    if not isinstance(raw_points, list):
                        raw_points = first_list.get("passipaikat")
                    if not isinstance(raw_points, list):
                        raw_points = first_list.get("stands")
                else:
                    raw_points = []
        if not isinstance(raw_points, list):
            raw_points = []
    elif isinstance(value, list):
        raw_points = value
    else:
        raw_points = []

    points = []
    seen_ids = set()
    for index, raw_point in enumerate(raw_points):
        point = _normalize_passipaikka_payload(raw_point, index)
        if not point or point["id"] in seen_ids:
            continue
        seen_ids.add(point["id"])
        points.append(point)
    return points


def _parse_coordinate_pair(value: object) -> Optional[List[float]]:
    if not isinstance(value, list) or len(value) < 2:
        return None
    lon = _parse_finite_number(value[0])
    lat = _parse_finite_number(value[1])
    if lon is None or lat is None:
        return None
    return [lon, lat]


def _normalize_passi_line_payload(value: object, index: int) -> Optional[dict]:
    if not isinstance(value, dict):
        return None
    raw_coordinates = value.get("coordinates")
    if not isinstance(raw_coordinates, list):
        raw_coordinates = []
    coordinates = [
        coordinate
        for raw_coordinate in raw_coordinates
        if (coordinate := _parse_coordinate_pair(raw_coordinate)) is not None
    ]
    if not coordinates:
        return None
    raw_created_at = value.get("createdAt")
    if raw_created_at is None:
        raw_created_at = value.get("created_at")
    created_at = _parse_finite_number(raw_created_at)
    return {
        "id": str(value.get("id") or f"passi-line-{index + 1}"),
        "name": str(value.get("name") or f"Linja {index + 1}"),
        "coordinates": coordinates,
        "createdAt": int(created_at) if created_at is not None else int(time.time() * 1000),
        "position": index,
    }


def _normalize_passi_ajo_group_payload(value: object, index: int) -> Optional[dict]:
    if not isinstance(value, dict):
        return None
    raw_lines = value.get("lines")
    if not isinstance(raw_lines, list):
        raw_lines = []
    lines = []
    seen_line_ids = set()
    for line_index, raw_line in enumerate(raw_lines):
        line = _normalize_passi_line_payload(raw_line, line_index)
        if not line or line["id"] in seen_line_ids:
            continue
        seen_line_ids.add(line["id"])
        lines.append(line)
    raw_created_at = value.get("createdAt")
    if raw_created_at is None:
        raw_created_at = value.get("created_at")
    created_at = _parse_finite_number(raw_created_at)
    return {
        "id": str(value.get("id") or f"passi-ajo-group-{index + 1}"),
        "name": str(value.get("name") or f"Passiajo {index + 1}"),
        "lines": lines,
        "createdAt": int(created_at) if created_at is not None else int(time.time() * 1000),
        "position": index,
    }


def _extract_passi_ajo_groups_payload(value: object) -> List[dict]:
    if isinstance(value, dict):
        raw_groups = value.get("groups")
        if not isinstance(raw_groups, list):
            raw_groups = value.get("passi_ajo_groups")
        if not isinstance(raw_groups, list):
            raw_groups = value.get("passiAjoGroups")
        if not isinstance(raw_groups, list):
            raw_groups = []
    elif isinstance(value, list):
        raw_groups = value
    else:
        raw_groups = []

    groups = []
    seen_ids = set()
    for index, raw_group in enumerate(raw_groups):
        group = _normalize_passi_ajo_group_payload(raw_group, index)
        if not group or group["id"] in seen_ids:
            continue
        seen_ids.add(group["id"])
        groups.append(group)
    return groups


def _normalize_phone(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    trimmed = value.strip()
    if not trimmed:
        return None
    cleaned = "".join(ch for ch in trimmed if (ch.isdigit() or ch == "+"))
    if not any(ch.isdigit() for ch in cleaned):
        return None
    if cleaned.count("+") > 1:
        cleaned = cleaned.replace("+", "")
        cleaned = f"+{cleaned}" if cleaned else ""
    if "+" in cleaned and not cleaned.startswith("+"):
        cleaned = cleaned.replace("+", "")
    return cleaned or None


UNSET = object()


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
    except JWTError as e:
        print("JWT error:", e)
        raise HTTPException(status_code=401, detail="invalid token")


def _build_raster_style(tile_url: str, name: str) -> Dict[str, object]:
    return {
        "version": 8,
        "name": name,
        "glyphs": "https://demotiles.maplibre.org/font/{fontstack}/{range}.pbf",
        "sources": {
            "raster-tiles": {
                "type": "raster",
                "tiles": [tile_url],
                "tileSize": 256,
                "minzoom": 0,
                "maxzoom": 19,
            }
        },
        "layers": [
            {
                "id": "raster-tiles-layer",
                "type": "raster",
                "source": "raster-tiles",
            }
        ],
    }


@app.get("/map-styles/{style_name}.json")
def get_map_style(style_name: str) -> Dict[str, object]:
    style = style_name.lower()
    if style == "mml":
        tile_url = (
            "https://avoin-karttakuva.maanmittauslaitos.fi/avoin/wmts/1.0.0/"
            f"maastokartta/default/WGS84_Pseudo-Mercator/{{z}}/{{y}}/{{x}}.png?api-key={MML_API_KEY}"
        )
        return _build_raster_style(tile_url, "commudus-mml")
    if style == "satellite":
        tile_url = (
            "https://services.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}"
        )
        return _build_raster_style(tile_url, "commudus-satellite")
    if style == "osm":
        tile_url = "https://tile.openstreetmap.org/{z}/{x}/{y}.png"
        return _build_raster_style(tile_url, "commudus-osm")
    raise HTTPException(status_code=404, detail="unknown style")

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
              email TEXT UNIQUE,
              phone TEXT,
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

            CREATE TABLE IF NOT EXISTS password_reset_tokens (
              id TEXT PRIMARY KEY,
              user_id TEXT NOT NULL,
              token_hash TEXT NOT NULL UNIQUE,
              expires_at REAL NOT NULL,
              used_at REAL,
              created_at REAL NOT NULL,
              FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS group_messages (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              group_id TEXT NOT NULL,
              user_id TEXT NOT NULL,
              body TEXT NOT NULL,
              image_path TEXT,
              image_lat REAL,
              image_lon REAL,
              image_accuracy REAL,
              image_timestamp REAL,
              created_at REAL NOT NULL,
              FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE,
              FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS group_message_receipts (
              message_id INTEGER NOT NULL,
              user_id TEXT NOT NULL,
              delivered_at REAL NOT NULL,
              read_at REAL,
              PRIMARY KEY (message_id, user_id),
              FOREIGN KEY (message_id) REFERENCES group_messages(id) ON DELETE CASCADE,
              FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS group_passipaikat (
              group_id TEXT NOT NULL,
              id TEXT NOT NULL,
              number INTEGER NOT NULL,
              lon REAL NOT NULL,
              lat REAL NOT NULL,
              position INTEGER NOT NULL,
              PRIMARY KEY (group_id, id),
              FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS group_passi_ajo_groups (
              group_id TEXT NOT NULL,
              id TEXT NOT NULL,
              name TEXT NOT NULL,
              created_at INTEGER NOT NULL,
              position INTEGER NOT NULL,
              PRIMARY KEY (group_id, id),
              FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS group_passi_ajo_lines (
              group_id TEXT NOT NULL,
              ajo_group_id TEXT NOT NULL,
              id TEXT NOT NULL,
              name TEXT NOT NULL,
              coordinates_json TEXT NOT NULL,
              created_at INTEGER NOT NULL,
              position INTEGER NOT NULL,
              PRIMARY KEY (group_id, ajo_group_id, id),
              FOREIGN KEY (group_id, ajo_group_id)
                REFERENCES group_passi_ajo_groups(group_id, id) ON DELETE CASCADE
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

        # Migration: add phone to users
        try:
            conn.execute("ALTER TABLE users ADD COLUMN phone TEXT")
        except sqlite3.OperationalError:
            # column already exists
            pass

        # Migration: allow NULL email and ensure unique phone
        try:
            columns = conn.execute("PRAGMA table_info(users)").fetchall()
            email_notnull = next((col["notnull"] for col in columns if col["name"] == "email"), 0)
            if email_notnull:
                conn.execute("PRAGMA foreign_keys = OFF")
                try:
                    conn.execute(
                        "CREATE TABLE users_new ("
                        "id TEXT PRIMARY KEY, "
                        "name TEXT NOT NULL, "
                        "email TEXT UNIQUE, "
                        "phone TEXT UNIQUE, "
                        "password_hash TEXT NOT NULL, "
                        "created_at REAL NOT NULL)"
                    )
                    conn.execute(
                        "INSERT INTO users_new(id, name, email, phone, password_hash, created_at) "
                        "SELECT id, name, email, phone, password_hash, created_at FROM users"
                    )
                    conn.execute("DROP TABLE users")
                    conn.execute("ALTER TABLE users_new RENAME TO users")
                finally:
                    conn.execute("PRAGMA foreign_keys = ON")
            else:
                try:
                    conn.execute("CREATE UNIQUE INDEX idx_users_phone ON users(phone)")
                except sqlite3.OperationalError:
                    pass
        except sqlite3.OperationalError:
            pass
        # Migration: add image_path to group_messages
        try:
            conn.execute("ALTER TABLE group_messages ADD COLUMN image_path TEXT")
        except sqlite3.OperationalError:
            # column already exists
            pass
        # Migration: add image location columns to group_messages
        for stmt in (
            "ALTER TABLE group_messages ADD COLUMN image_lat REAL",
            "ALTER TABLE group_messages ADD COLUMN image_lon REAL",
            "ALTER TABLE group_messages ADD COLUMN image_accuracy REAL",
            "ALTER TABLE group_messages ADD COLUMN image_timestamp REAL",
        ):
            try:
                conn.execute(stmt)
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

        try:
            conn.execute(
                "CREATE INDEX idx_group_message_receipts_user ON group_message_receipts(user_id)"
            )
        except sqlite3.OperationalError:
            # index already exists
            pass

        try:
            conn.execute(
                "CREATE INDEX idx_group_message_receipts_message ON group_message_receipts(message_id)"
            )
        except sqlite3.OperationalError:
            # index already exists
            pass

        try:
            conn.execute(
                "CREATE INDEX idx_password_reset_tokens_user ON password_reset_tokens(user_id)"
            )
        except sqlite3.OperationalError:
            # index already exists
            pass

        try:
            conn.execute(
                "CREATE INDEX idx_group_passipaikat_group_position ON group_passipaikat(group_id, position)"
            )
        except sqlite3.OperationalError:
            # index already exists
            pass

        try:
            conn.execute(
                "CREATE INDEX idx_group_passi_ajo_groups_group_position ON group_passi_ajo_groups(group_id, position)"
            )
        except sqlite3.OperationalError:
            # index already exists
            pass

        try:
            conn.execute(
                "CREATE INDEX idx_group_passi_ajo_lines_group_position ON group_passi_ajo_lines(group_id, ajo_group_id, position)"
            )
        except sqlite3.OperationalError:
            # index already exists
            pass

        _purge_empty_groups()


def _build_image_url(image_path: Optional[str]) -> Optional[str]:
    if not image_path:
        return None
    return f"/uploads/{image_path}"


_IMAGE_EXTENSIONS = {
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".webp",
    ".heic",
    ".heif",
}


def _normalize_image_extension(filename: str, content_type: Optional[str]) -> str:
    ext = Path(filename or "").suffix.lower()
    if ext in _IMAGE_EXTENSIONS:
        return ext
    if content_type:
        mapping = {
            "image/jpeg": ".jpg",
            "image/png": ".png",
            "image/gif": ".gif",
            "image/webp": ".webp",
            "image/heic": ".heic",
            "image/heif": ".heif",
        }
        mapped = mapping.get(content_type.lower())
        if mapped:
            return mapped
    return ".jpg"


def _save_uploaded_image(upload: UploadFile) -> str:
    ext = _normalize_image_extension(upload.filename or "", upload.content_type)
    filename = f"{uuid.uuid4().hex}{ext}"
    destination = UPLOAD_DIR / filename
    try:
        upload.file.seek(0)
    except Exception:
        pass
    with destination.open("wb") as out:
        shutil.copyfileobj(upload.file, out)
    return filename


async def _db_call(fn, *args, **kwargs):
    return await asyncio.to_thread(fn, *args, **kwargs)


# -----------------------
# Models
# -----------------------
class UserCreate(BaseModel):
    name: str
    email: Optional[EmailStr] = None
    password: str
    phone: Optional[str] = None


class UserPublic(BaseModel):
    id: str
    name: str
    email: Optional[EmailStr] = None
    phone: Optional[str] = None


class UserPhoneUpdate(BaseModel):
    phone: Optional[str] = None


class UserUpdate(BaseModel):
    name: Optional[str] = None
    email: Optional[EmailStr] = None
    phone: Optional[str] = None


class LoginRequest(BaseModel):
    identifier: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    password: str


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class PasswordResetRequest(BaseModel):
    token: str
    new_password: str


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


class PassipaikkaPublic(BaseModel):
    id: str
    number: int
    coords: List[float]


class PassipaikkaListPublic(BaseModel):
    id: str
    name: str
    points: List[PassipaikkaPublic]


class PassiLinePublic(BaseModel):
    id: str
    name: str
    coordinates: List[List[float]]
    createdAt: int


class PassiAjoGroupPublic(BaseModel):
    id: str
    name: str
    lines: List[PassiLinePublic]
    createdAt: int


class ShareUpdate(BaseModel):
    enabled: bool


class PushTokenPayload(BaseModel):
    token: str


class ChatMessageCreate(BaseModel):
    body: Optional[str] = None


class ChatMessagePublic(BaseModel):
    id: int
    group_id: str
    user_id: str
    username: str
    body: str
    created_at: float
    image_url: Optional[str] = None
    image_lat: Optional[float] = None
    image_lon: Optional[float] = None
    image_accuracy: Optional[float] = None
    image_timestamp: Optional[float] = None
    delivered_count: int = 0
    read_count: int = 0
    recipient_count: int = 0


class MessageReceiptUser(BaseModel):
    id: str
    name: str
    read_at: Optional[float] = None


class MessageReceiptSummary(BaseModel):
    group_id: str
    message_id: int
    read_by: List[MessageReceiptUser]
    unread_by: List[MessageReceiptUser]


# -----------------------
# User CRUD
# -----------------------
def _create_user(
    name: str,
    email: Optional[str],
    password: str,
    phone: Optional[str] = None,
) -> UserPublic:
    user_id = str(uuid.uuid4())
    password_hash = _hash_password(password)
    now = time.time()
    try:
        with _get_conn() as conn:
            conn.execute(
                "INSERT INTO users(id, name, email, phone, password_hash, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (user_id, name, email, phone, password_hash, now),
            )
    except sqlite3.IntegrityError:
        raise ValueError("email_or_phone_exists")
    return UserPublic(id=user_id, name=name, email=email, phone=phone)


def _get_user_by_email(email: str) -> Optional[sqlite3.Row]:
    with _get_conn() as conn:
        return conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()


def _hash_reset_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _create_password_reset_token(email: str) -> Optional[str]:
    row = _get_user_by_email(email)
    if not row:
        return None

    token = secrets.token_urlsafe(32)
    token_hash = _hash_reset_token(token)
    now = time.time()
    expires_at = now + PASSWORD_RESET_EXPIRES_SECONDS
    with _get_conn() as conn:
        conn.execute(
            "UPDATE password_reset_tokens SET used_at = ? WHERE user_id = ? AND used_at IS NULL",
            (now, row["id"]),
        )
        conn.execute(
            """
            INSERT INTO password_reset_tokens(id, user_id, token_hash, expires_at, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (str(uuid.uuid4()), row["id"], token_hash, expires_at, now),
        )
    return token


def _build_password_reset_url(token: str) -> str:
    encoded_token = urllib.parse.quote(token, safe="")
    return f"{PUBLIC_APP_URL.rstrip('/')}/reset-password?token={encoded_token}"


def _send_password_reset_email(email: str, token: str) -> None:
    reset_url = _build_password_reset_url(token)
    if not SMTP_HOST:
        raise RuntimeError("SMTP_HOST is not set")

    message = EmailMessage()
    message["Subject"] = "Reset your Commudus password"
    message["From"] = SMTP_FROM
    message["To"] = email
    message.set_content(
        "Use this link to reset your password. "
        f"It expires in {PASSWORD_RESET_EXPIRES_SECONDS // 60} minutes.\n\n{reset_url}\n"
    )

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as smtp:
            smtp.starttls()
            if SMTP_USERNAME and SMTP_PASSWORD:
                smtp.login(SMTP_USERNAME, SMTP_PASSWORD)
            smtp.send_message(message)
    except (OSError, smtplib.SMTPException) as e:
        raise RuntimeError(f"SMTP password reset email failed: {e}") from e


def _send_firebase_password_reset_email(email: str) -> str:
    if not FIREBASE_WEB_API_KEY:
        raise RuntimeError("FIREBASE_WEB_API_KEY is not set")

    request_payload: Dict[str, object] = {
        "requestType": "PASSWORD_RESET",
        "email": email,
    }
    if FIREBASE_PASSWORD_RESET_CONTINUE_URL:
        request_payload["continueUrl"] = FIREBASE_PASSWORD_RESET_CONTINUE_URL
    if FIREBASE_PASSWORD_RESET_ANDROID_PACKAGE_NAME:
        request_payload["androidPackageName"] = FIREBASE_PASSWORD_RESET_ANDROID_PACKAGE_NAME
    if FIREBASE_PASSWORD_RESET_IOS_BUNDLE_ID:
        request_payload["iOSBundleId"] = FIREBASE_PASSWORD_RESET_IOS_BUNDLE_ID

    request = urllib.request.Request(
        "https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode"
        f"?key={urllib.parse.quote(FIREBASE_WEB_API_KEY, safe='')}",
        data=json.dumps(request_payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            response.read()
            return "sent"
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8", errors="replace")
        try:
            error_code = json.loads(error_body)["error"]["message"]
        except (KeyError, json.JSONDecodeError, TypeError):
            error_code = error_body or str(e)
        if error_code == "EMAIL_NOT_FOUND":
            return "email_not_found"
        raise RuntimeError(f"Firebase password reset failed: {error_code}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"Firebase password reset request failed: {e.reason}") from e


def _reset_password_with_token(token: str, new_password: str) -> bool:
    token_hash = _hash_reset_token(token)
    password_hash = _hash_password(new_password)
    now = time.time()
    with _get_conn() as conn:
        row = conn.execute(
            """
            SELECT id, user_id FROM password_reset_tokens
            WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?
            """,
            (token_hash, now),
        ).fetchone()
        if not row:
            return False

        cursor = conn.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (password_hash, row["user_id"]),
        )
        conn.execute(
            "UPDATE password_reset_tokens SET used_at = ? WHERE id = ?",
            (now, row["id"]),
        )
        return cursor.rowcount > 0



def _get_user_by_phone(phone: str) -> Optional[sqlite3.Row]:
    with _get_conn() as conn:
        return conn.execute("SELECT * FROM users WHERE phone = ?", (phone,)).fetchone()


def _get_user_by_id(user_id: str) -> Optional[sqlite3.Row]:
    with _get_conn() as conn:
        return conn.execute("SELECT id, name, email, phone FROM users WHERE id = ?", (user_id,)).fetchone()


def _update_user_phone(user_id: str, phone: Optional[str]) -> Optional[sqlite3.Row]:
    return _update_user(user_id, UNSET, UNSET, phone)



def _update_user(
    user_id: str,
    name: object,
    email: object,
    phone: object,
) -> Optional[sqlite3.Row]:
    with _get_conn() as conn:
        row = conn.execute("SELECT id, name, email, phone FROM users WHERE id = ?", (user_id,)).fetchone()
        if not row:
            return None
        next_name = row["name"] if name is UNSET else name
        next_email = row["email"] if email is UNSET else email
        next_phone = row["phone"] if phone is UNSET else phone
        if name is not UNSET and next_name is None:
            return None
        if email is not UNSET and next_email is not None:
            existing = conn.execute(
                "SELECT id FROM users WHERE email = ? AND id != ?",
                (next_email, user_id),
            ).fetchone()
            if existing:
                raise ValueError("email_already_exists")
        if phone is not UNSET and next_phone is not None:
            existing = conn.execute(
                "SELECT id FROM users WHERE phone = ? AND id != ?",
                (next_phone, user_id),
            ).fetchone()
            if existing:
                raise ValueError("phone_already_exists")
        try:
            conn.execute(
                "UPDATE users SET name = ?, email = ?, phone = ? WHERE id = ?",
                (next_name, next_email, next_phone, user_id),
            )
        except sqlite3.IntegrityError:
            raise ValueError("email_or_phone_exists")
        return conn.execute("SELECT id, name, email, phone FROM users WHERE id = ?", (user_id,)).fetchone()


def _delete_user(user_id: str) -> bool:
    with _get_conn() as conn:
        cursor = conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        return cursor.rowcount > 0


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


def _get_group_name(group_id: str) -> Optional[str]:
    with _get_conn() as conn:
        row = conn.execute("SELECT name FROM groups WHERE id = ?", (group_id,)).fetchone()
        if not row:
            return None
        return row["name"]

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


def _format_passipaikka_list(group_id: str, group_name: Optional[str], rows: List[sqlite3.Row]) -> dict:
    return {
        "id": group_id,
        "name": group_name or "Passipaikat",
        "points": [
            {
                "id": r["id"],
                "number": int(r["number"]),
                "coords": [float(r["lon"]), float(r["lat"])],
            }
            for r in rows
        ],
    }


def _get_group_passipaikka_list(group_id: str) -> dict:
    with _get_conn() as conn:
        group = conn.execute("SELECT id, name FROM groups WHERE id = ?", (group_id,)).fetchone()
        if not group:
            raise ValueError("group_not_found")
        rows = conn.execute(
            """
            SELECT id, number, lon, lat
            FROM group_passipaikat
            WHERE group_id = ?
            ORDER BY position, number, id
            """,
            (group_id,),
        ).fetchall()
        return _format_passipaikka_list(group["id"], group["name"], rows)


def _replace_group_passipaikat(group_id: str, points: List[dict]) -> dict:
    with _get_conn() as conn:
        group = conn.execute("SELECT id, name FROM groups WHERE id = ?", (group_id,)).fetchone()
        if not group:
            raise ValueError("group_not_found")
        conn.execute("DELETE FROM group_passipaikat WHERE group_id = ?", (group_id,))
        conn.executemany(
            """
            INSERT INTO group_passipaikat(group_id, id, number, lon, lat, position)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    group_id,
                    point["id"],
                    point["number"],
                    point["lon"],
                    point["lat"],
                    point["position"],
                )
                for point in points
            ],
        )
        rows = conn.execute(
            """
            SELECT id, number, lon, lat
            FROM group_passipaikat
            WHERE group_id = ?
            ORDER BY position, number, id
            """,
            (group_id,),
        ).fetchall()
        return _format_passipaikka_list(group["id"], group["name"], rows)


def _list_group_passi_ajo_groups(group_id: str) -> List[dict]:
    with _get_conn() as conn:
        if not conn.execute("SELECT 1 FROM groups WHERE id = ?", (group_id,)).fetchone():
            raise ValueError("group_not_found")
        group_rows = conn.execute(
            """
            SELECT id, name, created_at
            FROM group_passi_ajo_groups
            WHERE group_id = ?
            ORDER BY position, created_at, id
            """,
            (group_id,),
        ).fetchall()
        line_rows = conn.execute(
            """
            SELECT ajo_group_id, id, name, coordinates_json, created_at
            FROM group_passi_ajo_lines
            WHERE group_id = ?
            ORDER BY ajo_group_id, position, created_at, id
            """,
            (group_id,),
        ).fetchall()

    lines_by_group: Dict[str, List[dict]] = {}
    for row in line_rows:
        try:
            coordinates = json.loads(row["coordinates_json"])
        except json.JSONDecodeError:
            coordinates = []
        lines_by_group.setdefault(row["ajo_group_id"], []).append(
            {
                "id": row["id"],
                "name": row["name"],
                "coordinates": coordinates if isinstance(coordinates, list) else [],
                "createdAt": int(row["created_at"]),
            }
        )

    return [
        {
            "id": row["id"],
            "name": row["name"],
            "lines": lines_by_group.get(row["id"], []),
            "createdAt": int(row["created_at"]),
        }
        for row in group_rows
    ]


def _replace_group_passi_ajo_groups(group_id: str, groups: List[dict]) -> List[dict]:
    with _get_conn() as conn:
        if not conn.execute("SELECT 1 FROM groups WHERE id = ?", (group_id,)).fetchone():
            raise ValueError("group_not_found")
        conn.execute("DELETE FROM group_passi_ajo_groups WHERE group_id = ?", (group_id,))
        for group in groups:
            conn.execute(
                """
                INSERT INTO group_passi_ajo_groups(group_id, id, name, created_at, position)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    group_id,
                    group["id"],
                    group["name"],
                    group["createdAt"],
                    group["position"],
                ),
            )
            conn.executemany(
                """
                INSERT INTO group_passi_ajo_lines(
                    group_id,
                    ajo_group_id,
                    id,
                    name,
                    coordinates_json,
                    created_at,
                    position
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        group_id,
                        group["id"],
                        line["id"],
                        line["name"],
                        json.dumps(line["coordinates"], separators=(",", ":")),
                        line["createdAt"],
                        line["position"],
                    )
                    for line in group["lines"]
                ],
            )
    return _list_group_passi_ajo_groups(group_id)


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
        conn.execute("DELETE FROM user_push_tokens WHERE user_id = ?", (user_id,))
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
                SELECT gm.id, gm.group_id, gm.user_id, u.name AS username, gm.body, gm.image_path,
                       gm.image_lat, gm.image_lon, gm.image_accuracy, gm.image_timestamp, gm.created_at
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
                SELECT gm.id, gm.group_id, gm.user_id, u.name AS username, gm.body, gm.image_path,
                       gm.image_lat, gm.image_lon, gm.image_accuracy, gm.image_timestamp, gm.created_at
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
                "image_path": r["image_path"],
                "image_lat": r["image_lat"],
                "image_lon": r["image_lon"],
                "image_accuracy": r["image_accuracy"],
                "image_timestamp": r["image_timestamp"],
                "created_at": r["created_at"],
            }
            for r in rows
        ]
        return list(reversed(messages))


def _list_group_message_image_paths(group_id: str) -> List[str]:
    with _get_conn() as conn:
        rows = conn.execute(
            """
            SELECT image_path
            FROM group_messages
            WHERE group_id = ? AND image_path IS NOT NULL
            """,
            (group_id,),
        ).fetchall()
        return [r["image_path"] for r in rows if r["image_path"]]


def _delete_group_uploads(group_id: str) -> None:
    image_paths = _list_group_message_image_paths(group_id)
    for image_path in image_paths:
        try:
            (UPLOAD_DIR / image_path).unlink()
        except FileNotFoundError:
            pass
        except Exception as exc:
            print("Failed to delete upload", image_path, exc)


def _purge_empty_groups() -> None:
    with _get_conn() as conn:
        rows = conn.execute(
            """
            SELECT g.id AS id
            FROM groups g
            LEFT JOIN group_members gm ON gm.group_id = g.id
            GROUP BY g.id
            HAVING COUNT(gm.user_id) = 0
            """
        ).fetchall()
        empty_ids = [row["id"] for row in rows]
    for group_id in empty_ids:
        _delete_group_uploads(group_id)
        with _get_conn() as conn:
            conn.execute("DELETE FROM groups WHERE id = ?", (group_id,))


def _get_message_info(message_id: int) -> Optional[dict]:
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT id, group_id, user_id FROM group_messages WHERE id = ?",
            (message_id,),
        ).fetchone()
        if not row:
            return None
        return {"id": row["id"], "group_id": row["group_id"], "user_id": row["user_id"]}


def _count_group_members(group_id: str) -> int:
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS cnt FROM group_members WHERE group_id = ?",
            (group_id,),
        ).fetchone()
        return int(row["cnt"] if row else 0)


def _mark_messages_delivered(group_id: str, user_id: str, message_ids: List[int]) -> None:
    if not message_ids:
        return
    now = time.time()
    with _get_conn() as conn:
        conn.executemany(
            """
            INSERT OR IGNORE INTO group_message_receipts(message_id, user_id, delivered_at)
            VALUES (?, ?, ?)
            """,
            [(message_id, user_id, now) for message_id in message_ids],
        )


def _mark_messages_read(group_id: str, user_id: str, message_ids: List[int]) -> None:
    if not message_ids:
        return
    now = time.time()
    with _get_conn() as conn:
        conn.executemany(
            """
            INSERT OR IGNORE INTO group_message_receipts(message_id, user_id, delivered_at, read_at)
            VALUES (?, ?, ?, ?)
            """,
            [(message_id, user_id, now, now) for message_id in message_ids],
        )
        placeholders = ",".join("?" for _ in message_ids)
        conn.execute(
            f"""
            UPDATE group_message_receipts
            SET read_at = ?
            WHERE user_id = ? AND message_id IN ({placeholders}) AND read_at IS NULL
            """,
            [now, user_id, *message_ids],
        )


def _get_receipt_counts(message_ids: List[int]) -> Dict[int, Dict[str, int]]:
    if not message_ids:
        return {}
    placeholders = ",".join("?" for _ in message_ids)
    with _get_conn() as conn:
        rows = conn.execute(
            f"""
            SELECT message_id,
                   COUNT(*) AS delivered_count,
                   SUM(CASE WHEN read_at IS NOT NULL THEN 1 ELSE 0 END) AS read_count
            FROM group_message_receipts
            WHERE message_id IN ({placeholders})
            GROUP BY message_id
            """,
            message_ids,
        ).fetchall()
        result: Dict[int, Dict[str, int]] = {}
        for row in rows:
            result[int(row["message_id"])] = {
                "delivered_count": int(row["delivered_count"] or 0),
                "read_count": int(row["read_count"] or 0),
            }
        return result


def _list_message_read_ids(message_id: int) -> List[str]:
    with _get_conn() as conn:
        rows = conn.execute(
            """
            SELECT user_id
            FROM group_message_receipts
            WHERE message_id = ? AND read_at IS NOT NULL
            """,
            (message_id,),
        ).fetchall()
        return [r["user_id"] for r in rows]


def _list_message_read_users(message_id: int) -> List[dict]:
    with _get_conn() as conn:
        rows = conn.execute(
            """
            SELECT u.id AS id, u.name AS name, r.read_at AS read_at
            FROM group_message_receipts r
            JOIN users u ON u.id = r.user_id
            WHERE r.message_id = ? AND r.read_at IS NOT NULL
            ORDER BY r.read_at ASC
            """,
            (message_id,),
        ).fetchall()
        return [
            {"id": r["id"], "name": r["name"], "read_at": r["read_at"]}
            for r in rows
        ]


def _add_group_message(
    group_id: str,
    user_id: str,
    body: str,
    image_path: Optional[str] = None,
    image_lat: Optional[float] = None,
    image_lon: Optional[float] = None,
    image_accuracy: Optional[float] = None,
    image_timestamp: Optional[float] = None,
) -> dict:
    created_at = time.time()
    with _get_conn() as conn:
        conn.execute(
            """
            INSERT INTO group_messages(
                group_id,
                user_id,
                body,
                image_path,
                image_lat,
                image_lon,
                image_accuracy,
                image_timestamp,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                group_id,
                user_id,
                body,
                image_path,
                image_lat,
                image_lon,
                image_accuracy,
                image_timestamp,
                created_at,
            ),
        )
        row = conn.execute(
            """
            SELECT gm.id, gm.group_id, gm.user_id, u.name AS username, gm.body, gm.image_path,
                   gm.image_lat, gm.image_lon, gm.image_accuracy, gm.image_timestamp, gm.created_at
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
            "image_path": row["image_path"],
            "image_lat": row["image_lat"],
            "image_lon": row["image_lon"],
            "image_accuracy": row["image_accuracy"],
            "image_timestamp": row["image_timestamp"],
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


def _ensure_fcm_app() -> bool:
    global _fcm_app
    if _fcm_app is not None:
        return True
    if not FCM_SERVICE_ACCOUNT_FILE:
        return False
    try:
        cred = firebase_credentials.Certificate(FCM_SERVICE_ACCOUNT_FILE)
        _fcm_app = firebase_admin.initialize_app(cred)
        return True
    except Exception as exc:
        print("Failed to init Firebase Admin SDK:", exc)
        return False


def _send_fcm_push(tokens: List[str], title: str, body: str, data: dict) -> None:
    if not tokens:
        return
    if not _ensure_fcm_app():
        return
    payload_data = {str(k): str(v) for k, v in data.items()}
    for token in tokens:
        try:
            message = firebase_messaging.Message(
                token=token,
                data=payload_data,
                android=firebase_messaging.AndroidConfig(priority="high"),
            )
            firebase_messaging.send(message)
        except Exception as exc:
            print("FCM send failed", exc)


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
    return {"id": row["id"], "name": row["name"], "email": row["email"], "phone": row["phone"]}


@app.put("/users/{user_id}", response_model=UserPublic)
async def update_user(
    user_id: str,
    payload: UserUpdate,
    current_user_id: str = Depends(get_current_user_id),
):
    if current_user_id != user_id:
        raise HTTPException(status_code=403, detail="cannot update another user")
    name_value = payload.name.strip() if payload.name is not None else UNSET
    if payload.name is not None and not name_value:
        raise HTTPException(status_code=400, detail="name required")
    email_value = UNSET
    if payload.email is not None:
        email_value = str(payload.email).strip()
        if not email_value:
            raise HTTPException(status_code=400, detail="email required")
    phone_value = UNSET
    if payload.phone is not None:
        trimmed_phone = payload.phone.strip()
        if not trimmed_phone:
            phone_value = None
        else:
            phone_value = _normalize_phone(trimmed_phone)
            if not phone_value:
                raise HTTPException(status_code=400, detail="phone required")
    try:
        row = await _db_call(_update_user, user_id, name_value, email_value, phone_value)
    except ValueError as exc:
        if str(exc) == "email_already_exists":
            raise HTTPException(status_code=409, detail="email already exists")
        if str(exc) == "phone_already_exists":
            raise HTTPException(status_code=409, detail="phone already exists")
        raise
    if not row:
        raise HTTPException(status_code=404, detail="user not found")
    return {"id": row["id"], "name": row["name"], "email": row["email"], "phone": row["phone"]}


@app.get("/users/by-email/{email}", response_model=UserPublic)
async def get_user_by_email(email: EmailStr, current_user_id: str = Depends(get_current_user_id)):
    row = await _db_call(_get_user_by_email, str(email))
    if not row:
        raise HTTPException(status_code=404, detail="user not found")
    return {"id": row["id"], "name": row["name"], "email": row["email"], "phone": row["phone"]}


@app.put("/users/{user_id}/phone", response_model=UserPublic)
async def update_user_phone(
    user_id: str,
    payload: UserPhoneUpdate,
    current_user_id: str = Depends(get_current_user_id),
):
    if current_user_id != user_id:
        raise HTTPException(status_code=403, detail="cannot update another user")
    if payload.phone is None:
        raise HTTPException(status_code=400, detail="phone required")
    trimmed_phone = payload.phone.strip()
    if trimmed_phone:
        phone_value = _normalize_phone(trimmed_phone)
        if not phone_value:
            raise HTTPException(status_code=400, detail="phone required")
    else:
        phone_value = None
    try:
        row = await _db_call(_update_user_phone, user_id, phone_value)
    except ValueError as exc:
        if str(exc) == "phone_already_exists":
            raise HTTPException(status_code=409, detail="phone already exists")
        raise
    if not row:
        raise HTTPException(status_code=404, detail="user not found")
    return {"id": row["id"], "name": row["name"], "email": row["email"], "phone": row["phone"]}


@app.delete("/users/{user_id}")
async def delete_user(
    user_id: str,
    current_user_id: str = Depends(get_current_user_id),
):
    if current_user_id != user_id:
        raise HTTPException(status_code=403, detail="cannot delete another user")
    deleted = await _db_call(_delete_user, user_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="user not found")
    return {"status": "deleted"}


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
    email_value = str(payload.email) if payload.email is not None else None
    phone_value = None
    if payload.phone is not None:
        phone_value = _normalize_phone(payload.phone)
        if payload.phone.strip() and not phone_value:
            raise HTTPException(status_code=400, detail="phone required")
    if not email_value and not phone_value:
        raise HTTPException(status_code=400, detail="email or phone required")
    if email_value:
        existing = await _db_call(_get_user_by_email, email_value)
        if existing:
            raise HTTPException(status_code=409, detail="email already exists")
    if phone_value:
        existing = await _db_call(_get_user_by_phone, phone_value)
        if existing:
            raise HTTPException(status_code=409, detail="phone already exists")
    try:
        return await _db_call(
            _create_user, payload.name, email_value, payload.password, phone_value
        )
    except ValueError as e:
        if str(e) == "email_or_phone_exists":
            raise HTTPException(status_code=409, detail="email or phone already exists")
        raise


@app.post("/auth/login")
async def login(payload: "LoginRequest"):
    identifier = (payload.identifier or payload.email or payload.phone or "").strip()
    if not identifier:
        raise HTTPException(status_code=400, detail="identifier required")
    if "@" in identifier:
        row = await _db_call(_get_user_by_email, identifier)
    else:
        phone_value = _normalize_phone(identifier)
        if not phone_value:
            raise HTTPException(status_code=400, detail="phone required")
        row = await _db_call(_get_user_by_phone, phone_value)
    if not row or not _verify_password(payload.password, row["password_hash"]):
        raise HTTPException(status_code=401, detail="invalid credentials")

    token = _create_access_token(row["id"])
    return {"access_token": token, "token_type": "bearer"}


@app.post("/auth/forgot-password")
async def forgot_password(payload: ForgotPasswordRequest):
    email = str(payload.email)
    if FIREBASE_WEB_API_KEY:
        try:
            firebase_result = await asyncio.to_thread(_send_firebase_password_reset_email, email)
        except RuntimeError as e:
            raise HTTPException(status_code=502, detail=str(e))

        if firebase_result == "sent":
            print(f"Firebase password reset email requested for {email}")
            return {"status": "ok"}

        print(f"Firebase password reset skipped for {email}: email not found in Firebase Auth")
    else:
        print("Firebase password reset is not configured; using local SMTP reset flow")

    token = await _db_call(_create_password_reset_token, email)
    if token:
        try:
            await asyncio.to_thread(_send_password_reset_email, email, token)
        except RuntimeError as e:
            raise HTTPException(status_code=502, detail=str(e))
    else:
        print(f"Password reset skipped for {email}: email not found in local users")
    return {"status": "ok"}


@app.get("/reset-password", response_class=HTMLResponse)
async def reset_password_page(token: str = ""):
    token_json = json.dumps(token)
    return f"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Reset password</title>
  <style>
    :root {{
      color-scheme: light dark;
      font-family: Arial, sans-serif;
    }}
    body {{
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      background: #f4f6f8;
      color: #17202a;
    }}
    main {{
      width: min(100% - 32px, 420px);
      padding: 28px;
      background: #ffffff;
      border: 1px solid #d8dee4;
      border-radius: 8px;
      box-shadow: 0 8px 30px rgba(0, 0, 0, 0.08);
    }}
    h1 {{
      margin: 0 0 20px;
      font-size: 24px;
    }}
    label {{
      display: block;
      margin-bottom: 8px;
      font-weight: 700;
    }}
    input, button {{
      box-sizing: border-box;
      width: 100%;
      min-height: 44px;
      border-radius: 6px;
      font: inherit;
    }}
    input {{
      margin-bottom: 14px;
      padding: 10px 12px;
      border: 1px solid #c7ced6;
      background: #ffffff;
      color: #17202a;
    }}
    button {{
      border: 0;
      background: #166534;
      color: #ffffff;
      font-weight: 700;
      cursor: pointer;
    }}
    button:disabled {{
      opacity: 0.65;
      cursor: wait;
    }}
    #message {{
      min-height: 22px;
      margin-top: 14px;
      font-size: 14px;
    }}
    .error {{
      color: #b42318;
    }}
    .success {{
      color: #166534;
    }}
    @media (prefers-color-scheme: dark) {{
      body {{
        background: #111827;
        color: #f9fafb;
      }}
      main {{
        background: #1f2937;
        border-color: #374151;
      }}
      input {{
        background: #111827;
        border-color: #4b5563;
        color: #f9fafb;
      }}
    }}
  </style>
</head>
<body>
  <main>
    <h1>Reset password</h1>
    <form id="reset-form">
      <label for="new-password">New password</label>
      <input id="new-password" name="new-password" type="password" autocomplete="new-password" required minlength="1">
      <button id="submit-button" type="submit">Update password</button>
      <div id="message" role="status" aria-live="polite"></div>
    </form>
  </main>
  <script>
    const token = {token_json};
    const form = document.getElementById("reset-form");
    const passwordInput = document.getElementById("new-password");
    const submitButton = document.getElementById("submit-button");
    const message = document.getElementById("message");

    if (!token) {{
      submitButton.disabled = true;
      message.className = "error";
      message.textContent = "Reset token is missing.";
    }}

    form.addEventListener("submit", async (event) => {{
      event.preventDefault();
      submitButton.disabled = true;
      message.className = "";
      message.textContent = "Updating password...";

      try {{
        const response = await fetch("/auth/reset-password", {{
          method: "POST",
          headers: {{"Content-Type": "application/json"}},
          body: JSON.stringify({{
            token,
            new_password: passwordInput.value,
          }}),
        }});

        if (!response.ok) {{
          const error = await response.json().catch(() => ({{detail: "Password reset failed"}}));
          throw new Error(error.detail || "Password reset failed");
        }}

        message.className = "success";
        message.textContent = "Password updated.";
        form.reset();
      }} catch (error) {{
        message.className = "error";
        message.textContent = error.message;
        submitButton.disabled = false;
      }}
    }});
  </script>
</body>
</html>
"""


@app.post("/auth/reset-password")
async def reset_password(payload: PasswordResetRequest):
    if not payload.token.strip():
        raise HTTPException(status_code=400, detail="token required")
    if not payload.new_password.strip():
        raise HTTPException(status_code=400, detail="new password required")
    updated = await _db_call(_reset_password_with_token, payload.token, payload.new_password)
    if not updated:
        raise HTTPException(status_code=400, detail="invalid or expired reset token")
    return {"status": "ok"}

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
            group_name = await _db_call(_get_group_name, group_id)
            group_label = group_name or group_id
            title = "Liittymispyyntö"
            body = f"{requester_name} haluaa liittyä ryhmään {group_label}."
            data = {
                "type": "join_request",
                "group_id": group_id,
                "group_name": group_name or "",
                "requester_id": current_user_id,
                "requester_name": requester_name,
            }
            asyncio.create_task(_send_fcm_push_async(tokens, title, body, data))
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
        await _db_call(_delete_group_uploads, group_id)
        with _get_conn() as conn:
            conn.execute("DELETE FROM groups WHERE id = ?", (group_id,))
        return {"status": "deleted", "group_id": group_id, "user_id": user_id}

    return {"status": "ok", "group_id": group_id, "user_id": user_id}


@app.delete("/groups/{group_id}")
async def delete_group(
    group_id: str,
    current_user_id: str = Depends(get_current_user_id),
):
    if not await _db_call(_group_exists, group_id):
        raise HTTPException(status_code=404, detail="group not found")
    owner_id = await _db_call(_get_group_owner_id, group_id)
    if not owner_id:
        raise HTTPException(status_code=404, detail="group not found")
    if owner_id != current_user_id:
        raise HTTPException(status_code=403, detail="only group owner can delete group")
    await _db_call(_delete_group_uploads, group_id)
    with _get_conn() as conn:
        conn.execute("DELETE FROM groups WHERE id = ?", (group_id,))
    return {"status": "deleted", "group_id": group_id}


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


@app.get("/groups/{group_id}/passipaikat", response_model=Dict[str, List[PassipaikkaListPublic]])
async def get_group_passipaikat(
    group_id: str,
    current_user_id: str = Depends(get_current_user_id),
):
    if not await _db_call(_group_exists, group_id):
        raise HTTPException(status_code=404, detail="group not found")
    if not await _db_call(_is_member, group_id, current_user_id):
        raise HTTPException(status_code=403, detail="not a member of this group")
    passipaikka_list = await _db_call(_get_group_passipaikka_list, group_id)
    return {"lists": [passipaikka_list]}


@app.put("/groups/{group_id}/passipaikat", response_model=Dict[str, List[PassipaikkaListPublic]])
async def sync_group_passipaikat(
    group_id: str,
    request: Request,
    current_user_id: str = Depends(get_current_user_id),
):
    if not await _db_call(_group_exists, group_id):
        raise HTTPException(status_code=404, detail="group not found")
    if not await _db_call(_is_member, group_id, current_user_id):
        raise HTTPException(status_code=403, detail="not a member of this group")
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid json body")
    points = _extract_passipaikat_payload(payload)
    passipaikka_list = await _db_call(_replace_group_passipaikat, group_id, points)
    return {"lists": [passipaikka_list]}


@app.get("/groups/{group_id}/passi-ajo-groups", response_model=Dict[str, List[PassiAjoGroupPublic]])
async def get_passi_ajo_groups(
    group_id: str,
    current_user_id: str = Depends(get_current_user_id),
):
    if not await _db_call(_group_exists, group_id):
        raise HTTPException(status_code=404, detail="group not found")
    if not await _db_call(_is_member, group_id, current_user_id):
        raise HTTPException(status_code=403, detail="not a member of this group")
    groups = await _db_call(_list_group_passi_ajo_groups, group_id)
    return {"groups": groups}


@app.put("/groups/{group_id}/passi-ajo-groups", response_model=Dict[str, List[PassiAjoGroupPublic]])
async def save_passi_ajo_groups(
    group_id: str,
    request: Request,
    current_user_id: str = Depends(get_current_user_id),
):
    if not await _db_call(_group_exists, group_id):
        raise HTTPException(status_code=404, detail="group not found")
    owner_id = await _db_call(_get_group_owner_id, group_id)
    if owner_id != current_user_id:
        raise HTTPException(status_code=403, detail="only group owner can save passi ajo groups")
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid json body")
    groups = _extract_passi_ajo_groups_payload(payload)
    saved_groups = await _db_call(_replace_group_passi_ajo_groups, group_id, groups)
    return {"groups": saved_groups}


@app.get("/groups/{group_id}/messages", response_model=List[ChatMessagePublic])
async def list_group_messages(
    group_id: str,
    limit: int = 50,
    before: Optional[float] = None,
    mark_read: bool = False,
    current_user_id: str = Depends(get_current_user_id),
):
    if not await _db_call(_group_exists, group_id):
        raise HTTPException(status_code=404, detail="group not found")
    if not await _db_call(_is_member, group_id, current_user_id):
        raise HTTPException(status_code=403, detail="not a member of this group")
    limit = max(1, min(200, limit))
    messages = await _db_call(_list_group_messages, group_id, limit, before)
    if not messages:
        return messages
    for message in messages:
        message["image_url"] = _build_image_url(message.get("image_path"))
        message.pop("image_path", None)
    message_ids = [int(message["id"]) for message in messages]
    recipient_ids = [
        int(message["id"])
        for message in messages
        if message.get("user_id") != current_user_id
    ]
    if recipient_ids:
        await _db_call(_mark_messages_delivered, group_id, current_user_id, recipient_ids)
        if mark_read:
            await _db_call(_mark_messages_read, group_id, current_user_id, recipient_ids)
    receipt_counts = await _db_call(_get_receipt_counts, message_ids)
    member_count = await _db_call(_count_group_members, group_id)
    recipient_count = max(0, member_count - 1)
    enriched = []
    for message in messages:
        msg_id = int(message["id"])
        counts = receipt_counts.get(msg_id, {"delivered_count": 0, "read_count": 0})
        enriched.append(
            {
                **message,
                "delivered_count": counts["delivered_count"],
                "read_count": counts["read_count"],
                "recipient_count": recipient_count,
            }
        )
    return enriched


@app.get("/groups/{group_id}/messages/{message_id}/receipts", response_model=MessageReceiptSummary)
async def get_message_receipts(
    group_id: str,
    message_id: int,
    current_user_id: str = Depends(get_current_user_id),
):
    if not await _db_call(_group_exists, group_id):
        raise HTTPException(status_code=404, detail="group not found")
    if not await _db_call(_is_member, group_id, current_user_id):
        raise HTTPException(status_code=403, detail="not a member of this group")
    info = await _db_call(_get_message_info, message_id)
    if not info or info["group_id"] != group_id:
        raise HTTPException(status_code=404, detail="message not found")
    if info["user_id"] != current_user_id:
        raise HTTPException(status_code=403, detail="only sender can view receipts")
    members = await _db_call(_list_members_with_names, group_id)
    read_users = await _db_call(_list_message_read_users, message_id)
    read_ids = {user["id"] for user in read_users}
    read_by = [user for user in read_users if user["id"] != current_user_id]
    unread_by = [
        member
        for member in members
        if member["id"] != current_user_id and member["id"] not in read_ids
    ]
    return {
        "group_id": group_id,
        "message_id": message_id,
        "read_by": read_by,
        "unread_by": unread_by,
    }


@app.post("/groups/{group_id}/messages", response_model=ChatMessagePublic)
async def create_group_message(
    group_id: str,
    request: Request,
    current_user_id: str = Depends(get_current_user_id),
):
    if not await _db_call(_group_exists, group_id):
        raise HTTPException(status_code=404, detail="group not found")
    if not await _db_call(_is_member, group_id, current_user_id):
        raise HTTPException(status_code=403, detail="not a member of this group")
    body = ""
    image_path: Optional[str] = None
    image_lat: Optional[float] = None
    image_lon: Optional[float] = None
    image_accuracy: Optional[float] = None
    image_timestamp: Optional[float] = None
    content_type = (request.headers.get("content-type") or "").lower()
    if content_type.startswith("multipart/form-data"):
        form = await request.form()
        raw_body = form.get("body")
        if isinstance(raw_body, str):
            body = raw_body.strip()
        upload = form.get("image")
        if isinstance(upload, UploadFile) or (hasattr(upload, "file") and hasattr(upload, "filename")):
            if not upload.content_type or not upload.content_type.startswith("image/"):
                raise HTTPException(status_code=400, detail="invalid image type")
            image_path = _save_uploaded_image(upload)
            upload.file.close()
            image_lat = _parse_optional_float(form.get("image_lat"))
            image_lon = _parse_optional_float(form.get("image_lon"))
            image_accuracy = _parse_optional_float(form.get("image_accuracy"))
            image_timestamp = _parse_optional_float(form.get("image_timestamp"))
            if image_lat is None or image_lon is None:
                image_lat = None
                image_lon = None
                image_accuracy = None
                image_timestamp = None
        elif upload is not None:
            raise HTTPException(status_code=400, detail=f"invalid image upload type={type(upload).__name__}")
    else:
        try:
            payload = await request.json()
        except Exception:
            payload = {}
        if isinstance(payload, dict):
            body = str(payload.get("body") or "").strip()
    if not body and not image_path:
        raise HTTPException(status_code=400, detail="message body or image required")
    message = await _db_call(
        _add_group_message,
        group_id,
        current_user_id,
        body,
        image_path,
        image_lat,
        image_lon,
        image_accuracy,
        image_timestamp,
    )
    image_url = _build_image_url(message.get("image_path"))
    message.pop("image_path", None)
    member_count = await _db_call(_count_group_members, group_id)
    recipient_count = max(0, member_count - 1)
    if FCM_SERVICE_ACCOUNT_FILE:
        member_ids = await _db_call(_list_members, group_id)
        target_ids = [uid for uid in member_ids if uid != current_user_id]
        tokens: List[str] = []
        for uid in target_ids:
            tokens.extend(await _db_call(_list_push_tokens, uid))
        if tokens:
            deduped = list(dict.fromkeys(tokens))
            body_text = (message.get("body") or "").strip()
            body_preview = body_text[:80] if body_text else ("Kuva" if image_url else "")
            group_name = await _db_call(_get_group_name, group_id)
            data = {
                "type": "chat",
                "group_id": group_id,
                "group_name": group_name or "",
                "sender_id": current_user_id,
                "sender_name": message["username"],
                "message_id": str(message["id"]),
                "body_preview": body_preview,
                "body": message["body"],
            }
            asyncio.create_task(
                _send_fcm_push_async(deduped, message["username"], body_preview, data)
            )
    return {
        **message,
        "image_url": image_url,
        "delivered_count": 0,
        "read_count": 0,
        "recipient_count": recipient_count,
    }


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


@app.get("/groups/{group_id}/sharing")
async def get_group_sharing(group_id: str, current_user_id: str = Depends(get_current_user_id)):
    if not await _db_call(_group_exists, group_id):
        raise HTTPException(status_code=404, detail="group not found")
    if not await _db_call(_is_member, group_id, current_user_id):
        raise HTTPException(status_code=403, detail="not a member of this group")
    enabled_ids = await _db_call(_get_share_enabled_member_ids, group_id)
    return {"group_id": group_id, "enabled_user_ids": enabled_ids}


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
    port = int(os.environ.get("PORT", "5656"))
    uvicorn.run(app, host="0.0.0.0", port=port)
