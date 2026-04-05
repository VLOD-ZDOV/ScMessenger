"""
SCmess Server
Запуск: python server.py [host] [port]
Требует: pip install websockets

Сервер хранит:
  - имена пользователей + публичные ключи (RSA PEM)
  - зашифрованные сообщения (расшифровать не может)
  - историю чатов (зашифрованные блобы)

Сервер НЕ видит содержимое сообщений.
"""

import asyncio, json, sqlite3, time, hashlib, sys, logging, re
from collections import defaultdict
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
log = logging.getLogger("scmess")

try:
    import websockets
except ImportError:
    print("Установите websockets: pip install websockets")
    sys.exit(1)

DB_PATH = "scmess_server.db"


# ─────────────────────────────────────────────────────────────
# БАЗА ДАННЫХ
# ─────────────────────────────────────────────────────────────

def db_conn():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    return c

def db_init():
    with db_conn() as c:
        # WAL: убирает блокировки при одновременном чтении/записи
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA synchronous=NORMAL")
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            pubkey   TEXT NOT NULL,
            created  INTEGER
        );
        CREATE TABLE IF NOT EXISTS messages (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            msg_type  TEXT NOT NULL DEFAULT 'message',
            from_user TEXT NOT NULL,
            to_user   TEXT NOT NULL,
            payload   TEXT NOT NULL,
            ts        INTEGER NOT NULL,
            delivered INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS contact_requests (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            from_user TEXT NOT NULL,
            to_user   TEXT NOT NULL,
            pubkey    TEXT NOT NULL,
            status    TEXT DEFAULT 'pending',
            ts        INTEGER
        );
        """)
        # Индексы для быстрого get_pending
        c.executescript("""
        CREATE INDEX IF NOT EXISTS idx_messages_to_delivered
            ON messages(to_user, delivered);
        CREATE INDEX IF NOT EXISTS idx_messages_ts
            ON messages(ts);
        CREATE INDEX IF NOT EXISTS idx_contact_requests_to_status
            ON contact_requests(to_user, status);
        """)
        cols = {r["name"] for r in c.execute("PRAGMA table_info(messages)").fetchall()}
        if "msg_type" not in cols:
            c.execute("ALTER TABLE messages ADD COLUMN msg_type TEXT NOT NULL DEFAULT 'message'")
    log.info("БД инициализирована")


def db_cleanup_old_messages(days: int = 30):
    """Удаляет доставленные сообщения старше `days` дней (TTL)."""
    cutoff = int(time.time() * 1000) - days * 86_400_000
    with db_conn() as c:
        cur = c.execute(
            "DELETE FROM messages WHERE delivered=1 AND ts < ?", (cutoff,))
        if cur.rowcount:
            log.info("TTL cleanup: удалено %d старых сообщений", cur.rowcount)


# ─────────────────────────────────────────────────────────────
# МЕНЕДЖЕР ПОДКЛЮЧЕНИЙ
# ─────────────────────────────────────────────────────────────

# username → websocket
online: dict[str, object] = {}

# Rate limiting: username → список timestamp'ов последних сообщений
_rate_buckets: dict[str, list] = defaultdict(list)
RATE_LIMIT     = 30    # максимум сообщений
RATE_WINDOW    = 60    # за N секунд
MAX_PAYLOAD_B  = 8 * 1024 * 1024  # 8 МБ — жёсткий лимит на payload сообщения


def _check_rate_limit(username: str) -> bool:
    """Возвращает True если лимит НЕ превышен."""
    now = time.time()
    bucket = _rate_buckets[username]
    # Оставляем только метки в пределах окна
    _rate_buckets[username] = [t for t in bucket if now - t < RATE_WINDOW]
    if len(_rate_buckets[username]) >= RATE_LIMIT:
        return False
    _rate_buckets[username].append(now)
    return True


async def send_to(username: str, msg: dict) -> bool:
    ws = online.get(username)
    if ws:
        try:
            await ws.send(json.dumps(msg, ensure_ascii=False))
            return True
        except Exception:
            log.exception("send_to @%s failed", username)
    return False


# ─────────────────────────────────────────────────────────────
# ОБРАБОТЧИК
# ─────────────────────────────────────────────────────────────

async def handler(websocket):
    username = None
    try:
        async for raw in websocket:
            try:
                msg = json.loads(raw)
            except Exception:
                continue

            t = msg.get("type")

            # ── Авторизация / регистрация ────────────────────
            if t == "auth":
                uname  = msg.get("username", "").strip()
                pubkey = msg.get("pubkey", "").strip()

                if not uname or not pubkey or len(uname) > 64:
                    await websocket.send(json.dumps({
                        "type": "auth_error",
                        "reason": "Неверные данные"
                    }))
                    continue

                # Валидация имени (re теперь импортирован на уровне модуля)
                if not re.match(r"^[a-zA-Z0-9_]{3,32}$", uname):
                    await websocket.send(json.dumps({
                        "type": "auth_error",
                        "reason": "Имя: 3-32 символа, латиница/цифры/_"
                    }))
                    continue

                with db_conn() as c:
                    existing = c.execute(
                        "SELECT pubkey FROM users WHERE username=?", (uname,)
                    ).fetchone()
                    if existing:
                        # Пользователь уже есть — проверяем ключ
                        # (идентификация по публичному ключу)
                        if existing["pubkey"] != pubkey:
                            await websocket.send(json.dumps({
                                "type": "auth_error",
                                "reason": "Публичный ключ не совпадает с зарегистрированным"
                            }))
                            continue
                    else:
                        # Новый пользователь — регистрируем
                        c.execute(
                            "INSERT INTO users (username,pubkey,created) VALUES (?,?,?)",
                            (uname, pubkey, int(time.time()*1000))
                        )
                        log.info(f"Новый пользователь: @{uname}")

                username = uname
                online[username] = websocket
                log.info(f"@{username} подключился")

                await websocket.send(json.dumps({"type": "auth_ok"}))

                # Уведомляем контакты что пользователь онлайн
                await _notify_contacts_online(username, True)

            # Все остальные команды — только после авторизации
            elif username is None:
                await websocket.send(json.dumps({
                    "type": "error", "reason": "Не авторизован"
                }))

            # ── Получить непрочитанные ───────────────────────
            elif t == "get_pending":
                await _deliver_pending(username, websocket)

            # ── Отправить сообщение ──────────────────────────
            elif t in ("message", "image_message"):
                to       = msg.get("to", "")
                payload  = msg.get("payload")
                ts       = msg.get("ts") or int(time.time()*1000)
                group_id = msg.get("group_id")

                if not to or not payload:
                    continue

                # Rate limiting
                if not _check_rate_limit(username):
                    await websocket.send(json.dumps({
                        "type":   "error",
                        "reason": f"Слишком много сообщений. Подождите немного."
                    }))
                    log.warning("Rate limit exceeded for @%s", username)
                    continue

                # Валидация размера payload
                payload_str = json.dumps(payload)
                if len(payload_str.encode()) > MAX_PAYLOAD_B:
                    await websocket.send(json.dumps({
                        "type":   "error",
                        "reason": "Сообщение слишком большое"
                    }))
                    continue

                # Проверяем что получатель существует
                with db_conn() as c:
                    target = c.execute(
                        "SELECT username FROM users WHERE username=?", (to,)
                    ).fetchone()
                if not target:
                    await websocket.send(json.dumps({
                        "type":   "error",
                        "reason": f"Пользователь @{to} не найден"
                    }))
                    continue

                with db_conn() as c:
                    cur = c.execute(
                        "INSERT INTO messages (msg_type,from_user,to_user,payload,ts) VALUES (?,?,?,?,?)",
                        (t, username, to, payload_str, ts)
                    )
                    server_id = str(cur.lastrowid)

                # Пытаемся доставить онлайн
                out_msg = {
                    "type":      t,
                    "from":      username,
                    "payload":   payload,
                    "ts":        ts,
                    "server_id": server_id,
                }
                if group_id:
                    out_msg["group_id"] = group_id

                delivered = await send_to(to, out_msg)
                if delivered:
                    with db_conn() as c:
                        c.execute("UPDATE messages SET delivered=1 WHERE id=?",
                                  (server_id,))
                    await websocket.send(json.dumps({
                        "type":      "message_status",
                        "server_id": server_id,
                        "status":    "delivered"
                    }))
                else:
                    await websocket.send(json.dumps({
                        "type":      "message_status",
                        "server_id": server_id,
                        "status":    "sent"
                    }))

            # ── Подтверждение получения ──────────────────────
            elif t == "ack":
                sid = msg.get("server_id")
                if sid:
                    with db_conn() as c:
                        row = c.execute(
                            "SELECT from_user FROM messages WHERE id=?", (sid,)
                        ).fetchone()
                    if row:
                        await send_to(row["from_user"], {
                            "type":      "message_status",
                            "server_id": sid,
                            "status":    "delivered"
                        })

            # ── Найти пользователя ───────────────────────────
            elif t == "find_user":
                target  = msg.get("username", "")
                req_id  = msg.get("req_id")
                with db_conn() as c:
                    row = c.execute(
                        "SELECT username,pubkey FROM users WHERE username=?",
                        (target,)
                    ).fetchone()
                if row:
                    await websocket.send(json.dumps({
                        "type":   "user_info",
                        "req_id": req_id,
                        "username": row["username"],
                        "pubkey":   row["pubkey"],
                        "online":   row["username"] in online,
                    }))
                else:
                    await websocket.send(json.dumps({
                        "type":   "error",
                        "req_id": req_id,
                        "reason": f"@{target} не найден"
                    }))

            # ── Запрос контакта ──────────────────────────────
            elif t == "contact_request":
                to = msg.get("to", "")
                with db_conn() as c:
                    to_row = c.execute(
                        "SELECT pubkey FROM users WHERE username=?", (to,)
                    ).fetchone()
                    my_row = c.execute(
                        "SELECT pubkey FROM users WHERE username=?", (username,)
                    ).fetchone()
                if not to_row or not my_row:
                    continue
                # Сохраняем запрос в БД — доставим при подключении если офлайн
                with db_conn() as c:
                    # Проверяем нет ли уже pending-запроса
                    exists = c.execute(
                        "SELECT id FROM contact_requests "
                        "WHERE from_user=? AND to_user=? AND status='pending'",
                        (username, to)
                    ).fetchone()
                    if not exists:
                        c.execute(
                            "INSERT INTO contact_requests "
                            "(from_user,to_user,pubkey,status,ts) VALUES (?,?,?,?,?)",
                            (username, to, my_row["pubkey"], "pending",
                             int(time.time()*1000))
                        )
                # Если получатель онлайн — шлём сразу
                delivered = await send_to(to, {
                    "type":   "contact_request",
                    "from":   username,
                    "pubkey": my_row["pubkey"],
                })
                log.info("@%s → contact_request → @%s (delivered=%s)",
                         username, to, delivered)

            # ── Принять запрос ───────────────────────────────
            elif t == "contact_accept":
                to     = msg.get("to", "")
                pubkey = msg.get("pubkey", "")
                # Помечаем запрос принятым
                with db_conn() as c:
                    c.execute(
                        "UPDATE contact_requests SET status='accepted' "
                        "WHERE from_user=? AND to_user=? AND status='pending'",
                        (to, username)
                    )
                await send_to(to, {
                    "type":   "contact_accepted",
                    "peer":   username,
                    "pubkey": pubkey,
                })
                log.info("@%s принял контакт от @%s", username, to)

            # ── Отклонить запрос ─────────────────────────────
            elif t == "contact_reject":
                to = msg.get("to", "")
                with db_conn() as c:
                    c.execute(
                        "UPDATE contact_requests SET status='rejected' "
                        "WHERE from_user=? AND to_user=? AND status='pending'",
                        (to, username)
                    )
                await send_to(to, {
                    "type": "contact_rejected",
                    "peer": username,
                })

            else:
                log.debug(f"Неизвестный тип: {t}")

    except websockets.exceptions.ConnectionClosed:
        pass
    except Exception as e:
        log.exception("handler error for @%s: %s", username, e)
    finally:
        if username and online.get(username) is websocket:
            del online[username]
            log.info(f"@{username} отключился")
            await _notify_contacts_online(username, False)


async def _deliver_pending(username: str, websocket):
    """Отправить накопленные сообщения и оффлайн-запросы в контакты."""
    # ── Сообщения ────────────────────────────────────────────
    with db_conn() as c:
        rows = c.execute(
            "SELECT * FROM messages WHERE to_user=? AND delivered=0 ORDER BY ts ASC",
            (username,)
        ).fetchall()
    for row in rows:
        try:
            payload = json.loads(row["payload"])
            out = {
                "type":      row["msg_type"] if row["msg_type"] else "message",
                "from":      row["from_user"],
                "payload":   payload,
                "ts":        row["ts"],
                "server_id": str(row["id"]),
            }
            if row["msg_type"] == "message":
                try:
                    meta = json.loads(row.get("meta") or "{}")
                    if meta.get("group_id"):
                        out["group_id"] = meta["group_id"]
                except Exception:
                    pass
            await websocket.send(json.dumps(out))
            with db_conn() as c:
                c.execute("UPDATE messages SET delivered=1 WHERE id=?", (row["id"],))
        except Exception as e:
            log.exception("_deliver_pending: failed to deliver msg id=%s: %s",
                          row["id"], e)

    # ── Оффлайн запросы на добавление в контакты ─────────────
    with db_conn() as c:
        creqs = c.execute(
            "SELECT * FROM contact_requests "
            "WHERE to_user=? AND status='pending' ORDER BY ts ASC",
            (username,)
        ).fetchall()
    for creq in creqs:
        try:
            await websocket.send(json.dumps({
                "type":   "contact_request",
                "from":   creq["from_user"],
                "pubkey": creq["pubkey"],
            }))
            log.info("Delivered offline contact_request from @%s to @%s",
                     creq["from_user"], username)
        except Exception as e:
            log.exception("_deliver_pending: contact_request id=%s: %s",
                          creq["id"], e)


async def _notify_contacts_online(username: str, is_online: bool):
    """Оповестить онлайн-пользователей об изменении статуса."""
    # Простая реализация: уведомляем всех онлайн
    status_msg = json.dumps({
        "type":    "user_status",
        "username": username,
        "online":   is_online,
    })
    for uname, ws in list(online.items()):
        if uname != username:
            try:
                await ws.send(status_msg)
            except Exception:
                log.debug("notify_contacts_online: send to @%s failed", uname)


# ─────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────

async def _ttl_cleanup_loop(interval_hours: int = 6):
    """Периодически удаляет старые доставленные сообщения (TTL = 30 дней)."""
    while True:
        await asyncio.sleep(interval_hours * 3600)
        try:
            db_cleanup_old_messages(days=30)
        except Exception:
            log.exception("TTL cleanup failed")


async def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "0.0.0.0"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8765

    db_init()

    # Первичная очистка при старте
    try:
        db_cleanup_old_messages(days=30)
    except Exception:
        log.exception("Initial TTL cleanup failed")

    log.info("SCmess сервер запускается на %s:%s", host, port)

    # Для WSS: передайте ssl=ssl_context в websockets.serve
    # ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # ssl_context.load_cert_chain("cert.pem", "key.pem")

    async with websockets.serve(handler, host, port,
                                max_size=10 * 1024 * 1024,  # 10 МБ
                                ping_interval=30,
                                ping_timeout=10):
        log.info("✓ Сервер запущен  ws://%s:%s", host, port)
        log.info("Ctrl+C для остановки")
        # Запускаем фоновую задачу TTL-очистки
        asyncio.create_task(_ttl_cleanup_loop(interval_hours=6))
        await asyncio.Future()  # run forever


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("Сервер остановлен")
