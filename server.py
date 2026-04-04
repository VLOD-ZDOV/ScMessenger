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

import asyncio, json, sqlite3, time, hashlib, sys, logging
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
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            pubkey   TEXT NOT NULL,
            created  INTEGER
        );
        CREATE TABLE IF NOT EXISTS messages (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            from_user TEXT NOT NULL,
            to_user   TEXT NOT NULL,
            payload   TEXT NOT NULL,   -- JSON зашифрованный блоб
            ts        INTEGER NOT NULL,
            delivered INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS contact_requests (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            from_user TEXT NOT NULL,
            to_user   TEXT NOT NULL,
            pubkey    TEXT NOT NULL,
            status    TEXT DEFAULT 'pending',  -- pending|accepted|rejected
            ts        INTEGER
        );
        """)
    log.info("БД инициализирована")


# ─────────────────────────────────────────────────────────────
# МЕНЕДЖЕР ПОДКЛЮЧЕНИЙ
# ─────────────────────────────────────────────────────────────

# username → websocket
online: dict[str, object] = {}


async def send_to(username: str, msg: dict) -> bool:
    ws = online.get(username)
    if ws:
        try:
            await ws.send(json.dumps(msg, ensure_ascii=False))
            return True
        except Exception:
            pass
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

                # Валидация имени
                import re
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
            elif t == "message":
                to      = msg.get("to", "")
                payload = msg.get("payload")
                ts      = msg.get("ts") or int(time.time()*1000)

                if not to or not payload:
                    continue

                # Проверяем что получатель существует
                with db_conn() as c:
                    target = c.execute(
                        "SELECT username FROM users WHERE username=?", (to,)
                    ).fetchone()
                if not target:
                    await websocket.send(json.dumps({
                        "type": "error",
                        "reason": f"Пользователь @{to} не найден"
                    }))
                    continue

                with db_conn() as c:
                    cur = c.execute(
                        "INSERT INTO messages (from_user,to_user,payload,ts) VALUES (?,?,?,?)",
                        (username, to, json.dumps(payload), ts)
                    )
                    server_id = str(cur.lastrowid)

                # Пытаемся доставить онлайн
                delivered = await send_to(to, {
                    "type":      "message",
                    "from":      username,
                    "payload":   payload,
                    "ts":        ts,
                    "server_id": server_id,
                })
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
                to = msg.get("to","")
                with db_conn() as c:
                    row = c.execute(
                        "SELECT pubkey FROM users WHERE username=?", (to,)
                    ).fetchone()
                if not row:
                    continue
                # Уведомляем получателя
                await send_to(to, {
                    "type":   "contact_request",
                    "from":   username,
                    "pubkey": row["pubkey"],  # публичный ключ инициатора
                })
                # Получаем ключ инициатора
                with db_conn() as c:
                    my_row = c.execute(
                        "SELECT pubkey FROM users WHERE username=?", (username,)
                    ).fetchone()
                # Отправляем ключ инициатора получателю
                await send_to(to, {
                    "type":   "contact_request",
                    "from":   username,
                    "pubkey": my_row["pubkey"] if my_row else "",
                })
                log.info(f"@{username} → contact request → @{to}")

            # ── Принять запрос ───────────────────────────────
            elif t == "contact_accept":
                to     = msg.get("to","")
                pubkey = msg.get("pubkey","")
                await send_to(to, {
                    "type":   "contact_accepted",
                    "peer":   username,
                    "pubkey": pubkey,
                })
                log.info(f"@{username} принял контакт от @{to}")

            # ── Отклонить запрос ─────────────────────────────
            elif t == "contact_reject":
                to = msg.get("to","")
                await send_to(to, {
                    "type": "contact_rejected",
                    "peer": username,
                })

            else:
                log.debug(f"Неизвестный тип: {t}")

    except websockets.exceptions.ConnectionClosed:
        pass
    except Exception as e:
        log.error(f"Ошибка handler: {e}")
    finally:
        if username and online.get(username) is websocket:
            del online[username]
            log.info(f"@{username} отключился")
            await _notify_contacts_online(username, False)


async def _deliver_pending(username: str, websocket):
    """Отправить накопленные сообщения."""
    with db_conn() as c:
        rows = c.execute(
            "SELECT * FROM messages WHERE to_user=? AND delivered=0 ORDER BY ts ASC",
            (username,)
        ).fetchall()
    for row in rows:
        try:
            payload = json.loads(row["payload"])
            await websocket.send(json.dumps({
                "type":      "message",
                "from":      row["from_user"],
                "payload":   payload,
                "ts":        row["ts"],
                "server_id": str(row["id"]),
            }))
            with db_conn() as c:
                c.execute("UPDATE messages SET delivered=1 WHERE id=?", (row["id"],))
        except Exception as e:
            log.error(f"Ошибка доставки pending: {e}")


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
            except:
                pass


# ─────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────

async def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "0.0.0.0"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8765

    db_init()
    log.info(f"SCmess сервер запускается на {host}:{port}")

    async with websockets.serve(handler, host, port,
                                 max_size=10 * 1024 * 1024,  # 10 МБ
                                 ping_interval=30,
                                 ping_timeout=10):
        log.info(f"✓ Сервер запущен  ws://{host}:{port}")
        log.info("Ctrl+C для остановки")
        await asyncio.Future()  # run forever


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("Сервер остановлен")
