from __future__ import annotations

import asyncio
import hashlib
import json
import re
import sqlite3
import threading
import time
import uuid
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from pathlib import Path
from typing import Any, cast

try:
    import frida
except ImportError:  # The adapter reports this without preventing AstrBot startup.
    frida = None  # type: ignore[assignment]

from astrbot.api import logger
from astrbot.api.event import AstrMessageEvent, MessageChain
from astrbot.api.message_components import At, Plain
from astrbot.api.platform import (
    AstrBotMessage,
    Group,
    MessageMember,
    MessageType,
    Platform,
    PlatformMetadata,
    register_platform_adapter,
)
from astrbot.api.star import Context, Star, register
from astrbot.core.platform.astr_message_event import MessageSesion

PLUGIN_NAME = "astrbot_plugin_wecom_external_bridge"
PLATFORM_NAME = "wecom_external_bridge"
PLUGIN_VERSION = "1.1.0"
PLUGIN_DIR = Path(__file__).resolve().parent
AGENT_PATH = PLUGIN_DIR / "agent" / "monitor.js"

DEFAULT_CONFIG = {
    "frida_host": "host.docker.internal",
    "frida_port": 27042,
    "frida_token": "",
    "frida_connect_timeout_seconds": 15,
    "process_name": "企业微信",
    "wecom_pid": 0,
    "allowed_group_ids": [],
    "bot_user_id": "",
    "bot_display_name": "数字员工",
    "capture_only": True,
    "send_enabled": False,
    "require_outer_group": True,
    "require_mention_id_match": True,
    "max_text_chars": 4000,
    "poll_interval_seconds": 0.75,
    "poll_message_count": 50,
    "reconnect_seconds": 3,
    "reply_aggregate_seconds": 0.5,
    "send_min_interval_seconds": 0.2,
    "sent_echo_guard_seconds": 86400,
    "event_retention_days": 7,
}

_LEADING_MENTION = re.compile(r"^\s*@\S+\s*")


def _as_string_set(value: Any) -> set[str]:
    if isinstance(value, str):
        values = value.replace("\n", ",").split(",")
    elif isinstance(value, list):
        values = value
    else:
        values = []
    return {str(item).strip() for item in values if str(item).strip()}


def _as_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off", ""}:
            return False
    if isinstance(value, (int, float)):
        return bool(value)
    return default


def _as_float(value: Any, default: float, minimum: float, maximum: float) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(parsed, maximum))


def _as_int(value: Any, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(parsed, maximum))


def _plain_text(message: MessageChain) -> str:
    return "".join(
        component.text
        for component in message.chain
        if isinstance(component, Plain) and component.text
    ).strip()


def _text_fingerprint(text: str) -> str:
    return hashlib.sha256(text.strip().encode("utf-8")).hexdigest()


def _string(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _stable_message_id(payload: dict[str, Any]) -> str:
    for name in ("msgKey", "messageId", "serverId", "clientId"):
        value = _string(payload.get(name))
        if value:
            return value
    return ""


def _clean_text(text: str, display_name: str) -> str:
    value = text.replace("\u2005", " ").strip()
    if display_name and value.startswith(f"@{display_name}"):
        value = value[len(f"@{display_name}") :].lstrip(" :：\n\t")
    else:
        value = _LEADING_MENTION.sub("", value, count=1).strip()
    return value


class BridgeStateDatabase:
    def __init__(self) -> None:
        try:
            from astrbot.core.star.star_tools import StarTools

            data_dir = Path(StarTools.get_data_dir(PLUGIN_NAME))
        except Exception:
            data_dir = Path("data/plugin_data") / PLUGIN_NAME
        data_dir.mkdir(parents=True, exist_ok=True)
        self.path = data_dir / "frida_adapter.db"
        self._lock = threading.RLock()
        self.connection = sqlite3.connect(
            self.path,
            check_same_thread=False,
            isolation_level=None,
        )
        self.connection.row_factory = sqlite3.Row
        try:
            self.path.chmod(0o600)
        except OSError:
            pass
        with self._lock:
            self.connection.execute("PRAGMA journal_mode=WAL")
            self.connection.execute("PRAGMA synchronous=FULL")
            self.connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS events (
                    cursor INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL UNIQUE,
                    group_id TEXT NOT NULL,
                    message_id TEXT NOT NULL,
                    sender_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    received_at REAL NOT NULL,
                    acked_at REAL
                );

                CREATE UNIQUE INDEX IF NOT EXISTS events_group_message
                    ON events(group_id, message_id);
                CREATE INDEX IF NOT EXISTS events_unacked
                    ON events(acked_at, cursor);

                CREATE TABLE IF NOT EXISTS sends (
                    request_id TEXT PRIMARY KEY,
                    group_id TEXT NOT NULL,
                    text_sha256 TEXT NOT NULL,
                    state TEXT NOT NULL,
                    message_id TEXT,
                    error TEXT,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS sends_echo_guard
                    ON sends(group_id, text_sha256, state, updated_at);

                CREATE TABLE IF NOT EXISTS seen_messages (
                    message_key TEXT PRIMARY KEY,
                    first_seen_at REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS state (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                """
            )

    def close(self) -> None:
        with self._lock:
            self.connection.close()

    def accept_event(self, event: dict[str, Any]) -> tuple[bool, int | None]:
        payload_json = json.dumps(
            event,
            ensure_ascii=False,
            separators=(",", ":"),
        )
        with self._lock:
            try:
                cursor = self.connection.execute(
                    """
                    INSERT INTO events(
                        event_id, group_id, message_id, sender_id,
                        payload_json, received_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event["event_id"],
                        event["group_id"],
                        event["message_id"],
                        event["sender_id"],
                        payload_json,
                        time.time(),
                    ),
                ).lastrowid
            except sqlite3.IntegrityError:
                row = self.connection.execute(
                    "SELECT cursor FROM events WHERE event_id = ?",
                    (event["event_id"],),
                ).fetchone()
                return False, int(row["cursor"]) if row is not None else None
            return True, int(cursor)

    def unacked_events(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            rows = self.connection.execute(
                """
                SELECT cursor, payload_json
                FROM events
                WHERE acked_at IS NULL
                ORDER BY cursor ASC
                LIMIT ?
                """,
                (max(1, min(limit, 500)),),
            ).fetchall()
        events: list[dict[str, Any]] = []
        for row in rows:
            payload = json.loads(row["payload_json"])
            payload["cursor"] = int(row["cursor"])
            events.append(payload)
        return events

    def ack(self, cursor: int) -> int:
        with self._lock:
            result = self.connection.execute(
                """
                UPDATE events
                SET acked_at = COALESCE(acked_at, ?)
                WHERE cursor <= ?
                """,
                (time.time(), max(0, cursor)),
            )
        return int(result.rowcount)

    def remember_message(self, message_key: str) -> bool:
        if not message_key:
            return True
        with self._lock:
            try:
                self.connection.execute(
                    """
                    INSERT INTO seen_messages(message_key, first_seen_at)
                    VALUES (?, ?)
                    """,
                    (message_key, time.time()),
                )
            except sqlite3.IntegrityError:
                return False
        return True

    def has_seen_message(self, message_key: str) -> bool:
        if not message_key:
            return False
        with self._lock:
            row = self.connection.execute(
                "SELECT 1 FROM seen_messages WHERE message_key = ?",
                (message_key,),
            ).fetchone()
        return row is not None

    def latest_seen_message_id(self, group_id: str) -> str:
        prefix = f"{group_id}:"
        with self._lock:
            row = self.connection.execute(
                """
                SELECT message_key
                FROM seen_messages
                WHERE substr(message_key, 1, ?) = ?
                ORDER BY CAST(substr(message_key, ?) AS INTEGER) DESC
                LIMIT 1
                """,
                (len(prefix), prefix, len(prefix) + 1),
            ).fetchone()
        if row is None:
            return ""
        value = str(row["message_key"])
        return value[len(prefix) :] if value.startswith(prefix) else ""

    def recent_sent_text(
        self,
        group_id: str,
        text_sha256: str,
        within_seconds: int,
    ) -> bool:
        cutoff = time.time() - max(1, within_seconds)
        with self._lock:
            row = self.connection.execute(
                """
                SELECT 1
                FROM sends
                WHERE group_id = ?
                  AND text_sha256 = ?
                  AND state = 'sent'
                  AND updated_at >= ?
                LIMIT 1
                """,
                (group_id, text_sha256, cutoff),
            ).fetchone()
        return row is not None

    def reserve_send(
        self,
        request_id: str,
        group_id: str,
        text_sha256: str,
        stale_seconds: int = 120,
    ) -> tuple[bool, dict[str, Any]]:
        now = time.time()
        with self._lock:
            row = self.connection.execute(
                "SELECT * FROM sends WHERE request_id = ?",
                (request_id,),
            ).fetchone()
            if row is None:
                self.connection.execute(
                    """
                    INSERT INTO sends(
                        request_id, group_id, text_sha256, state,
                        created_at, updated_at
                    ) VALUES (?, ?, ?, 'pending', ?, ?)
                    """,
                    (request_id, group_id, text_sha256, now, now),
                )
                return True, {"state": "pending"}

            record = dict(row)
            if record["state"] == "sent":
                return False, record
            if (
                record["state"] in {"pending", "sending"}
                and now - float(record["updated_at"]) < stale_seconds
            ):
                return False, record
            self.connection.execute(
                """
                UPDATE sends
                SET group_id = ?, text_sha256 = ?, state = 'pending',
                    message_id = NULL, error = NULL, updated_at = ?
                WHERE request_id = ?
                """,
                (group_id, text_sha256, now, request_id),
            )
            return True, {"state": "pending"}

    def mark_send_sending(self, request_id: str) -> None:
        with self._lock:
            self.connection.execute(
                """
                UPDATE sends
                SET state = 'sending', error = NULL, updated_at = ?
                WHERE request_id = ?
                """,
                (time.time(), request_id),
            )

    def finish_send(
        self,
        request_id: str,
        state: str,
        message_id: str | None = None,
        error: str | None = None,
    ) -> None:
        with self._lock:
            self.connection.execute(
                """
                UPDATE sends
                SET state = ?, message_id = ?, error = ?, updated_at = ?
                WHERE request_id = ?
                """,
                (state, message_id, error, time.time(), request_id),
            )

    def prune(self, retention_days: int) -> None:
        before = time.time() - max(1, retention_days) * 86400
        with self._lock:
            self.connection.execute(
                """
                DELETE FROM events
                WHERE acked_at IS NOT NULL AND acked_at < ?
                """,
                (before,),
            )
            self.connection.execute(
                "DELETE FROM seen_messages WHERE first_seen_at < ?",
                (before,),
            )
            self.connection.execute(
                "DELETE FROM sends WHERE updated_at < ?",
                (before,),
            )


class FridaRuntime:
    def __init__(
        self,
        database: BridgeStateDatabase,
        *,
        host: str,
        port: int,
        token: str,
        process_name: str,
        wecom_pid: int,
        allowed_group_ids: set[str],
        bot_user_id: str,
        bot_display_name: str,
        require_outer_group: bool,
        require_mention_id_match: bool,
        max_text_chars: int,
        poll_interval_seconds: float,
        poll_message_count: int,
        reconnect_seconds: float,
        sent_echo_guard_seconds: int,
        send_min_interval_seconds: float,
        event_retention_days: int,
        connect_timeout_seconds: float,
    ) -> None:
        self.database = database
        self.host = host
        self.port = port
        self.token = token
        self.process_name = process_name
        self.wecom_pid = wecom_pid
        self.allowed_group_ids = allowed_group_ids
        self.bot_user_id = bot_user_id
        self.bot_display_name = bot_display_name
        self.require_outer_group = require_outer_group
        self.require_mention_id_match = require_mention_id_match
        self.max_text_chars = max_text_chars
        self.poll_interval_seconds = poll_interval_seconds
        self.poll_message_count = poll_message_count
        self.reconnect_seconds = reconnect_seconds
        self.sent_echo_guard_seconds = sent_echo_guard_seconds
        self.send_min_interval_seconds = send_min_interval_seconds
        self.event_retention_days = event_retention_days
        self.connect_timeout_seconds = connect_timeout_seconds
        self.address = f"{host}:{port}"

        self.attached = False
        self.pid: int | None = None
        self.last_error: str | None = None
        self.last_poll_error: str | None = None
        self.last_event_at: float | None = None
        self.last_poll_at: float | None = None
        self.last_poll_duration_seconds: float | None = None
        self.last_poll_metrics: dict[str, Any] = {}
        self.connected_at: float | None = None
        self.poll_rounds = 0
        self.poll_messages_seen = 0
        self.accepted_events = 0
        self.filter_reasons: Counter[str] = Counter()

        self._manager: Any = None
        self._device: Any = None
        self._session: Any = None
        self._script: Any = None
        self._attach_task: asyncio.Task[None] | None = None
        self._poll_task: asyncio.Task[None] | None = None
        self._stopping = False
        self._rpc_lock = asyncio.Lock()
        self._event_ready = asyncio.Event()
        self._send_requested = asyncio.Event()
        self._send_waiters = 0
        self._last_send_at = 0.0
        self._executor = ThreadPoolExecutor(
            # Frida RPC is not safe to overlap. A timed-out Python future can
            # leave the native call running, so all operations share one lane.
            max_workers=1,
            thread_name_prefix="wecom-frida",
        )
        self._executor_shutdown = False
        self._stop_lock = asyncio.Lock()
        self._stopped = False

    async def _run_blocking(self, function: Any, *args: Any) -> Any:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            self._executor,
            partial(function, *args),
        )

    async def start(self) -> None:
        if frida is None:
            raise RuntimeError("frida Python package is not installed")
        if self._attach_task is None:
            self._attach_task = asyncio.create_task(
                self._attach_forever(),
                name="wecom-frida-attach",
            )
        if self._poll_task is None:
            self._poll_task = asyncio.create_task(
                self._poll_forever(),
                name="wecom-frida-poll",
            )

    async def stop(self) -> None:
        async with self._stop_lock:
            if self._stopped:
                return
            self._stopped = True
            self._stopping = True
            for task in (self._attach_task, self._poll_task):
                if task is not None:
                    task.cancel()
            for task in (self._attach_task, self._poll_task):
                if task is not None:
                    await asyncio.gather(task, return_exceptions=True)
            self._attach_task = None
            self._poll_task = None
            if not self._executor_shutdown:
                await self._run_blocking(self._detach)
                self._executor.shutdown(wait=False, cancel_futures=True)
                self._executor_shutdown = True

    async def wait_for_event(self, timeout: float) -> None:
        await asyncio.wait_for(self._event_ready.wait(), timeout=timeout)

    def clear_event(self) -> None:
        self._event_ready.clear()

    async def _attach_forever(self) -> None:
        while not self._stopping:
            if not self.attached:
                try:
                    await self._run_blocking(self._attach)
                except asyncio.CancelledError:
                    raise
                except Exception as error:
                    self.last_error = self._error_detail(error)
                    logger.warning(
                        "[wecom_external_bridge] Frida 接入失败: %s",
                        self.last_error,
                    )
            await asyncio.sleep(self.reconnect_seconds)

    @staticmethod
    def _error_detail(error: BaseException) -> str:
        name = type(error).__name__
        message = str(error).strip()
        representation = repr(error)
        if message:
            return f"{name}: {message}"[:300]
        if representation and representation != "None":
            return f"{name}: {representation}"[:300]
        return name

    @staticmethod
    def _is_fatal_frida_error(error: BaseException) -> bool:
        detail = (
            f"{type(error).__name__} {error!s} {error!r}"
        ).lower()
        markers = (
            "script has been destroyed",
            "script is destroyed",
            "device is gone",
            "device has gone away",
            "connection is closed",
            "unable to connect to remote frida-server",
            "process terminated",
            "invalid operation on closed",
        )
        return any(marker in detail for marker in markers)

    def _attach(self) -> None:
        if frida is None:
            raise RuntimeError("frida Python package is not installed")
        self._detach()
        manager = frida.get_device_manager()
        try:
            manager.remove_remote_device(self.address)
        except Exception:
            pass
        device = manager.add_remote_device(
            self.address,
            token=self.token,
        )
        processes = device.enumerate_processes()
        candidates = [
            process
            for process in processes
            if process.name == self.process_name
        ]
        if self.wecom_pid > 0:
            candidates = [
                process
                for process in candidates
                if int(process.pid) == self.wecom_pid
            ]
        if not candidates:
            raise RuntimeError(
                f"未找到企业微信进程: {self.process_name}"
            )
        selected = candidates[0]
        if len(candidates) > 1:
            logger.warning(
                "[wecom_external_bridge] 发现多个同名企业微信进程，使用 pid=%s",
                selected.pid,
            )

        session = device.attach(int(selected.pid))
        if not AGENT_PATH.exists():
            raise RuntimeError(f"Frida Agent 不存在: {AGENT_PATH}")
        script = session.create_script(
            AGENT_PATH.read_text(encoding="utf-8"),
            name="wecom-external-bridge",
        )
        self._manager = manager
        self._device = device
        self._session = session
        self._script = script
        script.on("message", self._on_script_message)
        script.on("destroyed", self._on_script_destroyed)
        script.load()
        health = script.exports_sync.health()
        if not isinstance(health, dict) or not health.get("ok"):
            raise RuntimeError("Frida Agent 健康检查失败")

        self.attached = True
        self.pid = int(selected.pid)
        self.connected_at = time.time()
        self.last_error = None
        logger.info(
            "[wecom_external_bridge] 已通过远程 Frida 接入企业微信 pid=%s",
            self.pid,
        )

    def _detach(self) -> None:
        script, session, manager = self._script, self._session, self._manager
        address = self.address
        self._script = None
        self._session = None
        self._device = None
        self._manager = None
        self.attached = False
        self.pid = None
        if script is not None:
            try:
                script.unload()
            except Exception:
                pass
        if session is not None:
            try:
                session.detach()
            except Exception:
                pass
        if manager is not None:
            try:
                manager.remove_remote_device(address)
            except Exception:
                pass

    def _on_script_message(
        self,
        message: dict[str, Any],
        data: bytes | None,
    ) -> None:
        del data
        if message.get("type") == "error":
            self.last_error = str(
                message.get("description") or "Frida Agent error"
            )[:300]
            logger.error(
                "[wecom_external_bridge] Frida Agent 错误: %s",
                self.last_error,
            )
            return
        payload = message.get("payload")
        if isinstance(payload, dict) and payload.get("kind") == "ready":
            logger.info("[wecom_external_bridge] Frida 原生消息监听器已就绪")

    def _on_script_destroyed(self, *_args: Any) -> None:
        self.attached = False
        self._script = None
        if not self._stopping:
            self.last_error = "Frida Agent 已断开"

    @staticmethod
    def _payload_message_key(payload: dict[str, Any]) -> str:
        message = payload.get("data")
        if not isinstance(message, dict):
            return ""
        conversation = message.get("conversation")
        group_id = (
            _string(conversation.get("id"))
            if isinstance(conversation, dict)
            else ""
        )
        message_id = _stable_message_id(message)
        if not message_id:
            return ""
        return f"{group_id}:{message_id}" if group_id else message_id

    def _build_event(
        self,
        payload: dict[str, Any],
    ) -> tuple[dict[str, Any] | None, str]:
        if payload.get("kind") != "message":
            return None, "not_parsed_message"
        message = payload.get("data")
        if not isinstance(message, dict):
            return None, "invalid_message"
        conversation = message.get("conversation")
        if not isinstance(conversation, dict):
            return None, "missing_conversation"

        group_id = _string(conversation.get("id"))
        if not group_id:
            return None, "missing_group_id"
        if group_id not in self.allowed_group_ids:
            return None, "group_not_allowed"
        if self.require_outer_group and message.get(
            "isOuterGroup",
            conversation.get("isOuterGroup"),
        ) is not True:
            return None, "not_outer_group"
        if message.get("isSelf") is True:
            return None, "self_message"
        if message.get("isAtMe") is not True:
            return None, "not_at_bot"
        if "contentType" in message:
            try:
                content_type = int(message.get("contentType"))
            except (TypeError, ValueError):
                return None, "invalid_content_type"
            if content_type != 1:
                return None, "unsupported_content_type"

        sender = message.get("sender")
        if not isinstance(sender, dict):
            return None, "missing_sender"
        sender_id = _string(sender.get("id"))
        if not sender_id:
            return None, "missing_sender_id"
        if self.bot_user_id and sender_id == self.bot_user_id:
            return None, "self_message"

        mentions = message.get("mentions")
        mention_ids = (
            [str(value).strip() for value in mentions if str(value).strip()]
            if isinstance(mentions, list)
            else []
        )
        if (
            self.require_mention_id_match
            and self.bot_user_id
            and self.bot_user_id not in mention_ids
        ):
            return None, "mention_target_mismatch"

        text = _clean_text(
            _string(message.get("text")),
            self.bot_display_name,
        )
        if not text:
            return None, "empty_text"
        if len(text) > self.max_text_chars:
            return None, "text_too_long"
        if self.database.recent_sent_text(
            group_id,
            _text_fingerprint(text),
            self.sent_echo_guard_seconds,
        ):
            return None, "recent_bot_echo"

        message_id = _stable_message_id(message)
        if not message_id:
            return None, "missing_message_id"
        event_id = hashlib.sha256(
            f"{group_id}\0{message_id}".encode("utf-8")
        ).hexdigest()
        try:
            timestamp = int(float(message.get("timestamp")))
        except (TypeError, ValueError):
            timestamp = int(time.time())
        return {
            "event_id": event_id,
            "group_id": group_id,
            "group_name": _string(conversation.get("name")) or group_id,
            "message_id": message_id,
            "sender_id": sender_id,
            "sender_name": (
                _string(sender.get("name"))
                or _string(sender.get("realName"))
                or sender_id
            ),
            "text": text,
            "mention_ids": mention_ids,
            "is_self": False,
            "timestamp": timestamp,
            "raw_source": _string(payload.get("source")),
        }, "accepted"

    def _ingest_payload(self, payload: dict[str, Any]) -> None:
        message_key = self._payload_message_key(payload)
        if message_key and self.database.has_seen_message(message_key):
            self.filter_reasons["already_seen_message"] += 1
            return
        event, reason = self._build_event(payload)
        if event is None:
            if message_key:
                self.database.remember_message(message_key)
            self.filter_reasons[reason] += 1
            return
        inserted, _ = self.database.accept_event(event)
        if message_key:
            self.database.remember_message(message_key)
        if not inserted:
            self.filter_reasons["duplicate_event"] += 1
            return
        self.accepted_events += 1
        self.last_event_at = time.time()
        self._event_ready.set()
        logger.info(
            "[wecom_external_bridge] 接收事件 id=%s group=%s",
            event["event_id"][:12],
            event["group_id"],
        )

    async def _poll_once(self) -> None:
        if not self.allowed_group_ids:
            return
        group_ids = sorted(self.allowed_group_ids)
        known_message_ids = {
            group_id: self.database.latest_seen_message_id(group_id)
            for group_id in group_ids
        }
        async with self._rpc_lock:
            if self._send_requested.is_set():
                return
            script = self._require_script()
            started_at = time.monotonic()
            response = await self._run_blocking(
                script.exports_sync.poll_messages,
                group_ids,
                self.bot_user_id,
                self.poll_message_count,
                known_message_ids,
            )
            self.last_poll_duration_seconds = (
                time.monotonic() - started_at
            )
        if not isinstance(response, dict):
            raise RuntimeError("消息轮询返回无效结果")
        self.last_poll_metrics = {
            "callback_count": int(response.get("callbackCount") or 0),
            "timed_out": bool(response.get("timedOut")),
            "agent_duration_ms": int(response.get("durationMs") or 0),
            "service_count": int(response.get("serviceCount") or 0),
        }
        self.poll_rounds += 1
        self.last_poll_at = time.time()
        errors = response.get("errors")
        if isinstance(errors, list) and errors:
            self.last_poll_error = "; ".join(
                str(value)[:200] for value in errors[:3]
            )
        else:
            self.last_poll_error = None
        messages = response.get("messages")
        if not isinstance(messages, list):
            if not response.get("ok"):
                raise RuntimeError(
                    str(response.get("error") or "消息轮询失败")
                )
            return
        self.poll_messages_seen += len(messages)
        for message in messages:
            if isinstance(message, dict):
                self._ingest_payload(
                    {
                        "kind": "message",
                        "source": "native_poll",
                        "data": message,
                    }
                )

    async def _poll_forever(self) -> None:
        while not self._stopping:
            if self.attached:
                try:
                    await self._poll_once()
                except asyncio.CancelledError:
                    raise
                except Exception as error:
                    self.last_poll_error = self._error_detail(error)
                    if self._is_fatal_frida_error(error):
                        self.attached = False
                        self.last_error = self.last_poll_error
                        self._script = None
                    logger.warning(
                        "[wecom_external_bridge] 消息轮询失败: %s",
                        self.last_poll_error,
                    )
            await asyncio.sleep(self.poll_interval_seconds)

    def _require_script(self) -> Any:
        if not self.attached or self._script is None:
            raise RuntimeError("企业微信尚未通过 Frida 接入")
        return self._script

    async def send_text(
        self,
        group_id: str,
        text: str,
        request_id: str,
    ) -> dict[str, Any]:
        if group_id not in self.allowed_group_ids:
            raise RuntimeError("目标群不在白名单")
        if len(text) > self.max_text_chars:
            raise RuntimeError("回复文本过长")
        digest = _text_fingerprint(text)
        can_send, record = self.database.reserve_send(
            request_id,
            group_id,
            digest,
        )
        if not can_send:
            if record.get("state") == "sent":
                return {"ok": True, "duplicate": True}
            raise RuntimeError(
                f"回复正在处理或此前失败: {record.get('state')}"
            )

        self._send_waiters += 1
        self._send_requested.set()
        try:
            async with self._rpc_lock:
                elapsed = time.monotonic() - self._last_send_at
                if elapsed < self.send_min_interval_seconds:
                    await asyncio.sleep(
                        self.send_min_interval_seconds - elapsed
                    )
                script = self._require_script()
                self.database.mark_send_sending(request_id)
                try:
                    result = await self._run_blocking(
                        script.exports_sync.send_text,
                        group_id,
                        text,
                        request_id,
                    )
                except Exception as error:
                    self.last_error = self._error_detail(error)
                    if self._is_fatal_frida_error(error):
                        self.attached = False
                        self._script = None
                    raise
                if not isinstance(result, dict) or not result.get("ok"):
                    raise RuntimeError(
                        str(
                            result.get("error")
                            if isinstance(result, dict)
                            else "原生发送失败"
                        )[:200]
                    )
                self.database.finish_send(
                    request_id,
                    "sent",
                    message_id=(
                        _string(result.get("message_id")) or None
                    ),
                )
                self._last_send_at = time.monotonic()
                return result
        except Exception as error:
            self.database.finish_send(
                request_id,
                "failed",
                error=type(error).__name__,
            )
            raise
        finally:
            self._send_waiters = max(0, self._send_waiters - 1)
            if self._send_waiters == 0:
                self._send_requested.clear()

    def status(self) -> dict[str, Any]:
        return {
            "attached": self.attached,
            "pid": self.pid,
            "last_error": self.last_error,
            "last_poll_error": self.last_poll_error,
            "connected_at": self.connected_at,
            "last_poll_at": self.last_poll_at,
            "last_poll_duration_seconds": self.last_poll_duration_seconds,
            "last_poll_metrics": dict(self.last_poll_metrics),
            "poll_rounds": self.poll_rounds,
            "poll_messages_seen": self.poll_messages_seen,
            "accepted_events": self.accepted_events,
            "filter_reasons": dict(self.filter_reasons),
        }


class WeComExternalBridgeEvent(AstrMessageEvent):
    def __init__(
        self,
        message_str: str,
        message_obj: AstrBotMessage,
        platform_meta: PlatformMetadata,
        session_id: str,
        adapter: "WeComExternalBridgeAdapter",
    ) -> None:
        super().__init__(message_str, message_obj, platform_meta, session_id)
        self.adapter = adapter
        raw = message_obj.raw_message
        self.event_id = (
            _string(raw.get("event_id"))
            if isinstance(raw, dict)
            else ""
        )
        if not self.event_id:
            self.event_id = uuid.uuid4().hex
        self._pending_reply_parts: list[str] = []
        self._reply_flush_task: asyncio.Task[None] | None = None
        self._reply_batch_index = 0
        self._reply_lock = asyncio.Lock()

    async def send(self, message: MessageChain) -> None:
        text = _plain_text(message)
        if not text:
            logger.warning(
                "[wecom_external_bridge] 忽略非文本回复"
            )
            return
        async with self._reply_lock:
            self._pending_reply_parts.append(text)
            if (
                self._reply_flush_task is None
                or self._reply_flush_task.done()
            ):
                self._reply_flush_task = asyncio.create_task(
                    self._flush_pending_reply()
                )
        await super().send(message)

    async def _flush_pending_reply(self) -> None:
        try:
            while True:
                await asyncio.sleep(self.adapter.reply_aggregate_seconds)
                async with self._reply_lock:
                    parts = self._pending_reply_parts
                    self._pending_reply_parts = []
                if not parts:
                    return
                text = "\n".join(
                    part.strip() for part in parts if part.strip()
                )
                if not text:
                    continue
                batch_index = self._reply_batch_index
                self._reply_batch_index += 1
                started_at = time.monotonic()
                await self.adapter.send_group_text(
                    self.get_group_id(),
                    text,
                    request_id=f"{self.event_id}:reply:{batch_index}",
                )
                logger.info(
                    "[wecom_external_bridge] 回复完成 event=%s parts=%s "
                    "chars=%s elapsed=%.3fs",
                    self.event_id[:12],
                    len(parts),
                    len(text),
                    time.monotonic() - started_at,
                )
                async with self._reply_lock:
                    if not self._pending_reply_parts:
                        return
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception(
                "[wecom_external_bridge] 回复发送失败 event=%s",
                self.event_id[:12],
            )
        finally:
            async with self._reply_lock:
                if self._reply_flush_task is asyncio.current_task():
                    self._reply_flush_task = None
                if self._pending_reply_parts:
                    self._reply_flush_task = asyncio.create_task(
                        self._flush_pending_reply()
                    )

    async def send_streaming(
        self,
        generator: Any,
        use_fallback: bool = False,
    ) -> None:
        del use_fallback
        parts: list[str] = []
        async for chain in generator:
            if isinstance(chain, MessageChain):
                text = _plain_text(chain)
                if text:
                    parts.append(text)
        if parts:
            await self.send(MessageChain([Plain("\n".join(parts))]))


@register_platform_adapter(
    PLATFORM_NAME,
    "企业微信外部客户群原生 Frida 接入",
    default_config_tmpl=dict(DEFAULT_CONFIG),
    adapter_display_name="企业微信外部客户群",
    support_streaming_message=False,
)
class WeComExternalBridgeAdapter(Platform):
    def __init__(
        self,
        platform_config: dict,
        platform_settings: dict,
        event_queue: asyncio.Queue,
    ) -> None:
        super().__init__(platform_config, event_queue)
        del platform_settings
        self.allowed_group_ids = _as_string_set(
            platform_config.get("allowed_group_ids", [])
        )
        self.bot_user_id = _string(platform_config.get("bot_user_id"))
        self.bot_display_name = (
            _string(platform_config.get("bot_display_name")) or "数字员工"
        )
        self.capture_only = _as_bool(
            platform_config.get("capture_only"),
            True,
        )
        self.send_enabled = _as_bool(
            platform_config.get("send_enabled"),
            False,
        )
        self.reply_aggregate_seconds = _as_float(
            platform_config.get("reply_aggregate_seconds"),
            0.5,
            0.0,
            5.0,
        )
        self.database = BridgeStateDatabase()
        self.runtime = FridaRuntime(
            self.database,
            host=(
                _string(platform_config.get("frida_host"))
                or "host.docker.internal"
            ),
            port=_as_int(
                platform_config.get("frida_port"),
                27042,
                1,
                65535,
            ),
            token=_string(platform_config.get("frida_token")),
            process_name=(
                _string(platform_config.get("process_name")) or "企业微信"
            ),
            wecom_pid=_as_int(
                platform_config.get("wecom_pid"),
                0,
                0,
                2**31 - 1,
            ),
            allowed_group_ids=self.allowed_group_ids,
            bot_user_id=self.bot_user_id,
            bot_display_name=self.bot_display_name,
            require_outer_group=_as_bool(
                platform_config.get("require_outer_group"),
                True,
            ),
            require_mention_id_match=_as_bool(
                platform_config.get("require_mention_id_match"),
                True,
            ),
            max_text_chars=_as_int(
                platform_config.get("max_text_chars"),
                4000,
                1,
                20000,
            ),
            poll_interval_seconds=_as_float(
                platform_config.get("poll_interval_seconds"),
                0.75,
                0.25,
                10.0,
            ),
            poll_message_count=_as_int(
                platform_config.get("poll_message_count"),
                50,
                1,
                100,
            ),
            reconnect_seconds=_as_float(
                platform_config.get("reconnect_seconds"),
                3.0,
                1.0,
                60.0,
            ),
            sent_echo_guard_seconds=_as_int(
                platform_config.get("sent_echo_guard_seconds"),
                86400,
                60,
                7 * 86400,
            ),
            send_min_interval_seconds=_as_float(
                platform_config.get("send_min_interval_seconds"),
                0.2,
                0.0,
                10.0,
            ),
            event_retention_days=_as_int(
                platform_config.get("event_retention_days"),
                7,
                1,
                90,
            ),
            connect_timeout_seconds=_as_float(
                platform_config.get("frida_connect_timeout_seconds"),
                15.0,
                1.0,
                120.0,
            ),
        )
        self._stopped = False

    def meta(self) -> PlatformMetadata:
        return PlatformMetadata(
            name=PLATFORM_NAME,
            description="企业微信外部客户群原生 Frida 接入",
            id=cast(str, self.config.get("id") or PLATFORM_NAME),
            adapter_display_name="企业微信外部客户群",
            support_streaming_message=False,
            support_proactive_message=False,
        )

    def _validate_event(self, data: dict[str, Any]) -> bool:
        group_id = _string(data.get("group_id"))
        event_id = _string(data.get("event_id"))
        text = _string(data.get("text"))
        if not group_id or not event_id or not text:
            return False
        if group_id not in self.allowed_group_ids:
            return False
        if data.get("is_self") is True:
            return False
        if self.bot_user_id:
            if _string(data.get("sender_id")) == self.bot_user_id:
                return False
            mentions = data.get("mention_ids") or []
            if self.bot_user_id not in {
                str(value) for value in mentions
            }:
                return False
        return not self.database.recent_sent_text(
            group_id,
            _text_fingerprint(text),
            self.runtime.sent_echo_guard_seconds,
        )

    def _to_astrbot_event(self, data: dict[str, Any]) -> AstrMessageEvent:
        group_id = _string(data["group_id"])
        sender_id = _string(data["sender_id"])
        text = _string(data["text"])
        message_id = _string(data["message_id"])

        message = AstrBotMessage()
        message.type = MessageType.GROUP_MESSAGE
        message.self_id = self.bot_user_id
        message.session_id = group_id
        message.message_id = message_id
        message.group = Group(
            group_id=group_id,
            group_name=_string(data.get("group_name")) or group_id,
        )
        message.sender = MessageMember(
            user_id=sender_id,
            nickname=_string(data.get("sender_name")) or sender_id,
        )
        message.message_str = text
        message.message = [
            At(qq=self.bot_user_id, name=self.bot_display_name),
            Plain(text),
        ]
        message.raw_message = data
        try:
            message.timestamp = int(data.get("timestamp"))
        except (TypeError, ValueError):
            message.timestamp = int(time.time())

        event = WeComExternalBridgeEvent(
            message_str=text,
            message_obj=message,
            platform_meta=self.meta(),
            session_id=group_id,
            adapter=self,
        )
        event.is_wake = True
        event.is_at_or_wake_command = True
        return event

    async def _handle_event(self, data: dict[str, Any]) -> None:
        event_id = _string(data.get("event_id"))
        cursor = int(data.get("cursor") or 0)
        if not event_id:
            return
        if not self._validate_event(data):
            logger.warning(
                "[wecom_external_bridge] 拒绝事件 id=%s",
                event_id[:12],
            )
            self.database.ack(cursor)
            return
        if self.capture_only:
            logger.info(
                "[wecom_external_bridge] capture_only event=%s group=%s",
                event_id[:12],
                data.get("group_id"),
            )
            self.database.ack(cursor)
            return
        event = self._to_astrbot_event(data)
        self.commit_event(event)
        self.database.ack(cursor)

    async def run(self) -> None:
        if frida is None:
            logger.error(
                "[wecom_external_bridge] 缺少 frida==17.26.0，适配器不会启动"
            )
            return
        if not self.runtime.token:
            logger.error(
                "[wecom_external_bridge] frida_token 未配置，适配器不会启动"
            )
            return
        if not self.allowed_group_ids:
            logger.warning(
                "[wecom_external_bridge] allowed_group_ids 为空，不会处理任何群"
            )
        if not self.bot_user_id:
            logger.warning(
                "[wecom_external_bridge] bot_user_id 为空，不会接收任何 @ 消息"
            )
        await self.runtime.start()
        last_prune = 0.0
        last_status = 0.0
        try:
            while not self._stopped:
                events = self.database.unacked_events(limit=100)
                if not events:
                    self.runtime.clear_event()
                    try:
                        await self.runtime.wait_for_event(timeout=1.0)
                    except asyncio.TimeoutError:
                        pass
                    events = self.database.unacked_events(limit=100)
                for data in events:
                    await self._handle_event(data)

                now = time.monotonic()
                if now - last_prune > 3600:
                    self.database.prune(self.runtime.event_retention_days)
                    last_prune = now
                if now - last_status > 60:
                    status = self.runtime.status()
                    poll_duration = status["last_poll_duration_seconds"]
                    poll_ms = (
                        "-"
                        if poll_duration is None
                        else f"{float(poll_duration) * 1000:.0f}ms"
                    )
                    logger.info(
                        "[wecom_external_bridge] status attached=%s pid=%s "
                        "poll=%s poll_ms=%s poll_detail=%s "
                        "accepted=%s filters=%s",
                        status["attached"],
                        status["pid"],
                        status["poll_rounds"],
                        poll_ms,
                        status["last_poll_metrics"],
                        status["accepted_events"],
                        status["filter_reasons"],
                    )
                    last_status = now
        except asyncio.CancelledError:
            raise
        finally:
            await self.runtime.stop()

    async def send_group_text(
        self,
        group_id: str,
        text: str,
        request_id: str,
    ) -> None:
        if not self.send_enabled:
            raise RuntimeError("send_enabled 未开启")
        await self.runtime.send_text(group_id, text, request_id)

    async def send_by_session(
        self,
        session: MessageSesion,
        message_chain: MessageChain,
    ) -> None:
        if session.message_type != MessageType.GROUP_MESSAGE:
            raise RuntimeError("仅支持外部客户群文本消息")
        text = _plain_text(message_chain)
        if not text:
            raise RuntimeError("仅支持纯文本回复")
        request_id = (
            f"session:{session.session_id}:"
            f"{_text_fingerprint(text)[:16]}:"
            f"{uuid.uuid4().hex}"
        )
        await self.send_group_text(
            session.session_id,
            text,
            request_id,
        )
        await super().send_by_session(session, message_chain)

    async def terminate(self) -> None:
        if self._stopped:
            return
        self._stopped = True
        await self.runtime.stop()
        self.database.close()
        logger.info("[wecom_external_bridge] 适配器已停止并释放 Frida 会话")


@register(
    PLUGIN_NAME,
    "jiangbkvir",
    "在 AstrBot 插件内运行企业微信外部客户群原生桥接",
    PLUGIN_VERSION,
)
class WeComExternalBridgePlugin(Star):
    def __init__(self, context: Context, config: dict | None = None):
        super().__init__(context)
        self.config = dict(config or {})
