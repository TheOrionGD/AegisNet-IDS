import json
import logging
import asyncio
import uuid
import datetime
from collections import deque
from typing import Dict, Any, List, Optional, Callable, Awaitable
from pathlib import Path
from dataclasses import dataclass, field
from threading import Thread
import time

logger = logging.getLogger(__name__)


@dataclass
class StreamEvent:
    """Normalized event from Snort JSON."""

    timestamp: str
    src_ip: str
    dst_ip: str
    src_port: int = 0
    dst_port: int = 0
    protocol: str = "UNKNOWN"
    pkt_len: int = 0
    alert_msg: str = ""
    rule_sid: Optional[int] = None
    raw_data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "pkt_len": self.pkt_len,
            "alert_msg": self.alert_msg,
            "rule_sid": self.rule_sid,
            "raw_data": self.raw_data,
        }


class StreamProcessor:
    """
    Real-time stream processor for Snort JSON alerts.
    Handles incremental parsing, buffering, and callback dispatch.
    """

    def __init__(
        self,
        buffer_size: int = 1000,
        flush_interval: float = 1.0,
    ):
        self.buffer_size = buffer_size
        self.flush_interval = flush_interval
        self._buffer: deque = deque(maxlen=buffer_size)
        self._callbacks: List[Callable[[StreamEvent], Awaitable[None]]] = []
        self._running = False
        self._lock = asyncio.Lock()
        self._stats = {
            "events_processed": 0,
            "events_dropped": 0,
            "last_processed_at": None,
        }

    def add_callback(self, callback: Callable[[StreamEvent], Awaitable[None]]) -> None:
        """Register an async callback to be called for each processed event."""
        self._callbacks.append(callback)

    async def _dispatch(self, event: StreamEvent) -> None:
        """Dispatch event to all registered callbacks."""
        for callback in self._callbacks:
            try:
                await callback(event)
            except Exception as e:
                logger.error(f"Callback error: {e}")

    async def push_event(self, raw_event: Dict[str, Any]) -> Optional[StreamEvent]:
        """
        Parse and push a raw event into the stream.
        Returns the parsed StreamEvent or None if parsing failed.
        """
        try:
            event = self._parse_event(raw_event)
            if event:
                async with self._lock:
                    self._buffer.append(event)
                    self._stats["events_processed"] += 1
                    self._stats["last_processed_at"] = datetime.datetime.now(
                        timezone.utc
                    ).isoformat()
                await self._dispatch(event)
            return event
        except Exception as e:
            logger.error(f"Event push error: {e}")
            self._stats["events_dropped"] += 1
            return None

    def _parse_event(self, raw: Dict[str, Any]) -> Optional[StreamEvent]:
        """Parse raw JSON dict into StreamEvent."""
        event = raw.get("event", {}) if isinstance(raw.get("event"), dict) else {}
        source = (
            event.get("source", {}) if isinstance(event.get("source"), dict) else {}
        )
        destination = (
            event.get("destination", {})
            if isinstance(event.get("destination"), dict)
            else {}
        )

        timestamp = (
            raw.get("timestamp")
            or raw.get("time")
            or event.get("timestamp")
            or raw.get("ts")
        )
        if not timestamp:
            timestamp = datetime.datetime.now().isoformat()

        src_ip = (
            source.get("ip") or raw.get("src_ip") or raw.get("src_addr") or "0.0.0.0"
        )
        dst_ip = (
            destination.get("ip")
            or raw.get("dst_ip")
            or raw.get("dst_addr")
            or "0.0.0.0"
        )

        src_port = source.get("port") or raw.get("src_port") or 0
        dst_port = destination.get("port") or raw.get("dst_port") or 0

        protocol = (
            event.get("protocol") or raw.get("protocol") or raw.get("proto") or "TCP"
        )
        if isinstance(protocol, str):
            protocol = protocol.upper()
        else:
            protocol = "UNKNOWN"

        pkt_len = (
            event.get("packet", {}).get("length")
            or raw.get("pkt_len")
            or raw.get("pkt_num")
            or 0
        )

        alert = raw.get("alert", {}) if isinstance(raw.get("alert"), dict) else {}
        alert_msg = alert.get("msg") or raw.get("msg") or ""

        rule_sid = alert.get("sid") or raw.get("sid")

        return StreamEvent(
            timestamp=timestamp,
            src_ip=str(src_ip),
            dst_ip=str(dst_ip),
            src_port=int(src_port) if src_port else 0,
            dst_port=int(dst_port) if dst_port else 0,
            protocol=protocol,
            pkt_len=int(pkt_len) if pkt_len else 0,
            alert_msg=alert_msg,
            rule_sid=int(rule_sid) if rule_sid else None,
            raw_data=raw,
        )

    async def get_buffer(self) -> List[StreamEvent]:
        """Get current buffer contents."""
        async with self._lock:
            return list(self._buffer)

    def get_stats(self) -> Dict[str, Any]:
        """Get processing statistics."""
        return self._stats.copy()

    def clear_buffer(self) -> None:
        """Clear the event buffer."""
        self._buffer.clear()


class FileWatcher:
    """
    File tailing for real-time log monitoring.
    Uses a pointer file to persist position across restarts.
    """

    def __init__(
        self,
        file_path: str,
        processor: StreamProcessor,
        callback: Optional[Callable[[List[Dict[str, Any]]], Awaitable[None]]] = None,
    ):
        self.file_path = Path(file_path)
        self.processor = processor
        self.callback = callback
        self.pointer_file = f"{file_path}.pointer"
        self._file_handle = None
        self._running = False

    def _load_pointer(self) -> int:
        """Load last saved offset."""
        if Path(self.pointer_file).exists():
            try:
                with open(self.pointer_file, "r") as f:
                    return int(f.read().strip())
            except Exception:
                pass
        return 0

    def _save_pointer(self, offset: int) -> None:
        """Save current file position."""
        try:
            with open(self.pointer_file, "w") as f:
                f.write(str(offset))
        except Exception as e:
            logger.error(f"Failed to save pointer: {e}")

    def _read_new_lines(self) -> List[Dict[str, Any]]:
        """Read new lines from the file."""
        if not self.file_path.exists():
            return []

        current_offset = self._load_pointer()
        current_size = self.file_path.stat().st_size

        if current_size < current_offset:
            logger.info("Log file rotated, resetting offset")
            current_offset = 0

        if self._file_handle is None or self._file_handle.closed:
            self._file_handle = open(self.file_path, "r")
            self._file_handle.seek(current_offset)

        new_lines = self._file_handle.readlines()
        events = []
        for line in new_lines:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                logger.warning(f"Malformed JSON: {line[:100]}")

        if events:
            self._save_pointer(self._file_handle.tell())

        return events

    async def start(self) -> None:
        """Start watching the file."""
        self._running = True
        while self._running:
            try:
                events = self._read_new_lines()
                for event in events:
                    await self.processor.push_event(event)
                if events and self.callback:
                    await self.callback(events)
            except Exception as e:
                logger.error(f"FileWatcher error: {e}")
            await asyncio.sleep(0.5)

    def stop(self) -> None:
        """Stop watching."""
        self._running = False
        if self._file_handle:
            self._file_handle.close()


class LogStreamListener:
    """
    High-level stream listener that manages file watching
    and dispatches events to callbacks.
    """

    def __init__(
        self,
        log_file: str,
        buffer_size: int = 1000,
    ):
        self.log_file = log_file
        self.processor = StreamProcessor(buffer_size=buffer_size)
        self.watcher: Optional[FileWatcher] = None
        self._task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        """Start listening for log events."""
        self.watcher = FileWatcher(self.log_file, self.processor)
        self._task = asyncio.create_task(self.watcher.start())
        logger.info(f"LogStreamListener started: {self.log_file}")

    async def stop(self) -> None:
        """Stop listening."""
        if self.watcher:
            self.watcher.stop()
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("LogStreamListener stopped")

    def add_callback(self, callback: Callable[[StreamEvent], Awaitable[None]]) -> None:
        """Register callback for processed events."""
        self.processor.add_callback(callback)
