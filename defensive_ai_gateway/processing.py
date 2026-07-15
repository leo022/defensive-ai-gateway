from __future__ import annotations

import queue
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Callable

from .models import RawAlert


class AlertQueueFull(Exception):
    """Raised when the bounded alert queue refuses a new item."""


@dataclass(frozen=True)
class DeadLetter:
    """An accepted alert that could not reach a terminal processed state.

    ``dead_letter_handler`` can persist this object in an external inbox/DLQ.
    A bounded in-process copy is retained as a diagnostic fallback so a missing
    hook does not make terminal failures invisible.
    """

    alert: RawAlert
    attempts: int
    reason: str
    error: str
    created_at_ms: int

    def to_dict(self) -> dict:
        return {
            "alert_id": self.alert.alert_id,
            "product": self.alert.product,
            "alert": {
                "alert_id": self.alert.alert_id,
                "source": self.alert.source,
                "product": self.alert.product,
                "event_type": self.alert.event_type,
                "severity": self.alert.severity,
                "timestamp": self.alert.timestamp,
                "payload": self.alert.payload,
                "trusted_sample": self.alert.trusted_sample,
            },
            "attempts": self.attempts,
            "reason": self.reason,
            "error": self.error,
            "created_at_ms": self.created_at_ms,
        }


@dataclass
class AlertProcessorStats:
    enabled: bool
    queue_max_size: int
    workers: int
    queued: int
    inflight: int
    submitted: int
    processed: int
    failed: int
    retried: int
    dead_lettered: int
    rejected: int

    def to_dict(self) -> dict:
        return {
            "enabled": self.enabled,
            "queue_max_size": self.queue_max_size,
            "workers": self.workers,
            "queued": self.queued,
            "inflight": self.inflight,
            "submitted": self.submitted,
            "processed": self.processed,
            "failed": self.failed,
            "retried": self.retried,
            "dead_lettered": self.dead_lettered,
            "rejected": self.rejected,
        }


class AlertProcessor:
    """Bounded worker pool that decouples alert intake from analysis."""

    def __init__(
        self,
        handler: Callable[[RawAlert], object],
        *,
        max_size: int = 5000,
        workers: int = 4,
        max_attempts: int = 3,
        retry_base_delay: float = 0.1,
        retry_max_delay: float = 2.0,
        dead_letter_handler: Callable[[DeadLetter], object] | None = None,
        dead_letter_max_size: int = 1000,
    ):
        self._handler = handler
        self._queue: queue.Queue[RawAlert] = queue.Queue(maxsize=max(1, int(max_size)))
        self._worker_count = max(1, int(workers))
        self._max_attempts = max(1, int(max_attempts))
        self._retry_base_delay = max(0.0, float(retry_base_delay))
        self._retry_max_delay = max(self._retry_base_delay, float(retry_max_delay))
        self._dead_letter_handler = dead_letter_handler
        self._dead_letters: deque[DeadLetter] = deque(maxlen=max(1, int(dead_letter_max_size)))
        self._threads: list[threading.Thread] = []
        self._lock = threading.Lock()
        self._abort = threading.Event()
        self._started = False
        self._stopped = False
        self._submitted = 0
        self._processed = 0
        self._failed = 0
        self._retried = 0
        self._dead_lettered = 0
        self._rejected = 0
        self._inflight = 0

    def start(self) -> None:
        with self._lock:
            if self._started:
                return
            if self._stopped:
                raise RuntimeError("cannot start a stopped alert processor")
            self._started = True
            for idx in range(self._worker_count):
                thread = threading.Thread(target=self._run, name=f"alert-worker-{idx + 1}", daemon=True)
                thread.start()
                self._threads.append(thread)

    def submit(self, alert: RawAlert) -> None:
        with self._lock:
            if self._stopped:
                self._rejected += 1
                raise AlertQueueFull("alert processor is stopped")
            try:
                self._queue.put_nowait(alert)
            except queue.Full as exc:
                self._rejected += 1
                raise AlertQueueFull("alert queue is full") from exc
            self._submitted += 1

    def wait_for_idle(self, timeout: float | None = None) -> bool:
        """Wait until all submitted work has been processed.

        ``queue.Queue.join`` has no timeout. Polling its unfinished-task count
        avoids creating a disposable waiting thread for every health/test call.
        """
        if timeout is None:
            self._queue.join()
            return self.stats().inflight == 0
        deadline = time.monotonic() + max(0, timeout)
        while True:
            if self._queue.unfinished_tasks == 0:
                stats = self.stats()
                if stats.inflight == 0 and stats.queued == 0:
                    return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.01)

    def stop(self, timeout: float = 5.0) -> bool:
        """Stop accepting work and try to drain within one shared deadline.

        The previous sentinel-based shutdown could block forever when all workers
        were busy and the bounded queue was full. Workers now poll with a short
        timeout and drain accepted alerts. If the deadline expires, pending work
        that has not started is moved to the DLQ and busy calls are allowed to
        finish in daemon workers. ``True`` means every worker exited gracefully;
        ``False`` means the deadline was reached.
        """
        with self._lock:
            if self._stopped:
                return not any(thread.is_alive() for thread in self._threads)
            self._stopped = True
            threads = list(self._threads)
        deadline = time.monotonic() + max(0, timeout)
        for thread in threads:
            thread.join(timeout=max(0, deadline - time.monotonic()))
        alive = [thread for thread in threads if thread.is_alive()]
        if alive:
            self._abort.set()
            self._drain_pending_to_dead_letter("shutdown_timeout")
            return False
        self._abort.set()
        self._drain_pending_to_dead_letter("shutdown_timeout")
        return True

    def stats(self) -> AlertProcessorStats:
        with self._lock:
            return AlertProcessorStats(
                enabled=True,
                queue_max_size=self._queue.maxsize,
                workers=self._worker_count,
                queued=self._queue.qsize(),
                inflight=self._inflight,
                submitted=self._submitted,
                processed=self._processed,
                failed=self._failed,
                retried=self._retried,
                dead_lettered=self._dead_lettered,
                rejected=self._rejected,
            )

    def is_healthy(self) -> bool:
        """Return whether the configured worker pool is running as expected."""
        with self._lock:
            return (
                self._started
                and not self._stopped
                and len(self._threads) == self._worker_count
                and all(thread.is_alive() for thread in self._threads)
            )

    def dead_letters(self) -> list[DeadLetter]:
        """Return the bounded diagnostic DLQ snapshot, oldest first."""
        with self._lock:
            return list(self._dead_letters)

    def _run(self) -> None:
        while True:
            try:
                item = self._queue.get(timeout=0.2)
            except queue.Empty:
                with self._lock:
                    if self._stopped:
                        return
                continue
            with self._lock:
                self._inflight += 1
            try:
                if self._abort.is_set():
                    self._record_dead_letter(item, 0, "shutdown_timeout", "processor shutdown deadline reached")
                else:
                    self._process_with_retry(item)
            finally:
                with self._lock:
                    self._inflight -= 1
                self._queue.task_done()

    def _process_with_retry(self, alert: RawAlert) -> None:
        for attempt in range(1, self._max_attempts + 1):
            try:
                self._handler(alert)
            except Exception as exc:  # noqa: BLE001 - failure is retried/DLQed, worker survives
                if attempt < self._max_attempts and not self._abort.is_set():
                    with self._lock:
                        self._retried += 1
                    delay = min(self._retry_max_delay, self._retry_base_delay * (2 ** (attempt - 1)))
                    if delay and self._abort.wait(delay):
                        self._record_dead_letter(alert, attempt, "shutdown_timeout", repr(exc))
                        return
                    continue
                reason = "shutdown_timeout" if self._abort.is_set() else "handler_error"
                print(
                    f"[gateway] alert worker exhausted for {alert.alert_id} "
                    f"after {attempt} attempt(s): {exc!r}"
                )
                self._record_dead_letter(alert, attempt, reason, repr(exc))
                return
            else:
                with self._lock:
                    self._processed += 1
                return

    def _record_dead_letter(self, alert: RawAlert, attempts: int, reason: str, error: str) -> None:
        entry = DeadLetter(
            alert=alert,
            attempts=max(0, int(attempts)),
            reason=str(reason),
            error=str(error),
            created_at_ms=int(time.time() * 1000),
        )
        with self._lock:
            self._failed += 1
            self._dead_lettered += 1
            self._dead_letters.append(entry)
        if not self._dead_letter_handler:
            return
        try:
            self._dead_letter_handler(entry)
        except Exception as exc:  # noqa: BLE001 - retain local DLQ even when external sink fails
            print(f"[gateway] dead-letter hook failed for {alert.alert_id}: {exc!r}")

    def _drain_pending_to_dead_letter(self, reason: str) -> None:
        while True:
            try:
                alert = self._queue.get_nowait()
            except queue.Empty:
                return
            try:
                self._record_dead_letter(alert, 0, reason, "alert did not start before shutdown deadline")
            finally:
                self._queue.task_done()
