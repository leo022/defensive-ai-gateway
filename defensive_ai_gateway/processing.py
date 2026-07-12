from __future__ import annotations

import queue
import threading
import time
from dataclasses import dataclass
from typing import Callable

from .models import RawAlert


class AlertQueueFull(Exception):
    """Raised when the bounded alert queue refuses a new item."""


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
            "rejected": self.rejected,
        }


class AlertProcessor:
    """Bounded worker pool that decouples alert intake from analysis."""

    def __init__(self, handler: Callable[[RawAlert], object], *, max_size: int = 5000, workers: int = 4):
        self._handler = handler
        self._queue: queue.Queue[RawAlert] = queue.Queue(maxsize=max(1, int(max_size)))
        self._worker_count = max(1, int(workers))
        self._threads: list[threading.Thread] = []
        self._lock = threading.Lock()
        self._started = False
        self._stopped = False
        self._submitted = 0
        self._processed = 0
        self._failed = 0
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

    def stop(self, timeout: float = 5.0) -> None:
        """Stop accepting work and drain the queue without a shutdown deadlock.

        The previous sentinel-based shutdown could block forever when all workers
        were busy and the bounded queue was full. Workers now poll with a short
        timeout, drain accepted alerts, then exit once the queue is empty. The
        join has one shared deadline so server shutdown remains bounded even when
        an LLM call is slow or unavailable.
        """
        with self._lock:
            if self._stopped:
                return
            self._stopped = True
            threads = list(self._threads)
        deadline = time.monotonic() + max(0, timeout)
        for thread in threads:
            thread.join(timeout=max(0, deadline - time.monotonic()))

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
                rejected=self._rejected,
            )

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
                self._handler(item)
            except Exception as exc:  # noqa: BLE001 - recorded, not allowed to kill intake
                print(f"[gateway] alert worker failed for {item.alert_id}: {exc!r}")
                with self._lock:
                    self._failed += 1
            else:
                with self._lock:
                    self._processed += 1
            finally:
                with self._lock:
                    self._inflight -= 1
                self._queue.task_done()
