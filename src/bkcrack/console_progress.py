"""Progress reporting on a console, mirroring ``ConsoleProgress.cpp``.

The C++ implementation starts a thread which overwrites the current line with
the progress percentage every 200 ms.  This port does the same with a daemon
thread.  :meth:`ConsoleProgress.log` clears the progress line before printing a
message so that log lines are not garbled.
"""

from __future__ import annotations

import threading
from typing import Optional, TextIO, Union

from .progress import Progress

__all__ = ["ConsoleProgress"]

#: Delay between two progress refreshes, in seconds.
DEFAULT_INTERVAL = 0.2


class ConsoleProgress(Progress):
    """Print the progress of an operation on a terminal, overwriting one line."""

    def __init__(
        self, stream: Optional[TextIO] = None, interval: float = DEFAULT_INTERVAL
    ) -> None:
        super().__init__(stream)
        self.interval = interval
        self._length_to_clear = 0
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._run, name="bkcrack-progress", daemon=True
        )
        self._thread.start()

    # -- context manager ---------------------------------------------------

    def __enter__(self) -> "ConsoleProgress":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    def close(self) -> None:
        """Stop the printer thread after printing the final progress line."""
        self._stop.set()
        self._thread.join()

    # -- progress line -----------------------------------------------------

    def get_progress_line(self) -> str:
        """Return the line to display, or an empty string if there is nothing to show."""
        total = self.total
        if not total:
            return ""

        done = self.done
        return f"{100.0 * done / total:.1f} % ({done} / {total})"

    def _print_line(self, final: bool) -> None:
        line = self.get_progress_line()
        if not line:
            return

        with self._lock:
            padding = ""
            if len(line) < self._length_to_clear:
                padding = " " * (self._length_to_clear - len(line))

            self.stream.write("\r" + line + padding)
            if final:
                self.stream.write("\n")
                self._length_to_clear = 0
            else:
                self._length_to_clear = len(line)
            self.stream.flush()

    def _run(self) -> None:
        # Give a small delay before the first print so that the running
        # operation is likely to have initialized the total number of steps.
        self._stop.wait(0.001)

        while not self._stop.is_set():
            self._print_line(final=False)
            self._stop.wait(self.interval)

        self._print_line(final=True)

    # -- logging -----------------------------------------------------------

    def log(self, message: Union[str, bytes]) -> None:
        """Print *message* on its own line, clearing the progress line first."""
        with self._lock:
            if self._length_to_clear:
                self.stream.write("\r" + " " * self._length_to_clear + "\r")
                self._length_to_clear = 0

            if isinstance(message, bytes):
                buffer = getattr(self.stream, "buffer", None)
                if buffer is None:  # pragma: no cover - text only streams
                    self.stream.write(message.decode("utf-8", "replace") + "\n")
                else:
                    self.stream.flush()
                    buffer.write(message + b"\n")
                    buffer.flush()
                return

            self.stream.write(message + "\n")
            self.stream.flush()
