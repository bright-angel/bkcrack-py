"""Progress reporting and cancellation, mirroring ``Progress.hpp``."""

from __future__ import annotations

import sys
from enum import Enum
from typing import Optional, TextIO, Union

__all__ = ["State", "Progress"]


class State(Enum):
    """Possible states of a long running operation."""

    NORMAL = "normal"
    CANCELED = "canceled"
    EARLY_EXIT = "early exit"


class Progress:
    """Track progress of a long operation and allow canceling it.

    The C++ version uses atomics and a mutex to protect the output stream.  In
    Python, the GIL makes the counters safe enough for our usage and parallel
    workers run in separate processes, so a callback based interface is used.
    """

    __slots__ = ("state", "done", "total", "stream")

    def __init__(self, stream: Optional[TextIO] = None) -> None:
        self.state = State.NORMAL
        self.done = 0
        self.total = 0
        self.stream = stream if stream is not None else sys.stdout

    def log(self, message: Union[str, bytes]) -> None:
        """Write a log *message* to the output stream.

        Byte messages are written as is so that non ASCII passwords are
        displayed like the original implementation does.
        """
        if isinstance(message, bytes):
            buffer = getattr(self.stream, "buffer", None)
            if buffer is None:  # pragma: no cover - text only streams
                print(message.decode("utf-8", "replace"), file=self.stream, flush=True)
            else:
                self.stream.flush()
                buffer.write(message + b"\n")
                buffer.flush()
        else:
            print(message, file=self.stream, flush=True)

    def cancel(self) -> None:
        """Request cancellation of the operation."""
        self.state = State.CANCELED
