"""Parallel candidate attack using multiple processes.

The attack is embarrassingly parallel over ``Z[2,32)`` candidates.  Since the
Python interpreter serializes CPU bound threads with the GIL, worker processes
are used instead of threads (the C++ implementation uses threads).
"""

from __future__ import annotations

import io
from multiprocessing import get_context
from typing import List, Sequence, Tuple

from .constants import CONTIGUOUS_SIZE
from .data import Data
from .keys import Keys
from .progress import Progress, State

__all__ = ["parallel_attack"]

#: Number of candidates handed to a worker at once.  Small enough to keep the
#: attack responsive when a solution is found early.
CHUNK_SIZE = 64

_WORKER: dict = {}


def _initializer(data: Data, index: int, exhaustive: bool) -> None:
    _WORKER["data"] = data
    _WORKER["index"] = index
    _WORKER["exhaustive"] = exhaustive


def _run_chunk(chunk: Tuple[int, Sequence[int]]) -> Tuple[int, int, List[Tuple[int, int, int]], List[str]]:
    """Attack a slice of candidates and report where it stopped."""
    chunk_start, candidates = chunk

    from .attack import Attack

    data = _WORKER["data"]
    index = _WORKER["index"]
    exhaustive = _WORKER["exhaustive"]

    stream = io.StringIO()
    progress = Progress(stream=stream)
    solutions: List[Keys] = []
    worker = Attack(data, index, solutions, exhaustive, progress)

    consumed = 0
    for candidate in candidates:
        worker.carryout(candidate)
        consumed += 1
        if progress.state is not State.NORMAL:
            break

    logs = [line for line in stream.getvalue().splitlines() if line]

    return (
        chunk_start,
        consumed,
        [solution.as_tuple() for solution in solutions],
        logs,
    )


def parallel_attack(
    data: Data,
    zi_2_32_vector: Sequence[int],
    start: int,
    index: int,
    jobs: int,
    exhaustive: bool,
    progress: Progress,
) -> Tuple[List[Keys], int]:
    """Run the attack on several processes and return ``(solutions, restart)``."""
    size = len(zi_2_32_vector)

    chunks = []
    for chunk_start in range(start, size, CHUNK_SIZE):
        chunks.append((chunk_start, list(zi_2_32_vector[chunk_start : chunk_start + CHUNK_SIZE])))

    solutions: List[Keys] = []
    consumed_by_chunk = {}
    failures = False

    context = get_context("spawn")
    pool = context.Pool(
        processes=max(1, min(jobs, len(chunks))),
        initializer=_initializer,
        initargs=(data, index, exhaustive),
    )

    try:
        for chunk_start, consumed, solutions_tuples, logs in pool.imap_unordered(_run_chunk, chunks):
            for message in logs:
                progress.log(message)

            for x, y, z in solutions_tuples:
                solutions.append(Keys(x, y, z))

            progress.done = max(progress.done, chunk_start + consumed)

            consumed_by_chunk[chunk_start] = consumed

            if progress.state is State.CANCELED:
                failures = True
                break
            if solutions and not exhaustive:
                progress.state = State.EARLY_EXIT
                failures = True
                break
    finally:
        pool.terminate()
        pool.join()

    # Restart at the first candidate that was not explored so that a later run
    # does not skip any candidate.
    if failures:
        restart = min(
            chunk_start + consumed_by_chunk.get(chunk_start, 0)
            for chunk_start, _ in chunks
        )
    else:
        restart = len(zi_2_32_vector)

    return solutions, restart
