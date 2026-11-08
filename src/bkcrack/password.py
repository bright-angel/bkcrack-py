"""Password recovery, mirroring ``password.cpp``.

The algorithm recovers the last six characters of a password from the internal
state, then bruteforces the remaining characters in front of them.  Every
password candidate whose internal state matches is reported, because several
passwords can lead to the same state.

The reference implementation parallelizes long searches with threads.  This port
runs them serially: results are identical, only the progress reporting of long
searches differs.
"""

from __future__ import annotations

from typing import List, Optional, Sequence, Tuple

from .constants import MASK_24_32, MAXDIFF_24, MULT, MULT_INV, U32
from .keys import Keys
from .progress import Progress, State
from .tables import crc32, crc32inv, get_yi_24_32, msb_prod_fiber2

__all__ = ["recover_password", "recover_password_for_mask"]


def _password_line(password: bytes) -> bytes:
    """Build the ``Password: <password>`` log line, as raw bytes."""
    return b"Password: " + password


def _password_out_of_space_line(password: bytes) -> bytes:
    """Build the ``Password: <password> (as bytes: ...)`` log line."""
    hex_bytes = b"".join(b" %02x" % byte for byte in password)
    return b"Password: " + password + b" (as bytes:" + hex_bytes + b")"


class _SixCharactersRecovery:
    """Recover the last six bytes of a password from the internal state."""

    def __init__(self) -> None:
        # possible Z0[16,32) and Z{-1}[24,32) values for the given charset
        self.z0_16_32: set = set()
        self.zm1_24_32: set = set()

        # cipher state (X, Y, Z)_i for i in [0, 6]; state 6 is the target
        self.x = [0] * 7
        self.y = [0] * 7
        self.z = [0] * 7

        self.candidate_x0 = 0
        self.p = [0] * 6

    def set_target(self, target: Keys, charset5: Sequence[int]) -> None:
        """Prepare the search for the given target state and 6th password byte set."""
        x = self.x
        y = self.y
        z = self.z

        x[6] = target.x
        y[6] = target.y
        z[6] = target.z

        # derive Y5
        y[5] = ((y[6] - 1) * MULT_INV - (x[6] & 0xFF)) & U32

        # derive more Z bytes
        for i in range(6, 1, -1):
            z[i - 1] = crc32inv(z[i], y[i] >> 24)

        # precompute possible Z0[16,32) and Z{-1}[24,32)
        self.z0_16_32 = set()
        self.zm1_24_32 = set()

        for p5 in charset5:
            x[5] = crc32inv(x[6], p5)
            y[4] = ((y[5] - 1) * MULT_INV - (x[5] & 0xFF)) & U32
            z[3] = crc32inv(z[4], y[4] >> 24)

            y3_ignoring_lsb_x4 = ((y[4] - 1) * MULT_INV) & U32
            msb_y3_min = (y3_ignoring_lsb_x4 - 255) >> 24
            msb_y3_max = y3_ignoring_lsb_x4 >> 24

            z[2] = crc32inv(z[3], msb_y3_min)
            z[1] = crc32inv(z[2], 0)
            z[0] = crc32inv(z[1], 0)

            self.z0_16_32.add(z[0] >> 16)
            self.zm1_24_32.add(crc32inv(z[0], 0) >> 24)

            if msb_y3_max != msb_y3_min:
                z[2] = crc32inv(z[3], msb_y3_max)
                z[1] = crc32inv(z[2], 0)
                z[0] = crc32inv(z[1], 0)

                self.z0_16_32.add(z[0] >> 16)
                self.zm1_24_32.add(crc32inv(z[0], 0) >> 24)

    def search(self, initial: Keys) -> None:
        """Search for a password suffix matching the target from *initial*."""
        x = self.x
        y = self.y
        z = self.z

        # check compatible Z0[16,32)
        if (initial.z >> 16) not in self.z0_16_32:
            return

        x[0] = self.candidate_x0 = initial.x
        y[0] = initial.y
        z[0] = initial.z

        # complete Z values and derive Y[24,32) values
        for i in range(1, 5):
            y[i] = get_yi_24_32(z[i], z[i - 1])
            z[i] = crc32(z[i - 1], y[i] >> 24)

        self._search_recursive(5)

    def _search_recursive(self, i: int) -> None:
        x = self.x
        y = self.y

        if i != 1:
            fy = ((y[i] - 1) * MULT_INV) & U32
            ffy = ((fy - 1) * MULT_INV) & U32
            y_i2_24_32 = y[i - 2] & MASK_24_32

            # get possible LSB(Xi)
            for xi_0_8 in msb_prod_fiber2(((ffy - y_i2_24_32) & U32) >> 24):
                yim1 = (fy - xi_0_8) & U32

                # filter values with Y{i-2}[24,32)
                if (
                    (ffy - MULT_INV * xi_0_8 - y_i2_24_32) & U32
                ) <= MAXDIFF_24 and (yim1 >> 24) == (y[i - 1] >> 24):
                    y[i - 1] = yim1
                    x[i] = xi_0_8
                    self._search_recursive(i - 1)
        else:
            # only the X1 LSB was not set yet
            x1 = ((y[1] - 1) * MULT_INV - y[0]) & U32
            if x1 > 0xFF:
                return
            x[1] = x1

            # complete X values and derive password
            for j in range(5, -1, -1):
                xi_xor_pi = crc32inv(x[j + 1], 0)
                self.p[j] = (xi_xor_pi ^ x[j]) & 0xFF
                x[j] = xi_xor_pi ^ self.p[j]

            if x[0] == self.candidate_x0:
                self.on_solution_found()

    def on_solution_found(self) -> None:  # pragma: no cover - overridden
        raise NotImplementedError


class _BruteforceRecovery(_SixCharactersRecovery):
    """Recover a password by bruteforcing its first characters."""

    def __init__(
        self,
        keys: Keys,
        charset: Sequence[int],
        solutions: List[bytes],
        exhaustive: bool,
        progress: Progress,
    ) -> None:
        super().__init__()
        self.charset = charset
        self.solutions = solutions
        self.exhaustive = exhaustive
        self.progress = progress
        self.length = 0
        self.prefix = bytearray()

        self.set_target(keys, charset)

    # -- search ------------------------------------------------------------

    def search(self, length: int, start: bytes = b"") -> bytes:
        """Search for a password of the given *length*, returning a restart point."""
        self.prefix = bytearray()
        self.length = length

        if length <= 6:
            self._search_short()
            return b""

        if length <= 9:
            self._search_long_recursive(Keys())
            return b""

        self.progress.done = 0
        self.progress.total = len(self.charset) * len(self.charset)
        return self._search_long_parallel_recursive(Keys(), start, b"")

    def on_solution_found(self) -> None:
        password = bytearray(self.prefix)
        password.extend(self.p)
        del password[: max(0, len(password) - self.length)]

        if not all(c in self.charset for c in password):
            self.progress.log(_password_out_of_space_line(bytes(password)))
            self.progress.log("Some characters are not in the expected charset. Continuing.")
            return

        self.solutions.append(bytes(password))
        self.progress.log(_password_line(bytes(password)))

        if not self.exhaustive:
            self.progress.state = State.EARLY_EXIT

    # -- internal ----------------------------------------------------------

    def _search_short(self) -> None:
        """Look for a password of length 6 or less."""
        initial = Keys()
        # update the initial state backward so that there are exactly 6 updates
        # between it and the target state
        for _ in range(self.length, 6):
            initial.update_backward_plaintext(self.charset[0])

        self.search_state(initial)

    def search_state(self, initial: Keys) -> None:
        """Run the six characters recovery from the given state."""
        _SixCharactersRecovery.search(self, initial)

    def _search_long_recursive(self, initial: Keys) -> None:
        """Look for a password of length 7 or more, recursing on prefix characters."""
        if len(self.prefix) + 7 == self.length:
            # there is only one more character to bruteforce
            if initial.z >> 24 not in self.zm1_24_32:
                return

            self.prefix.append(self.charset[0])

            # precompute as much as possible without knowing the password byte
            x0_partial = crc32(initial.x, 0)
            y0_partial = (initial.y * MULT + 1) & U32
            z0_partial = crc32(initial.z, 0)

            for pi in self.charset:
                x0 = x0_partial ^ crc32(0, pi)
                y0 = (y0_partial + MULT * (x0 & 0xFF)) & U32
                z0 = z0_partial ^ crc32(0, y0 >> 24)

                if (z0 >> 16) not in self.z0_16_32:
                    continue

                self.prefix[-1] = pi
                self.search_state(Keys(x0, y0, z0))

            self.prefix.pop()
        else:
            self.prefix.append(self.charset[0])

            for pi in self.charset:
                init = Keys(initial.x, initial.y, initial.z)
                init.update(pi)

                self.prefix[-1] = pi
                self._search_long_recursive(init)

            self.prefix.pop()

    # -- parallel exploration, simulated with a single worker ---------------

    def _search_long_parallel_recursive(
        self, initial: Keys, start: bytes, restart: bytes
    ) -> bytes:
        charset = self.charset
        charset_size = len(charset)

        index_start = 0
        if len(self.prefix) < len(start):
            while index_start < charset_size and charset[index_start] < start[len(self.prefix)]:
                index_start += 1

        if len(self.prefix) + 1 + 9 == self.length:
            # bruteforce one character in parallel
            self.prefix.append(charset[0])
            self.progress.done += index_start * charset_size

            index = index_start
            while index < charset_size:
                pm4 = charset[index]

                init = Keys(initial.x, initial.y, initial.z)
                init.update(pm4)
                self.prefix[-1] = pm4

                self._search_long_recursive(init)
                self.progress.done += charset_size

                index += 1
                if self.progress.state is not State.NORMAL:
                    break

            self.prefix.pop()

            if index < charset_size:
                restart = bytes(self.prefix)
                restart += bytes([charset[index]])
                restart += bytes([charset[0]]) * (self.length - 6 - len(restart))

            return restart

        if len(self.prefix) + 2 + 9 == self.length:
            # bruteforce two characters in parallel
            index_start *= charset_size
            if len(self.prefix) + 1 < len(start):
                max_index = min(charset_size * charset_size, index_start + charset_size)
                while (
                    index_start < max_index
                    and charset[index_start % charset_size] < start[len(self.prefix) + 1]
                ):
                    index_start += 1

            self.prefix.extend(bytes([charset[0], charset[0]]))

            report_progress = len(self.prefix) == 2
            report_progress_coarse = len(self.prefix) == 3

            if report_progress:
                self.progress.done += index_start
            elif report_progress_coarse:
                self.progress.done += index_start // charset_size

            index = index_start
            while index < charset_size * charset_size:
                pm4 = charset[index // charset_size]
                pm3 = charset[index % charset_size]

                init = Keys(initial.x, initial.y, initial.z)
                init.update(pm4)
                init.update(pm3)

                self.prefix[-2] = pm4
                self.prefix[-1] = pm3

                self._search_long_recursive(init)

                if report_progress or (
                    report_progress_coarse and index % charset_size == charset_size - 1
                ):
                    self.progress.done += 1

                index += 1
                if self.progress.state is not State.NORMAL:
                    break

            self.prefix.pop()
            self.prefix.pop()

            if index < charset_size * charset_size:
                restart = bytes(self.prefix)
                restart += bytes(
                    [charset[index // charset_size], charset[index % charset_size]]
                )
                restart += bytes([charset[0]]) * (self.length - 6 - len(restart))

            return restart

        # try password prefixes recursively
        self.prefix.append(charset[0])

        report_progress = len(self.prefix) == 2

        if len(self.prefix) == 1:
            self.progress.done += index_start * charset_size
        elif report_progress:
            self.progress.done += index_start

        index = index_start
        while index < charset_size:
            pi = charset[index]

            init = Keys(initial.x, initial.y, initial.z)
            init.update(pi)

            self.prefix[-1] = pi

            if self.progress.state is not State.NORMAL:
                restart = bytes(self.prefix)
                restart += bytes([charset[0]]) * (self.length - 6 - len(restart))
                break

            restart = self._search_long_parallel_recursive(
                init, start if index == index_start else b"", restart
            )

            # Because the recursive call may explore only a fraction of its search
            # space, check that it was run in full before counting progress.
            if restart:
                break

            if report_progress:
                self.progress.done += 1

            index += 1

        self.prefix.pop()

        return restart


class _MaskRecovery(_SixCharactersRecovery):
    """Recover a password following a mask of character sets.

    The mask is split in three parts: a prefix, a six-character factor and a
    suffix.  The factor start index is chosen to minimize the estimated search
    cost.  The suffix characters are explored in reverse order, then the prefix
    characters, and each complete decision is passed to the six-character
    recovery which recovers the factor.

    The reference implementation hands out pairs of decisions to worker threads.
    This port explores them serially, but keeps the same traversal order,
    progress accounting and restart semantics.
    """

    def __init__(
        self,
        keys: Keys,
        mask: Sequence[Sequence[int]],
        solutions: List[bytes],
        exhaustive: bool,
        progress: Progress,
    ) -> None:
        super().__init__()
        self.target = keys
        self.mask = mask
        self.solutions = solutions
        self.exhaustive = exhaustive
        self.progress = progress

        #: sequence of choices to build reversed(suffix) + prefix
        self.decisions = bytearray()
        self.factor_index = self._compute_factor_index()
        self.suffix_size = 0 if len(mask) < 7 else len(mask) - self.factor_index - 6
        self.parallel_depth = self._compute_parallel_depth()
        self.progress_depth = self._compute_progress_depth()

    # -- preparation -------------------------------------------------------

    def _compute_factor_index(self) -> int:
        """Choose the position of the six characters factor minimizing the cost."""
        mask = self.mask
        if len(mask) < 7:
            return 0

        def cost(f: int) -> float:
            p = 1.0
            for i in range(f):
                p *= len(mask[i])

            s = 1.0
            for i in range(f + 6, len(mask)):
                s *= len(mask[i])

            m5 = float(len(mask[f + 5]))
            mm1 = float(len(mask[f - 1])) if f else 1.0
            zm1_ratio = m5 / 256.0 if f else 1.0

            a = s * m5
            b = s * p * (1.0 - zm1_ratio) / mm1
            c = s * p * zm1_ratio

            return 0.70 * a + 0.24 * b + 0.06 * c

        best_index, best_cost = 0, cost(0)
        for f in range(1, len(mask) - 5):
            current = cost(f)
            if current <= best_cost:
                best_index, best_cost = f, current

        return best_index

    def _compute_parallel_depth(self) -> int:
        """Depth at which parallel workers would start, -1 if not worth it."""
        if len(self.mask) < 7:
            return -1

        def depth_for_size(size: int) -> int:
            product = 1
            for i in range(len(self.mask) - 6, 0, -1):
                product *= len(self.charset_at_depth(i - 1))
                if size <= product:
                    return i - 1
            return 0

        atomic_work_depth = depth_for_size(1 << 16)

        # not deep enough to warrant parallelization
        if atomic_work_depth < 2:
            return -1

        # Parallelizing earlier than this depth might make the program slow to stop
        # upon SIGINT or upon finding a solution.
        shallowest_parallel_depth = depth_for_size(1 << 32)

        # Find two consecutive characters to be guessed in parallel, maximizing
        # the number of work items.
        best_index, best_product = -1, 1
        for i in range(shallowest_parallel_depth, atomic_work_depth - 1):
            product = len(self.charset_at_depth(i)) * len(self.charset_at_depth(i + 1))
            if best_product < product:
                best_index, best_product = i, product

        return best_index

    def _compute_progress_depth(self) -> int:
        """Depth at which progress is counted, 0 if progress is not reported."""
        if self.parallel_depth < 0:
            return 0

        product = 1
        for i in range(self.parallel_depth + 2):
            product *= len(self.charset_at_depth(i))
            if 100 <= product:
                return i + 1

        return 0

    def charset_at_depth(self, depth: int) -> Sequence[int]:
        if depth < self.suffix_size:
            return self.mask[len(self.mask) - 1 - depth]
        return self.mask[depth - self.suffix_size]

    # -- search ------------------------------------------------------------

    def search(self, start: bytes = b"") -> bytes:
        self.decisions = bytearray()

        if len(self.mask) < 6:
            # update the target state forward so that there are exactly 6 updates
            # between it and the initial state
            after_target = Keys(self.target.x, self.target.y, self.target.z)
            for _ in range(len(self.mask), 6):
                after_target.update(0)
            self.set_target(after_target, (0,))
            self.search_state(Keys())
            return b""

        if len(self.mask) == 6:
            self.set_target(self.target, self.mask[5])
            self.search_state(Keys())
            return b""

        # 7 or more characters
        if self.suffix_size == 0:
            self.set_target(self.target, self.mask[self.factor_index + 5])

        if self.parallel_depth == -1:
            self._search_long_recursive(Keys(), self.target)
            return b""

        if self.progress_depth:
            product = 1
            for i in range(self.progress_depth):
                product *= len(self.charset_at_depth(i))

            self.progress.done = 0
            self.progress.total = product

        return self._search_long_parallel_recursive(Keys(), self.target, start, b"")

    def search_state(self, initial: Keys) -> None:
        _SixCharactersRecovery.search(self, initial)

    def on_solution_found(self) -> None:
        password = bytearray()
        password.extend(self.decisions[self.suffix_size :])
        password.extend(self.p)
        password.extend(reversed(self.decisions[: self.suffix_size]))
        del password[len(self.mask) :]

        in_search_space = all(c in self.mask[i] for i, c in enumerate(password))

        if not in_search_space:
            self.progress.log(_password_out_of_space_line(bytes(password)))
            self.progress.log("Some characters do not match the given mask. Continuing.")
            return

        self.solutions.append(bytes(password))
        self.progress.log(_password_line(bytes(password)))

        if not self.exhaustive:
            self.progress.state = State.EARLY_EXIT

    # -- sequential exploration -------------------------------------------

    def _search_long_recursive(self, after_prefix: Keys, before_suffix: Keys) -> None:
        depth = len(self.decisions)

        if depth + 7 == len(self.mask):
            # there is only one more character to bruteforce
            if depth < self.suffix_size:
                # bruteforce the last remaining suffix character
                self.decisions.append(0)

                for pi in self.charset_at_depth(depth):
                    before_suffix2 = Keys(before_suffix.x, before_suffix.y, before_suffix.z)
                    before_suffix2.update_backward_plaintext(pi)
                    self.set_target(before_suffix2, self.mask[self.factor_index + 5])

                    self.decisions[-1] = pi
                    self.search_state(after_prefix)

                self.decisions.pop()
            else:
                # bruteforce the last remaining prefix character
                if after_prefix.z >> 24 not in self.zm1_24_32:
                    return

                self.decisions.append(0)

                x0_partial = crc32(after_prefix.x, 0)
                y0_partial = (after_prefix.y * MULT + 1) & U32
                z0_partial = crc32(after_prefix.z, 0)

                for pi in self.charset_at_depth(depth):
                    x0 = x0_partial ^ crc32(0, pi)
                    y0 = (y0_partial + MULT * (x0 & 0xFF)) & U32
                    z0 = z0_partial ^ crc32(0, y0 >> 24)

                    if (z0 >> 16) not in self.z0_16_32:
                        continue

                    self.decisions[-1] = pi
                    self.search_state(Keys(x0, y0, z0))

                self.decisions.pop()
        elif depth < self.suffix_size:
            # bruteforce the next suffix character
            self.decisions.append(0)

            for pi in self.charset_at_depth(depth):
                before_suffix2 = Keys(before_suffix.x, before_suffix.y, before_suffix.z)
                before_suffix2.update_backward_plaintext(pi)
                if depth + 1 == self.suffix_size:
                    self.set_target(before_suffix2, self.mask[self.factor_index + 5])

                self.decisions[-1] = pi
                self._search_long_recursive(after_prefix, before_suffix2)

            self.decisions.pop()
        else:
            # bruteforce the next prefix character
            self.decisions.append(0)

            for pi in self.charset_at_depth(depth):
                after_prefix2 = Keys(after_prefix.x, after_prefix.y, after_prefix.z)
                after_prefix2.update(pi)

                self.decisions[-1] = pi
                self._search_long_recursive(after_prefix2, before_suffix)

            self.decisions.pop()

    # -- parallel exploration, simulated with a single worker ---------------

    def _search_long_parallel_recursive(
        self,
        after_prefix: Keys,
        before_suffix: Keys,
        start: bytes,
        restart: bytes,
    ) -> bytes:
        depth = len(self.decisions)
        charset = self.charset_at_depth(depth)

        index_start = 0
        if depth < len(start):
            while index_start < len(charset) and charset[index_start] < start[depth]:
                index_start += 1

        if depth == self.parallel_depth:
            # parallelize the next two decisions
            next_charset = self.charset_at_depth(depth + 1)
            parallel_space_size = len(charset) * len(next_charset)

            index_start *= len(next_charset)
            if depth + 1 < len(start):
                max_index = min(parallel_space_size, index_start + len(next_charset))
                while (
                    index_start < max_index
                    and next_charset[index_start % len(next_charset)] < start[depth + 1]
                ):
                    index_start += 1

            del self.decisions[depth:]
            self.decisions.extend(b"\x00\x00")

            report_progress = len(self.decisions) == self.progress_depth
            report_progress_coarse = len(self.decisions) == self.progress_depth + 1

            if report_progress:
                self.progress.done += index_start
            elif report_progress_coarse:
                self.progress.done += index_start // len(next_charset)

            index = index_start
            while index < parallel_space_size:
                first_choice = charset[index // len(next_charset)]
                second_choice = next_charset[index % len(next_charset)]

                after_prefix2 = Keys(after_prefix.x, after_prefix.y, after_prefix.z)
                before_suffix2 = Keys(before_suffix.x, before_suffix.y, before_suffix.z)

                if depth < self.suffix_size:
                    before_suffix2.update_backward_plaintext(first_choice)
                    if depth + 1 == self.suffix_size:
                        self.set_target(before_suffix2, self.mask[self.factor_index + 5])
                else:
                    after_prefix2.update(first_choice)

                if depth + 1 < self.suffix_size:
                    before_suffix2.update_backward_plaintext(second_choice)
                    if depth + 2 == self.suffix_size:
                        self.set_target(before_suffix2, self.mask[self.factor_index + 5])
                else:
                    after_prefix2.update(second_choice)

                self.decisions[depth] = first_choice
                self.decisions[depth + 1] = second_choice

                self._search_long_recursive(after_prefix2, before_suffix2)

                if report_progress or (
                    report_progress_coarse and index % len(next_charset) == len(next_charset) - 1
                ):
                    self.progress.done += 1

                index += 1

                if self.progress.state is not State.NORMAL:
                    break

            del self.decisions[depth:]

            if index < parallel_space_size:
                restart = bytes(self.decisions)
                restart += bytes(
                    [
                        charset[index // len(next_charset)],
                        next_charset[index % len(next_charset)],
                    ]
                )
                while len(restart) < len(self.mask) - 6:
                    restart += bytes([self.charset_at_depth(len(restart))[0]])

            return restart

        # take the next decisions recursively
        self.decisions.append(0)

        report_progress = depth + 1 == self.progress_depth

        if depth + 1 <= self.progress_depth:
            sub_search_size = 1
            for i in range(depth + 1, self.progress_depth):
                sub_search_size *= len(self.charset_at_depth(i))
            self.progress.done += index_start * sub_search_size

        index = index_start
        while index < len(charset):
            pi = charset[index]

            after_prefix2 = Keys(after_prefix.x, after_prefix.y, after_prefix.z)
            before_suffix2 = Keys(before_suffix.x, before_suffix.y, before_suffix.z)

            if depth < self.suffix_size:
                before_suffix2.update_backward_plaintext(pi)
                if depth + 1 == self.suffix_size:
                    self.set_target(before_suffix2, self.mask[self.factor_index + 5])
            else:
                after_prefix2.update(pi)

            self.decisions[-1] = pi

            if self.progress.state is not State.NORMAL:
                restart = bytes(self.decisions)
                while len(restart) < len(self.mask) - 6:
                    restart += bytes([self.charset_at_depth(len(restart))[0]])
                break

            restart = self._search_long_parallel_recursive(
                after_prefix2, before_suffix2, start if index == index_start else b"", restart
            )

            # Because the recursive call may explore only a fraction of its search
            # space, check that it was run in full before counting progress.
            if restart:
                break

            if report_progress:
                self.progress.done += 1

            index += 1

        self.decisions.pop()

        return restart


def recover_password(
    keys: Keys,
    charset: Sequence[int],
    min_length: int,
    max_length: int,
    start: bytes = b"",
    jobs: int = 1,
    exhaustive: bool = False,
    progress: Optional[Progress] = None,
) -> Tuple[List[bytes], bytes]:
    """Try to recover the password associated with *keys*.

    Returns the list of passwords and the restart point.
    """
    if progress is None:
        progress = Progress()

    charset = tuple(charset)
    solutions: List[bytes] = []
    worker = _BruteforceRecovery(keys, charset, solutions, exhaustive, progress)

    restart = b""
    start_length = max(min_length, 0 if not start else len(start) + 6)

    length = start_length
    while length <= max_length:
        if progress.state is not State.NORMAL:
            break

        if length <= 6:
            progress.log("length 0-6...")

            # look for a password of length between 0 and 6
            for short_length in range(0, 7):
                worker.search(short_length)
                if progress.state is not State.NORMAL:
                    break

            length = 7  # searching up to length 6 is done
            continue
        else:
            progress.log(f"length {length}...")
            restart = worker.search(length, start if length == start_length else b"")

        length += 1

    if progress.state is State.NORMAL:
        restart = b""

    return solutions, restart


def recover_password_for_mask(
    keys: Keys,
    mask: Sequence[Sequence[int]],
    start: bytes = b"",
    jobs: int = 1,
    exhaustive: bool = False,
    progress: Optional[Progress] = None,
) -> Tuple[List[bytes], bytes]:
    """Try to recover a password following *mask*."""
    if progress is None:
        progress = Progress()

    mask = tuple(tuple(charset) for charset in mask)
    solutions: List[bytes] = []
    worker = _MaskRecovery(keys, mask, solutions, exhaustive, progress)

    restart = worker.search(start)

    return solutions, restart
