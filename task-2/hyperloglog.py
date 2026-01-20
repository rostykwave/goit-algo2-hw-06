import json
import math
import time
from typing import Iterable, Tuple

import mmh3


class HyperLogLog:
    """
    Simplified HyperLogLog implementation for counting unique elements.

    Args:
        p: determines number of registers m = 2**p.
           Larger p → better accuracy, more memory.
    """

    def __init__(self, p: int = 14) -> None:
        if p <= 0:
            raise ValueError("Precision p must be positive")

        self.p = p
        self.m = 1 << p
        self.registers = [0] * self.m
        self.alpha = self._get_alpha()
        self.small_range_correction = 5 * self.m / 2

    def _get_alpha(self) -> float:
        if self.p <= 16:
            return 0.673
        if self.p == 32:
            return 0.697
        return 0.7213 / (1.0 + 1.079 / self.m)

    def _rho(self, w: int) -> int:
        """Position of the first non-zero bit (simplified version)."""
        if w == 0:
            return 32
        return len(bin(w)) - 2

    def add(self, item: str) -> None:
        """Add an element to the structure."""
        if item is None:
            return

        x = mmh3.hash(str(item), signed=False)
        j = x & (self.m - 1)
        w = x >> self.p
        self.registers[j] = max(self.registers[j], self._rho(w))

    def count(self) -> float:
        """Estimate the number of unique elements."""
        Z = sum(2.0 ** -r for r in self.registers)
        E = self.alpha * self.m * self.m / Z

        if E <= self.small_range_correction:
            V = self.registers.count(0)
            if V > 0:
                return self.m * math.log(self.m / V)

        return E


def iter_ips_from_log(path: str) -> Iterable[str]:
    """
    Iterate over IP addresses from the log file.

    Invalid lines are ignored:
      - invalid JSON
      - missing field 'remote_addr'
      - value is not a string
    """
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue

            ip = record.get("remote_addr")
            if isinstance(ip, str) and ip:
                yield ip


def exact_unique_ips_count(path: str) -> Tuple[int, float]:
    """Exact count of unique IP addresses using set."""
    start = time.perf_counter()
    unique_ips = set()

    for ip in iter_ips_from_log(path):
        unique_ips.add(ip)

    end = time.perf_counter()
    return len(unique_ips), end - start


def hll_unique_ips_count(path: str, p: int = 14) -> Tuple[float, float]:
    """Approximate count of unique IP addresses using HyperLogLog."""
    hll = HyperLogLog(p=p)
    start = time.perf_counter()

    for ip in iter_ips_from_log(path):
        hll.add(ip)

    estimate = hll.count()
    end = time.perf_counter()
    return estimate, end - start


def print_comparison_table(exact_count: int,
                           exact_time: float,
                           hll_count_value: float,
                           hll_time: float) -> None:
    """Print comparison results as a simple table."""
    print("Результати порівняння:")
    header = f"{'':28s}{'Точний підрахунок':>20s}{'HyperLogLog':>15s}"
    print(header)

    print(
        f"{'Унікальні елементи':28s}"
        f"{exact_count:>20.1f}"
        f"{hll_count_value:>15.1f}"
    )
    print(
        f"{'Час виконання (сек.)':28s}"
        f"{exact_time:>20.4f}"
        f"{hll_time:>15.4f}"
    )

    if exact_count > 0:
        abs_error = abs(hll_count_value - exact_count)
        rel_error = abs_error / exact_count * 100
        print(
            f"Абсолютна похибка: {abs_error:.4f}, "
            f"Відносна похибка: {rel_error:.4f}%"
        )


if __name__ == "__main__":
    log_path = "lms-stage-access.log"

    exact_count, exact_time = exact_unique_ips_count(log_path)
    approx_count, hll_time = hll_unique_ips_count(log_path, p=14)

    print_comparison_table(exact_count, exact_time, approx_count, hll_time)
