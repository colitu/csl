import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from check_g1 import main


class GateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for n in range(1, 4):
            self.write(f"direct-{n}", 100, 0)
            self.write(f"csl-{n}", 95, 0)
        for scenario in ("reset", "blackhole", "freeze"):
            self.write(scenario, 50, 1_000_000_000)

    def write(self, name, mbps, stall):
        (self.root / f"{name}.json").write_text(
            json.dumps({"ok": True, "bytes": 1, "mbps": mbps, "max_stall_ns": stall}),
            encoding="utf-8",
        )

    def check(self):
        with contextlib.redirect_stdout(io.StringIO()):
            return main(self.root)

    def test_passes_measured_limits(self):
        self.assertEqual(self.check(), 0)

    def test_fails_throughput_loss(self):
        self.write("csl-1", 85, 0)
        self.write("csl-2", 85, 0)
        self.assertEqual(self.check(), 1)

    def test_fails_carrier_stall(self):
        self.write("blackhole", 50, 2_100_000_000)
        self.assertEqual(self.check(), 1)


if __name__ == "__main__":
    unittest.main()
