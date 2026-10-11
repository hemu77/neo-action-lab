import sys
import unittest
from unittest.mock import patch
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1]))
from gate import Gate


class WorkedTraceTests(unittest.TestCase):
    def test_exact_fourteen_row_trace(self):
        gate = Gate(); intent = gate.mint({"party": 2, "time": "19:00", "date": "2026-10-16"})
        expected = [(1,"ALLOW",["G12"]),(2,"ALLOW",["G2","G11"]),(3,"ALLOW",["G1","G8","G10"]),
            (4,"ALLOW",["G1","G4"]),(5,"ALLOW",["G2","G3"]),(6,"ALLOW",["G4","G6"]),
            (7,"ALLOW",["G3","G5"]),(8,"CONFIRM",["G6"]),(9,"ALLOW",["G4","G5","G12"]),
            (10,"ALLOW",["G1","G5"]),(11,"DENY",["G3"]),(12,"DENY",["G2"]),(13,"DENY",["G5"]),(14,"DENY",["G4"])]
        actual = []
        for row, verdict, rules in expected:
            with self.subTest(row=row), patch("gate.time.time", return_value=1000 if row <= 8 else 1001):
                result = gate.trace_step(intent, row)
                actual.append((row, result["verdict"], result["rules"]))
                self.assertEqual((result["verdict"], result["rules"]), (verdict, rules))
        self.assertEqual(actual, expected)
        self.assertIsNotNone(intent["reservation"])


if __name__ == "__main__": unittest.main()
