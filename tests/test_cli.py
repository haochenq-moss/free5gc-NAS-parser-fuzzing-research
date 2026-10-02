import contextlib
import io
import unittest

from free5gc_security_lab import cli


class CliTests(unittest.TestCase):
    def test_doctor_is_non_failing_when_optional_runtime_tools_are_missing(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = cli.doctor()
        self.assertEqual(result, 0)
        self.assertIn("free5GC security lab prerequisites", output.getvalue())

    def test_bootstrap_requires_a_pinned_ref(self):
        output = io.StringIO()
        with contextlib.redirect_stderr(output):
            result = cli.bootstrap("")
        self.assertEqual(result, 2)
        self.assertIn("--ref", output.getvalue())


if __name__ == "__main__":
    unittest.main()
