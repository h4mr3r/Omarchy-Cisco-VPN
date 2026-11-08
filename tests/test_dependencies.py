import pathlib
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import dependencies


class DependenciesTest(unittest.TestCase):
    def test_reports_only_missing_packages(self):
        with patch.object(dependencies.subprocess, "run",
                          return_value=subprocess.CompletedProcess(
                              [], 0, "python-gobject\nother-package\n", "")) as runner:
            self.assertEqual(dependencies.missing_packages(), ["networkmanager-openconnect"])
        runner.assert_called_once_with(
            ["pacman", "-Qq"], capture_output=True, text=True, timeout=10, check=True
        )

    def test_reports_no_missing_packages(self):
        with patch.object(dependencies.subprocess, "run",
                          return_value=subprocess.CompletedProcess(
                              [], 0, "networkmanager-openconnect\npython-gobject\n", "")):
            self.assertEqual(dependencies.missing_packages(), [])

    def test_package_query_failure_is_not_treated_as_missing(self):
        with patch.object(dependencies.subprocess, "run",
                          side_effect=subprocess.CalledProcessError(1, ["pacman", "-Qq"])):
            with self.assertRaises(subprocess.CalledProcessError):
                dependencies.missing_packages()


if __name__ == "__main__":
    unittest.main()
