"""QEMU topology and no-operation default, with no VM launch."""

import io
from contextlib import redirect_stdout
from pathlib import Path
import unittest
from unittest import mock

import qemu_stage


class QEMUStageTests(unittest.TestCase):
    def test_user_network_only_with_loopback_forward(self):
        item = {"id": "testid123", "overlay": "/private/guest.qcow2"}
        with mock.patch.object(qemu_stage.shutil, "which", return_value="/usr/bin/qemu-system-x86_64"), \
             mock.patch.object(Path, "is_file", return_value=True):
            args = qemu_stage.qemu_command(item)
        joined = " ".join(args)
        self.assertIn("restrict=on,ipv6=off,net=10.88.81.0/24", joined)
        self.assertIn("hostfwd=tcp:127.0.0.1:2291-:22", joined)
        self.assertIn("/private/guest.qcow2,format=qcow2", joined)
        self.assertNotIn("vmnet", joined)
        self.assertNotIn("tap", joined)
        self.assertNotIn("socket", joined)

    def test_default_dry_run_does_not_read_guest_or_artifacts(self):
        with mock.patch("sys.argv", ["qemu_stage.py"]), \
             mock.patch.object(qemu_stage, "record", side_effect=AssertionError("stage accessed")), \
             mock.patch.object(qemu_stage, "stage", side_effect=AssertionError("guest accessed")), \
             redirect_stdout(io.StringIO()) as out:
            self.assertEqual(qemu_stage.main(), 0)
            self.assertIn("DRY_RUN", out.getvalue())


if __name__ == "__main__":
    unittest.main()
