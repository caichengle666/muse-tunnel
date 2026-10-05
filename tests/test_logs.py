"""Tests for the log retention window.

systemd appends raw stdout into logs/ on what is, on this kind of
sandbox, the only persistent volume. Nothing bounded it before: a
chatty program could fill $HOME and take config.json and secrets/ down
with it.

Two properties matter and are easy to get wrong:

  * rotation must rewrite the *same inode*. systemd holds the fd open
    for `StandardOutput=append:` and keeps writing to whatever inode it
    opened, so a rename-based rotation orphans the live log and leaves
    an invisible, ever-growing file behind.
  * a log belonging to a unit that no longer exists must actually go
    away, while a log still being written (which never looks old) must
    not.

Run with:  python3 -m unittest discover -s tests -v
"""
from __future__ import annotations

import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "bin"))

import cfbridge  # noqa: E402

DAY = 24 * 3600


class LogRetentionTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.proj = self._tmp.name
        self.logs = os.path.join(self.proj, "logs")
        os.makedirs(self.logs)
        os.makedirs(os.path.join(self.proj, "run"))

    # -- helpers ------------------------------------------------------

    def _write(self, name, data: bytes) -> str:
        path = os.path.join(self.logs, name)
        with open(path, "wb") as f:
            f.write(data)
        return path

    def _age(self, path, seconds):
        old = time.time() - seconds
        os.utime(path, (old, old))

    # -- size cap -----------------------------------------------------

    def test_missing_logs_dir_is_a_noop(self):
        empty = os.path.join(self._tmp.name, "nothing-here")
        self.assertEqual(cfbridge.prune_logs(empty), [])

    def test_caps_an_oversized_log_and_keeps_its_tail(self):
        payload = bytes(range(256)) * (12 * 1024)          # 3 MiB, patterned
        path = self._write("cloudflared.log", payload)
        inode_before = os.stat(path).st_ino
        actions = cfbridge.prune_logs(self.proj, retention_hours=24,
                                      max_bytes=1024 * 1024, tail_bytes=64 * 1024)
        self.assertTrue(any("capped cloudflared.log" in a for a in actions), actions)
        with open(path, "rb") as f:
            got = f.read()
        self.assertEqual(len(got), 64 * 1024)
        self.assertEqual(got, payload[-64 * 1024:], "the newest output must survive")
        if os.name == "posix":
            self.assertEqual(os.stat(path).st_ino, inode_before,
                             "rotation must rewrite the inode, not replace the file")

    def test_a_small_log_is_left_alone(self):
        path = self._write("bridge.log", b"small\n")
        self.assertEqual(cfbridge.prune_logs(self.proj, retention_hours=24,
                                             max_bytes=1024, tail_bytes=512), [])
        with open(path, "rb") as f:
            self.assertEqual(f.read(), b"small\n")

    def test_an_open_append_fd_keeps_writing_into_the_rotated_file(self):
        """The point of in-place rotation: systemd's fd stays usable."""
        path = self._write("svc-demo.log", b"a" * 200000)
        with open(path, "ab") as held:           # stands in for systemd's fd
            held.write(b"before\n")
            held.flush()
            cfbridge.prune_logs(self.proj, retention_hours=24,
                                max_bytes=1000, tail_bytes=4096)
            held.write(b"after\n")
            held.flush()
        with open(path, "rb") as f:
            data = f.read()
        self.assertTrue(data.endswith(b"after\n"), data[-32:])
        self.assertLessEqual(len(data), 4096 + 16)
        # Exactly one file: a rename-based rotation would have hidden the
        # live bytes in an unlinked inode instead.
        self.assertEqual([n for n in os.listdir(self.logs) if n.endswith(".log")],
                         ["svc-demo.log"])

    # -- stale leftovers ----------------------------------------------

    def test_removes_a_log_from_a_removed_unit(self):
        path = self._write("svc-deleted.log", b"old output\n")
        self._age(path, 2 * DAY)
        actions = cfbridge.prune_logs(self.proj, retention_hours=24)
        self.assertFalse(os.path.exists(path))
        self.assertTrue(any("removed stale log svc-deleted.log" in a for a in actions), actions)

    def test_keeps_a_recent_unknown_log(self):
        """A log written a moment ago is probably live; do not guess."""
        path = self._write("svc-just-added.log", b"fresh\n")
        cfbridge.prune_logs(self.proj, retention_hours=24)
        self.assertTrue(os.path.exists(path))

    def test_keeps_an_expected_log_even_when_it_looks_old(self):
        """cloudflared.log is managed; age alone must not delete it."""
        path = self._write("cloudflared.log", b"quiet for a week\n")
        self._age(path, 7 * DAY)
        cfbridge.prune_logs(self.proj, retention_hours=24)
        self.assertTrue(os.path.exists(path))

    def test_service_with_a_start_cmd_owns_its_log(self):
        cfbridge.save_config(self.proj, {
            "zone": "example.com", "tunnel_name": "t",
            "services": [{"name": "api", "hostname": "api.example.com", "port": 8080,
                          "health": "/health", "auth": "key", "origin": "",
                          "origin_request": {}, "start_cmd": "/bin/true",
                          "workdir": "", "env_proxy": False}]})
        self.assertIn("svc-api.log", cfbridge.expected_log_names(self.proj))
        path = self._write("svc-api.log", b"still managed\n")
        self._age(path, 7 * DAY)
        cfbridge.prune_logs(self.proj, retention_hours=24)
        self.assertTrue(os.path.exists(path))

    def test_route_only_service_does_not_own_a_log(self):
        cfbridge.save_config(self.proj, {
            "zone": "example.com", "tunnel_name": "t",
            "services": [{"name": "api", "hostname": "api.example.com", "port": 8080,
                          "health": "/health", "auth": "key", "origin": "",
                          "origin_request": {}, "start_cmd": "", "workdir": "",
                          "env_proxy": False}]})
        self.assertNotIn("svc-api.log", cfbridge.expected_log_names(self.proj))

    # -- rolling window ----------------------------------------------

    def test_first_run_rotates_so_existing_output_starts_bounded(self):
        path = self._write("bridge.log", b"x" * 100000)
        actions = cfbridge.prune_logs(self.proj, retention_hours=24, max_bytes=10 ** 9,
                                      tail_bytes=4096)
        self.assertTrue(any("rotated bridge.log" in a for a in actions), actions)
        self.assertEqual(os.path.getsize(path), 4096)

    def test_second_run_within_the_window_does_not_rotate_again(self):
        path = self._write("bridge.log", b"x" * 100000)
        cfbridge.prune_logs(self.proj, retention_hours=24, max_bytes=10 ** 9, tail_bytes=4096)
        self.assertEqual(os.path.getsize(path), 4096)
        with open(path, "ab") as f:
            f.write(b"y" * 5000)
        actions = cfbridge.prune_logs(self.proj, retention_hours=24, max_bytes=10 ** 9,
                                      tail_bytes=4096)
        self.assertEqual(actions, [], "the window has not elapsed yet")
        self.assertEqual(os.path.getsize(path), 9096)

    def test_rotates_again_once_the_window_has_elapsed(self):
        path = self._write("bridge.log", b"x" * 100000)
        cfbridge.prune_logs(self.proj, retention_hours=24, max_bytes=10 ** 9, tail_bytes=4096)
        with open(path, "ab") as f:
            f.write(b"y" * 5000)          # a window's worth of new output
        with open(cfbridge.log_retention_state_path(self.proj), "w", encoding="utf-8") as f:
            f.write('{"rotated_at": %f}' % (time.time() - 25 * 3600))
        actions = cfbridge.prune_logs(self.proj, retention_hours=24, max_bytes=10 ** 9,
                                      tail_bytes=4096)
        self.assertTrue(any("rotated bridge.log" in a for a in actions), actions)
        self.assertEqual(os.path.getsize(path), 4096)

    def test_a_rotation_with_nothing_to_drop_reports_nothing(self):
        path = self._write("bridge.log", b"tiny\n")
        with open(cfbridge.log_retention_state_path(self.proj), "w", encoding="utf-8") as f:
            f.write('{"rotated_at": 0}')
        self.assertEqual(cfbridge.prune_logs(self.proj, retention_hours=24,
                                             max_bytes=10 ** 9, tail_bytes=4096), [])
        self.assertEqual(os.path.getsize(path), 5)

    def test_rotation_state_records_the_window(self):
        cfbridge.prune_logs(self.proj, retention_hours=6)
        import json
        with open(cfbridge.log_retention_state_path(self.proj), encoding="utf-8") as f:
            state = json.load(f)
        self.assertEqual(state["window_hours"], 6)
        self.assertLess(abs(state["rotated_at"] - time.time()), 60)

    def test_force_rotates_inside_the_window(self):
        path = self._write("bridge.log", b"x" * 100000)
        cfbridge.prune_logs(self.proj, retention_hours=24, max_bytes=10 ** 9, tail_bytes=4096)
        with open(path, "ab") as f:
            f.write(b"y" * 5000)
        actions = cfbridge.prune_logs(self.proj, retention_hours=24, max_bytes=10 ** 9,
                                      tail_bytes=4096, force_rotate=True)
        self.assertTrue(any("rotated bridge.log" in a for a in actions), actions)
        self.assertEqual(os.path.getsize(path), 4096)

    def test_zero_hours_disables_pruning(self):
        path = self._write("svc-gone.log", b"keep me\n")
        self._age(path, 30 * DAY)
        self.assertEqual(cfbridge.prune_logs(self.proj, retention_hours=0), [])
        self.assertTrue(os.path.exists(path))

    def test_corrupt_state_file_is_treated_as_never_rotated(self):
        self._write("bridge.log", b"x" * 100000)
        with open(cfbridge.log_retention_state_path(self.proj), "w", encoding="utf-8") as f:
            f.write("{ truncated")
        actions = cfbridge.prune_logs(self.proj, retention_hours=24, max_bytes=10 ** 9,
                                      tail_bytes=4096)
        self.assertTrue(actions, "a corrupt state file must not disable retention forever")

    def test_config_hour_override(self):
        self.assertEqual(cfbridge.retention_hours_from_config({}), 24.0)
        self.assertEqual(cfbridge.retention_hours_from_config({"log_retention_hours": 3}), 3.0)
        # Garbage falls back rather than disabling retention by accident.
        self.assertEqual(cfbridge.retention_hours_from_config({"log_retention_hours": "nope"}), 24.0)
        self.assertEqual(cfbridge.retention_hours_from_config({"log_retention_hours": -5}), 0.0)

    def test_non_log_files_are_ignored(self):
        other = os.path.join(self.logs, "notes.txt")
        with open(other, "wb") as f:
            f.write(b"x" * 10 ** 6)
        self._age(other, 30 * DAY)
        cfbridge.prune_logs(self.proj, retention_hours=24, max_bytes=100, tail_bytes=10)
        self.assertTrue(os.path.exists(other))


if __name__ == "__main__":
    unittest.main()
