"""Tests for fim.py. Run with:  python -m unittest -v"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
FIM = os.path.join(HERE, "fim.py")
POSIX = os.name == "posix"
ROOT = POSIX and os.geteuid() == 0


class Base(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = os.path.realpath(tmp.name)
        self.tree = os.path.join(self.dir, "tree")
        os.makedirs(os.path.join(self.tree, "sub"))
        self.write("a.txt", "a")
        self.write("sub/b.txt", "b")
        self.base = os.path.join(self.dir, "baseline.json")

    def path(self, rel):
        return os.path.join(self.tree, *rel.split("/"))

    def write(self, rel, text):
        os.makedirs(os.path.dirname(self.path(rel)), exist_ok=True)
        with open(self.path(rel), "w") as f:
            f.write(text)

    def fim(self, *args, key=None):
        env = {k: v for k, v in os.environ.items() if k != "FIM_KEY"}
        if key:
            env["FIM_KEY"] = key
        p = subprocess.run([sys.executable, FIM, *args, "-b", self.base],
                           capture_output=True, text=True, env=env, cwd=self.dir)
        return p.returncode, p.stdout, p.stderr

    def init(self, *extra, key=None):
        code, out, err = self.fim("init", self.tree, *extra, key=key)
        self.assertEqual(code, 0, out + err)

    def check_json(self, *extra, key=None):
        code, out, err = self.fim("check", "--json", *extra, key=key)
        return code, json.loads(out)

    def edit_baseline(self, change):
        with open(self.base) as f:
            data = json.load(f)
        change(data)
        with open(self.base, "w") as f:
            json.dump(data, f)


class ChangeTests(Base):
    def test_untouched_tree_is_clean(self):
        self.init()
        self.assertEqual(self.fim("check")[0], 0)
        self.assertEqual(self.fim("check", "-q")[1], "")

    def test_added_removed_modified(self):
        self.init()
        self.write("new.txt", "n")
        self.write("a.txt", "changed")
        os.remove(self.path("sub/b.txt"))
        code, d = self.check_json()
        self.assertEqual(code, 1)
        self.assertEqual(d["added"], [self.path("new.txt")])
        self.assertEqual(d["removed"], [self.path("sub/b.txt")])
        self.assertEqual(d["modified"][0][0], self.path("a.txt"))

    def test_names_that_used_to_be_skipped_are_tracked(self):
        self.init()
        for rel in ("evil.log", "drop.tmp", ".git/backdoor.sh", "__pycache__/implant.py"):
            self.write(rel, "x")
        code, d = self.check_json()
        self.assertEqual(code, 1)
        for rel in ("evil.log", "drop.tmp", ".git/backdoor.sh", "__pycache__/implant.py"):
            self.assertIn(self.path(rel), d["added"])

    def test_new_empty_directory_is_reported(self):
        self.init()
        os.mkdir(self.path("emptydir"))
        code, d = self.check_json()
        self.assertEqual((code, d["added"]), (1, [self.path("emptydir")]))

    @unittest.skipUnless(POSIX, "needs POSIX permissions")
    def test_directory_permission_change_is_reported(self):
        os.chmod(self.path("sub"), 0o755)
        self.init()
        os.chmod(self.path("sub"), 0o777)
        code, d = self.check_json()
        self.assertEqual(code, 1)
        self.assertEqual(d["attrs"], [[self.path("sub"), "mode 0755 -> 0777"]])

    def test_timestamp_preserving_edit_is_flagged(self):
        self.init()
        st = os.stat(self.path("a.txt"))
        self.write("a.txt", "b")
        os.utime(self.path("a.txt"), ns=(st.st_atime_ns, st.st_mtime_ns))
        code, d = self.check_json()
        self.assertIn("timestamp preserved", d["modified"][0][1])

    def test_update_accepts_changes(self):
        self.init()
        self.write("a.txt", "changed")
        code, out, err = self.fim("update", "--json")
        self.assertTrue(json.loads(out)["baseline_updated"])      # valid JSON, nothing trailing
        self.assertEqual(self.fim("check")[0], 0)

    def test_exclude_at_check_time_reports_nothing_removed(self):
        self.init()
        for pattern in ("sub", "*/sub/*"):
            code, d = self.check_json("-x", pattern)
            self.assertEqual((code, d["removed"]), (0, []))

    def test_baseline_inside_the_tree_is_ignored(self):
        self.base = self.path("baseline.json")
        self.init()
        self.assertEqual(self.fim("check")[0], 0)

    @unittest.skipUnless(POSIX, "needs symlinks")
    def test_symlink_loop_terminates(self):
        os.symlink("..", self.path("sub/loop"))
        self.init("--follow")
        code, d = self.check_json()
        self.assertEqual(code, 0)
        self.assertLess(d["files"] + d["dirs"], 10)

    @unittest.skipIf(ROOT or not POSIX, "root can read everything")
    def test_unreadable_file_is_reported_not_skipped(self):
        os.chmod(self.path("a.txt"), 0)
        self.addCleanup(os.chmod, self.path("a.txt"), 0o644)
        self.assertEqual(self.fim("init", self.tree)[0], 2)
        code, out, err = self.fim("check", "-q")
        self.assertEqual(code, 2)
        self.assertIn("unreadable", out)


class BaselineTests(Base):
    def test_init_refuses_to_overwrite(self):
        self.init()
        self.assertEqual(self.fim("init", self.tree)[0], 2)
        self.assertEqual(self.fim("init", self.tree, "--force")[0], 0)

    def test_edited_settings_break_the_seal(self):
        self.init(key="k")
        self.edit_baseline(lambda d: d["meta"]["skip"].append("backdoor*"))
        self.write("backdoor.sh", "x")
        self.assertEqual(self.fim("check", "-q", key="k")[0], 2)

    def test_edited_records_break_the_seal(self):
        for key in (None, "k"):
            self.init("--force", key=key)
            self.edit_baseline(lambda d: d["records"][self.path("a.txt")].update(hash="0" * 64))
            self.assertEqual(self.fim("check", "-q", key=key)[0], 2)
            self.assertEqual(self.fim("update", key=key)[0], 2)

    def test_sealed_baseline_needs_its_key(self):
        self.init(key="k")
        self.assertEqual(self.fim("check", key="k")[0], 0)
        self.assertEqual(self.fim("check")[0], 2)
        self.assertEqual(self.fim("check", key="wrong")[0], 2)

    def test_unkeyed_baseline_is_rejected_when_a_key_is_set(self):
        self.init()
        self.assertEqual(self.fim("check", key="k")[0], 2)

    def test_old_format_is_rejected(self):
        with open(self.base, "w") as f:
            json.dump({"meta": {"roots": [], "skip": [], "seal": "x"}, "records": {}}, f)
        self.assertEqual(self.fim("check")[0], 2)

    def test_missing_baseline(self):
        self.assertEqual(self.fim("check")[0], 2)


if __name__ == "__main__":
    unittest.main()
