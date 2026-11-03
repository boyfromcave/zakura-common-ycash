#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .
"""Tests for check_workflow_triggers.py (run: python3 -m unittest discover -s .github/scripts -p 'test_check_workflow_triggers.py')."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import check_workflow_triggers as c  # noqa: E402

GOOD = """name: x
on:
  push:
    branches:
      - upgrade/vault
      - "vaults/**"
  pull_request:
    branches: [upgrade/vault, "vaults/**", "kc/**"]  # stacked PRs
  schedule:
    - cron: "0 8 * * *"
  workflow_dispatch:
jobs: {}
"""


def problems(text):
    return c.trigger_problems("w.yml", c.workflow_triggers(text))


class PolicyTest(unittest.TestCase):
    def test_good(self):
        self.assertEqual(problems(GOOD), [])

    def test_create_delete_and_other_events_fail(self):
        for event in ("create", "delete", "merge_group", "pull_request_target", "workflow_run"):
            self.assertTrue(problems("on:\n  %s:\n" % event), event)
            self.assertTrue(problems("on: [%s]\n" % event), event)

    def test_bare_or_wide_push_and_pull_request_fail(self):
        self.assertTrue(problems("on: push\n"))
        self.assertTrue(problems("on:\n  pull_request:\n"))
        for b in ("['**']", "[main]", "['feat/**']"):
            self.assertTrue(problems("on:\n  push:\n    branches: %s\n" % b), b)
        self.assertTrue(problems("on:\n  push:\n    branches-ignore: ['semgrep/**']\n"))

    def test_the_repository_complies(self):
        self.assertEqual(c.main([]), 0)

    def test_a_bad_workflow_fails_main(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, ".github/workflows"))
            with open(os.path.join(d, ".github/workflows/a.yml"), "w") as f:
                f.write("on:\n  delete:\n")
            self.assertEqual(c.main(["--repo", d]), 1)


if __name__ == "__main__":
    unittest.main()
