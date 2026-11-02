#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .
"""The fork's workflow trigger policy (.github/README-ycash.md "Triggers").

  python3 .github/scripts/check_workflow_triggers.py [--repo DIR]

Every file GitHub could run (.github/workflows/*.yml) must trigger only on the fork's own branches:
events only push, pull_request, schedule, workflow_dispatch and workflow_call (no create, delete,
merge_group, pull_request_target, workflow_run, ...); push only with a branches filter within
upgrade/vault and vaults/**; pull_request only with a branches filter within upgrade/vault,
vaults/** and kc/**; no branches-ignore, no tag pushes. Files in .github/workflows-off/ never run
and are not checked. The same policy and reader as kogany's qa/kogany_audit.py `workflows` leg.
Exit 0 when every workflow complies, 1 otherwise, 2 on an error. Stdlib only.
"""

import argparse
import fnmatch
import os
import re
import sys

WORKFLOW_DIR = ".github/workflows"


class AuditError(Exception):
    pass


ALLOWED_EVENTS = ("push", "pull_request", "schedule", "workflow_dispatch", "workflow_call")
PUSH_BRANCHES = ("upgrade/vault", "vaults/**")
PR_BRANCHES = ("upgrade/vault", "vaults/**", "kc/**")


def _yaml_scalar(text):
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "'\"":
        return text[1:-1]
    return text


def _strip_comment(line):
    """`line` without a trailing `# comment` (outside quotes)."""
    quote = None
    for i, c in enumerate(line):
        if quote:
            if c == quote:
                quote = None
        elif c in "'\"":
            quote = c
        elif c == "#" and (i == 0 or line[i - 1] in " \t"):
            return line[:i].rstrip()
    return line.rstrip()


def _flow_list(text):
    inner = text.strip()[1:-1]
    return [_yaml_scalar(x) for x in inner.split(",") if x.strip()]


def _inline(text):
    text = text.strip()
    if text.startswith("[") and text.endswith("]"):
        return _flow_list(text)
    if text == "{}":
        return {}
    if text in ("", "~", "null"):
        return None
    return _yaml_scalar(text)


def _block(lines, i, indent):
    """Parse the block of `lines` from `i` at `indent`: (value, next index). Mappings, block and
    flow lists and scalars: the subset GitHub workflow triggers use."""
    if i < len(lines) and lines[i][1].startswith("- "):
        items = []
        while i < len(lines) and lines[i][0] == indent and lines[i][1].startswith("- "):
            body = lines[i][1][2:]
            if ":" in body and not body.lstrip().startswith(("'", '"', "[")):
                # A mapping item: re-read it as a mapping at the item's inner indent.
                sub = [(indent + 2, body)]
                j = i + 1
                while j < len(lines) and lines[j][0] > indent:
                    sub.append(lines[j])
                    j += 1
                value, _ = _block(sub, 0, indent + 2)
                items.append(value)
                i = j
            else:
                items.append(_inline(body))
                i += 1
        return items, i
    mapping = {}
    while i < len(lines) and lines[i][0] == indent:
        text = lines[i][1]
        if ":" not in text:
            raise AuditError("unparsed workflow line %r" % text)
        key, rest = text.split(":", 1)
        key = _yaml_scalar(key)
        i += 1
        if rest.strip():
            mapping[key] = _inline(rest)
        elif i < len(lines) and lines[i][0] > indent:
            mapping[key], i = _block(lines, i, lines[i][0])
        else:
            mapping[key] = None
    return mapping, i


def workflow_triggers(text):
    """The `on:` value of a workflow file, as {event: config}. Stdlib only: a small reader of the
    YAML subset triggers are written in, which fails closed (AuditError) on anything else."""
    raw = text.splitlines()
    for n, line in enumerate(raw):
        m = re.match(r"""^(?:on|'on'|"on")\s*:(.*)$""", line)
        if not m:
            continue
        rest = _strip_comment(m.group(1)).strip()
        if rest:
            value = _inline(rest)
            if isinstance(value, list):
                return dict.fromkeys(value)
            if isinstance(value, str):
                return {value: None}
            raise AuditError("unparsed `on:` value %r" % rest)
        block = []
        for line2 in raw[n + 1:]:
            stripped = _strip_comment(line2)
            if not stripped.strip():
                continue
            ind = len(stripped) - len(stripped.lstrip(" "))
            if ind == 0:
                break
            block.append((ind, stripped.strip()))
        if not block:
            raise AuditError("empty `on:` block")
        value, end = _block(block, 0, block[0][0])
        if end != len(block) or not isinstance(value, dict):
            raise AuditError("unparsed `on:` block")
        return value
    raise AuditError("no `on:` key")


def _as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def trigger_problems(name, triggers):
    """The trigger-policy violations of one workflow (an empty list when it complies)."""
    problems = []
    for event, config in triggers.items():
        if event not in ALLOWED_EVENTS:
            problems.append("%s: event `%s` is not allowed (only %s)" % (name, event, ", ".join(ALLOWED_EVENTS)))
            continue
        if event not in ("push", "pull_request"):
            continue
        allowed = PUSH_BRANCHES if event == "push" else PR_BRANCHES
        config = config if isinstance(config, dict) else {}
        if "branches-ignore" in config:
            problems.append("%s: `%s` uses branches-ignore (runs on every other branch)" % (name, event))
        if event == "push" and ("tags" in config or "tags-ignore" in config):
            problems.append("%s: `push` has a tags filter (kogany pushes no tag to build)" % name)
        branches = _as_list(config.get("branches"))
        if not branches:
            problems.append("%s: `%s` has no branches filter (runs on every branch)" % (name, event))
        for b in branches:
            # A pattern of the policy itself, or a plain branch name one of them covers.
            if not (b in allowed or (not set(b) & set("*?[]!+") and any(
                    fnmatch.fnmatchcase(b, a.replace("**", "*")) for a in allowed))):
                problems.append("%s: `%s` branch `%s` is not one of %s" % (name, event, b, ", ".join(allowed)))
    return problems


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--repo", default=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
    args = ap.parse_args(argv)
    wf_dir = os.path.join(args.repo, WORKFLOW_DIR)
    problems = []
    names = sorted(f for f in os.listdir(wf_dir) if f.endswith((".yml", ".yaml")))
    for f in names:
        with open(os.path.join(wf_dir, f), encoding="utf-8") as fh:
            text = fh.read()
        try:
            problems += trigger_problems(f, workflow_triggers(text))
        except AuditError as e:
            problems.append("%s: triggers unreadable (%s)" % (f, e))
    for p in problems:
        print("::error::%s" % p if os.environ.get("GITHUB_ACTIONS") else p)
    print("%d workflow(s) in %s, %d problem(s)" % (len(names), WORKFLOW_DIR, len(problems)))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
