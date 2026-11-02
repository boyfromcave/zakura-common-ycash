# zakura-common-ycash CI

zakura-common-ycash is the Ycash developers' fork of `zakura-core/common`: the librustzcash crates
and `crates/zcash_script` that kogany, the third Ycash node line, takes through
`[patch.crates-io]` at one exact rev. With the `ycash` cargo feature off, every crate is upstream's
Zcash build; with it on (`zakura-protocol`, forwarded by `zakura-primitives`, `zakura-address` and
`zakura-transparent`), the consensus parameters, branch IDs and encodings are Ycash's. This file
says which GitHub Actions workflows run on the fork, what was changed in them, and why the rest are
off. The decisions are K-2 and K-15 of the kogany plan, and its §4.2 rule 8: "the fork's CI builds
and tests with the `ycash` feature on and off" (`docs/plans/kogany/kogany-yellowback-plan.md` in the
Yellowback workspace).

## Which workflows run

| State | Workflows | What changed |
| --- | --- | --- |
| kept | `ci.yml` | triggers narrowed to the fork's branches (Triggers below); a `ycash` leg in `librustzcash-test` and a `ycash` lint step in `rust-checks` |
| kept | `docs.yml`, `supply-chain.yml`, `workflow-security.yml` | triggers narrowed to the fork's branches |
| fork | `semgrep.yml`, `codeql.yml`, `secops.yml` | ours (Security CI below) |
| fork | `ycash-check.yml` | ours: the trigger policy, and the `ycash` gate when called or dispatched |
| off | `publish-crates.yml`, `semver.yml`, `changelog.yml`, `maintenance.yml` | moved, byte for byte, to `.github/workflows-off/` |

Every edit to a kept workflow or script carries a `zakura-common-ycash (2026-11-01)` comment.

### The `ycash` feature, off and on

- `.github/scripts/supported_features.py` lists upstream's "all supported features" for a set of
  crates. It now leaves `ycash` out unless `YCASH_FEATURE=on`. Without that change every
  all-features job would have tested only the Ycash build, and the Zcash build (feature off) would
  have gone untested. `test_supported_features.py` covers it.
- `librustzcash-test` has three legs. `default` and `nu7` are upstream's: the feature is off, and
  they test `zakura-address`, `-keys`, `-primitives`, `-protocol`, `-proofs`, `-transparent`,
  `-zcash-script` and `-zip321` with all supported features. The `ycash` leg tests
  `zakura-address`, `-primitives`, `-protocol`, `-transparent` and `-zcash-script` with default
  features plus `ycash`, the same set as the local gate below. With the feature on, the Zcash test
  vectors fail by design: those of `zakura-keys`, and the wallet-feature tests of
  `zakura-transparent` (bip32, zip48, the builder), which pin Zcash address strings and coin
  type 133. So those run on the feature-off legs only.
- `rust-checks` (group "Sapling and librustzcash") runs upstream's stable check, clippy with
  `-D warnings` and the MSRV check feature off, then again feature on for the four crates that carry
  it.
- `librustzcash-configurations` already runs clippy once per feature of each crate, so it covers
  `ycash` on its own.

`--all-features` is not possible in this workspace: `zakura-reddsa`'s two Pallas backends are
mutually exclusive. That is why the jobs use `supported_features.py`.

The same gate locally (`CARGO_TARGET_DIR` as you like):

```bash
cargo test -p zakura-protocol -p zakura-address -p zakura-transparent -p zakura-primitives -p zakura-zcash-script
cargo test -p zakura-protocol -p zakura-address -p zakura-transparent -p zakura-primitives -p zakura-zcash-script \
  --features zakura-protocol/ycash,zakura-address/ycash,zakura-transparent/ycash,zakura-primitives/ycash
```

### Triggers

The Yellowback lead architect's rule (2026-11-01): nothing runs for a branch that is not the
fork's, and nothing upstream's release or maintenance machinery would start. Every file in
`.github/workflows/` keeps to this policy, and `ycash-check.yml`'s `workflow triggers` job
(`.github/scripts/check_workflow_triggers.py`, the reader and policy of kogany's
`qa/kogany_audit.py` `workflows` leg; tests in `test_check_workflow_triggers.py`) fails when one
does not:

| Event | Allowed |
| --- | --- |
| `push` | only with a `branches:` filter within `upgrade/vault` and `vaults/**`; no `branches-ignore`, no tags |
| `pull_request` | only with a `branches:` filter (the base) within `upgrade/vault`, `vaults/**` and `kc/**` |
| `schedule` | yes (GitHub runs it from the default branch, `upgrade/vault`, only) |
| `workflow_dispatch`, `workflow_call` | yes |
| anything else | no: no `create`, `delete`, `merge_group`, `pull_request_target`, `workflow_run` |

So upstream's `main`, `feat/**`, `perf/**`, `release/**` and `agent/**` triggers and the merge
queue are commented out in the kept workflows, each with a `zakura-common-ycash (2026-11-01)`
comment, and `semgrep.yml` no longer runs on pushes to every branch. A push to an agent branch
or an inherited upstream branch, or a branch deletion, starts nothing. `ci.yml` has no
`workflow_dispatch`, because its path filter supports only pull request and push events;
`ycash-check.yml` is the dispatchable check. Scheduled runs (the nightly `supply-chain.yml`,
`semgrep.yml` and `secops.yml`, and the weekly `codeql.yml`) start doing useful work once the
default branch, `upgrade/vault`, carries these files.

### `ycash-check.yml`

The fork's own workflow, callable from kogany (`workflow_call`, inputs `ref` and `tests`) and
dispatchable; it publishes nothing (no artifact, release or cache save). Two independent jobs, so
either re-runs alone: `workflow triggers` (every push and pull request; seconds) and
`ycash feature off` / `ycash feature on` (only when called or dispatched with `tests`: the local
gate above, about 10 minutes each; on pushes and pull requests `ci.yml`'s `librustzcash-test`
runs the same legs).

## Why the off workflows are moved, not disabled in the settings

kogany now uses the same mechanism (since 2026-11-02, its `.github/README-kogany.md`): GitHub runs only
files under `.github/workflows/`, so a file under `.github/workflows-off/` cannot run, whatever
the settings say. The fork's settings are not ours to change in this change, and the fork must be
safe whatever they are. The moved files are unchanged, so git's rename detection carries an
upstream edit to them across a sync.

| Off | Why |
| --- | --- |
| `publish-crates.yml` | upstream's crates.io release pipeline (OIDC trusted publishing). The fork publishes no crate: its crates carry a `+ycash.1` build suffix and are consumed by git rev only |
| `semver.yml` | crates.io semver policy against the published baselines. The fork's additions (`NetworkUpgrade::Ycash`, `Vault`) are deliberate API changes it never publishes |
| `changelog.yml` | upstream's changelog-fragment policy for its release notes. The fork's record is its commit messages (with the four-part check for consensus changes) |
| `maintenance.yml` | nightly latest-dependency builds of every upstream crate, which belong to upstream's own maintenance. The fork's dependencies move only with an upstream sync |

To turn one back on, move it back with `git mv` and list the edits it needs here. A workflow that
an upstream sync adds lands in `.github/workflows/` and runs. At every sync, classify each new
workflow in the table above, and move it off if it is a release or fleet job.

`ci.yml` has six jobs that upstream itself turned off with `if: false` (Sensei and Udon). They stay
as upstream wrote them; `.github/actionlint.yaml` ignores that one actionlint finding for `ci.yml`.

## Security CI

This is the same design as every Yellowback repository (ycash6's `SECURITY-CI.md`), trimmed to what
a crate fork needs. The workflows and `contrib/semgrep/` scripts are copied from kogany's; the
lists are this repository's own.

| Leg | Workflow / job | Blocks a pull request when | Accepting a finding |
| --- | --- | --- | --- |
| Semgrep | `semgrep.yml` | the PR adds a critical finding | `contrib/semgrep/accepted.json`, `contrib/semgrep/config.json` |
| CodeQL (`rust`, `python`, `actions`) | `codeql.yml` | never (code scanning shows new alerts) | dismissed in code scanning, with the reason |
| gitleaks | `secops.yml` `gitleaks` | a leak not accepted | `.gitleaksignore` (fingerprints, each under its reason), `.gitleaks.toml` |
| OSV-Scanner | `secops.yml` `osv-scanner` | a known vulnerability not accepted | `osv-scanner.toml` (reason and an expiry at most 90 days out) |
| cargo-deny | `secops.yml` `cargo-deny` | an advisory, ban or source not allowed | `contrib/secops/deny-fork.toml` |
| Semgrep rule tests | `secops.yml` `semgrep-rules` | a rule test fails | `contrib/semgrep/rules/` |
| zizmor | `workflow-security.yml` (upstream's, kept) | any finding | an inline `zizmor: ignore[rule]` with its reason |
| Dependabot | `.github/dependabot.yml` | n/a | security updates only |

Upstream's own checks stay beside these: `supply-chain.yml` runs `cargo deny` with the root
`deny.toml` (advisories report-only there) and `cargo vet` over `supply-chain/`. The OSV and
cargo-deny ignores, triaged on 2026-11-01, are all upstream's `Cargo.lock` entries. That lock serves
only the fork's CI; kogany resolves the fork's crates in its own `Cargo.lock`, which is what ships.
The local Semgrep rule `ycash.consensus.branch-id-literal-outside-definition` keeps Ycash's branch
IDs to their one definition in `crates/zcash_protocol/src/consensus.rs`.

### Turning Actions on

Do this when the Yellowback lead architect decides to:

1. Settings → Code security: enable code scanning (for the SARIF uploads) and Dependabot security
   updates. For `semgrep.yml`'s `sync` job, allow GitHub Actions to create pull requests
   (optionally with the `SEMGREP_PR_TOKEN` secret, see `contrib/semgrep/README.md`).
2. Set the default branch to `upgrade/vault` before relying on any scheduled run.
3. Nothing has to be disabled: the off set lives in `.github/workflows-off/`, and every other
   workflow triggers only on the fork's branches (Triggers above).
4. Rulesets on `vaults/kogany-compat` and `upgrade/vault`, after the first green run: require
   `workflow triggers`, `ci.yml`'s `test-success`, and the security checks.
