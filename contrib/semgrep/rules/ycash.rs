// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .
//
// Test cases for ycash.yaml (`contrib/semgrep/scan.py --test`). Not compiled.

fn second_definition() -> u32 {
    // ruleid: ycash.consensus.branch-id-literal-outside-definition
    let vault = 0x6d5b_7a31;
    // ruleid: ycash.consensus.branch-id-literal-outside-definition
    let ycash = 0x374D694Fu32;
    vault ^ ycash
}

fn named_in_prose() -> u32 {
    // ok: ycash.consensus.branch-id-literal-outside-definition
    // The Vault epoch's branch ID is 0x6d5b7a31 (ZIP-200 style).
    u32::from(BranchId::Vault)
}

fn pinned_by_a_test() {
    // ok: ycash.consensus.branch-id-literal-outside-definition
    assert_eq!(u32::from(BranchId::Vault), 0x6d5b7a31);
}
