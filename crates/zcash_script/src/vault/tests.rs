//! Tests of the vault extensions: the semantics of ycash6's `vault_script_tests.cpp` and
//! `pq_script_tests.cpp`, and replays of the pinned cross-line vectors (`testdata/yellowback/`)
//! against a mock checker.

use alloc::vec::Vec;
use core::cell::RefCell;

use sha2::{Digest, Sha256};

use super::{VaultOp, is_compact_set_signature, pq, pq_sig_op_count};
use crate::{
    interpreter::{
        self, Error, Flags, NullSignatureChecker, SEQUENCE_LOCKTIME_DISABLE_FLAG,
        SEQUENCE_LOCKTIME_TYPE_FLAG, SET_SIG_SIZE, SignatureChecker, Stack,
    },
    num,
    opcode::{self, PushValue},
    script::{self, Evaluable},
    signature,
};

// ---------------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------------

const CSV: Flags = Flags::CHECKSEQUENCEVERIFY;
const VAULT: Flags = Flags::Vault;
const FALCON: Flags = Flags::PqFalcon;

/// ycash6 `STANDARD_SCRIPT_VERIFY_FLAGS`, in this crate's flags (DERSIG is always enforced here).
const STANDARD: Flags = Flags::P2SH
    .union(Flags::StrictEnc)
    .union(Flags::MinimalData)
    .union(Flags::NullDummy)
    .union(Flags::DiscourageUpgradableNOPs)
    .union(Flags::CleanStack)
    .union(Flags::CHECKLOCKTIMEVERIFY)
    .union(Flags::LowS);

/// A tiny script builder with minimal pushes.
#[derive(Clone, Default)]
struct S(Vec<u8>);

impl S {
    fn new() -> Self {
        Self::default()
    }
    fn d(mut self, v: &[u8]) -> Self {
        let pv = PushValue::from_slice(v).expect("push fits");
        self.0.extend(Vec::<u8>::from(&pv));
        self
    }
    fn n(self, n: i64) -> Self {
        self.d(&num::serialize(n))
    }
    fn op(mut self, b: u8) -> Self {
        self.0.push(b);
        self
    }
    fn raw(mut self, b: &[u8]) -> Self {
        self.0.extend_from_slice(b);
        self
    }
    fn code(&self) -> script::Code {
        script::Code(self.0.clone())
    }
}

const OP_0: u8 = 0x00;
const OP_1: u8 = 0x51;
const OP_2: u8 = 0x52;
const OP_3: u8 = 0x53;
const OP_1NEGATE: u8 = 0x4f;
const OP_IF: u8 = 0x63;
const OP_ENDIF: u8 = 0x68;
const OP_VERIFY: u8 = 0x69;
const OP_DROP: u8 = 0x75;
const OP_NOT: u8 = 0x91;
const OP_PICK: u8 = 0x79;
const OP_CHECKSIG: u8 = 0xac;
const OP_CSV: u8 = 0xb2;
const OP_CHECKSETSIG: u8 = 0xc0;
const OP_CHECKSETDORMANT: u8 = 0xc1;
const OP_CHECKPQSIG: u8 = 0xc2;

/// Evaluates one script on an empty stack; the interpreter error, if any.
fn eval(s: &S, flags: Flags, checker: &dyn SignatureChecker) -> Result<Stack<Vec<u8>>, Error> {
    s.code()
        .eval(flags, checker, Stack::new())
        .map_err(|e| match e {
            script::Error::Interpreter(_, ie) => ie.normalize(),
            other => panic!("not an interpreter error: {other:?}"),
        })
}

fn top(stack: &Stack<Vec<u8>>) -> Vec<u8> {
    stack.rget(0).expect("non-empty").clone()
}

/// `VerifyScript(scriptSig, scriptPubKey)`: Ok(bool) or the normalized error.
fn verify(
    sig: &[u8],
    spk: &[u8],
    flags: Flags,
    checker: &dyn SignatureChecker,
) -> Result<bool, script::Error> {
    script::Raw::from_raw_parts(sig.to_vec(), spk.to_vec())
        .eval(flags, checker)
        .map_err(|(_, e)| match e {
            script::Error::Interpreter(_, ie) => script::Error::Interpreter(None, ie.normalize()),
            other => other,
        })
}

fn ierr(e: Error) -> script::Error {
    script::Error::Interpreter(None, e)
}

/// What `check_pq_sig` was given: (scheme, signature, hash-type bits, public key).
type PqCall = (u8, Vec<u8>, i32, Vec<u8>);

/// A checker whose answers the test sets, recording what the interpreter passes it.
#[derive(Default)]
struct Mock {
    lock_time_ok: bool,
    /// `(tx version, input nSequence)` for `check_sequence`.
    sequence: Option<(u32, u32)>,
    threshold: Option<u32>,
    /// `Some(sigs)`: `check_set_sigs` accepts exactly these; `None`: accepts iff `sigs_ok`.
    expected_sigs: Option<Vec<[u8; SET_SIG_SIZE]>>,
    sigs_ok: bool,
    released: bool,
    /// `Some((scheme, sig, hash type bits, pk))`: `check_pq_sig` accepts exactly this.
    expected_pq: Option<PqCall>,
    /// accept any PQ signature (the shape checks are the interpreter's)
    pq_any: bool,

    set_sig_calls: RefCell<u32>,
    last_set: RefCell<Option<([u8; 32], u8)>>,
    last_sigs: RefCell<Vec<[u8; SET_SIG_SIZE]>>,
    last_dormant: RefCell<Option<[u8; 32]>>,
    pq_calls: RefCell<u32>,
    last_pq: RefCell<Option<PqCall>>,
}

impl SignatureChecker for Mock {
    fn check_sig(&self, _: &signature::Decoded, _: &[u8], _: &script::Code) -> bool {
        false
    }
    fn check_lock_time(&self, _lock_time: i64) -> bool {
        self.lock_time_ok
    }
    fn check_sequence(&self, sequence: i64) -> bool {
        self.sequence
            .is_some_and(|(v, s)| interpreter::check_sequence(v, s, sequence))
    }
    fn set_threshold(&self, set_id: &[u8; 32], role: u8) -> Option<u32> {
        *self.last_set.borrow_mut() = Some((*set_id, role));
        self.threshold
    }
    fn check_set_sigs(
        &self,
        set_id: &[u8; 32],
        role: u8,
        sigs: &[[u8; SET_SIG_SIZE]],
        _script_code: &script::Code,
    ) -> bool {
        *self.set_sig_calls.borrow_mut() += 1;
        assert_eq!(*self.last_set.borrow(), Some((*set_id, role)));
        *self.last_sigs.borrow_mut() = sigs.to_vec();
        match &self.expected_sigs {
            Some(want) => want.as_slice() == sigs,
            None => self.sigs_ok,
        }
    }
    fn is_set_released(&self, set_id: &[u8; 32]) -> bool {
        *self.last_dormant.borrow_mut() = Some(*set_id);
        self.released
    }
    fn check_pq_sig(
        &self,
        scheme: u8,
        sig: &[u8],
        hash_type: &signature::HashType,
        pub_key: &[u8],
        _script_code: &script::Code,
    ) -> bool {
        *self.pq_calls.borrow_mut() += 1;
        let got = (scheme, sig.to_vec(), hash_type.raw_bits(), pub_key.to_vec());
        *self.last_pq.borrow_mut() = Some(got.clone());
        self.pq_any || self.expected_pq.as_ref() == Some(&got)
    }
}

fn set_id_bytes(fill: u8) -> [u8; 32] {
    let mut v = [fill; 32];
    v[0] = 0x01; // not symmetric, so a byte-order slip shows
    v
}

/// A well-formed set signature: header 31, r = s = small (low S).
fn good_sig(tag: u8) -> [u8; SET_SIG_SIZE] {
    let mut sig = [0u8; SET_SIG_SIZE];
    sig[0] = 31;
    sig[1] = tag;
    sig[64] = tag;
    sig
}

fn chunks(v: &[u8]) -> Vec<&[u8]> {
    v.chunks(pq::MAX_CHUNK).collect()
}

/// `<sig_1>..<sig_s> <s> <pk_1>..<pk_p> <p>` (sig carries its hash-type byte).
fn pq_script_sig(sig: &[u8], pk: &[u8]) -> S {
    let mut s = S::new();
    let sc = chunks(sig);
    for c in &sc {
        s = s.d(c);
    }
    s = s.n(sc.len() as i64);
    let pc = chunks(pk);
    for c in &pc {
        s = s.d(c);
    }
    s.n(pc.len() as i64)
}

/// TX_PQPKH: `<keyHash:32> <scheme> OP_CHECKPQSIG`.
fn pqpkh(key_hash: &[u8], scheme: u8) -> S {
    S::new().d(key_hash).n(i64::from(scheme)).op(OP_CHECKPQSIG)
}

fn pq_operands(scheme: u8, sig: &[u8], pk: &[u8], key_hash: &[u8]) -> S {
    let s = pq_script_sig(sig, pk);
    S(s.0).d(key_hash).n(i64::from(scheme))
}

fn fake_key(scheme: u8) -> (Vec<u8>, Vec<u8>) {
    let pk = vec![0x11; pq::pub_key_size(scheme)];
    let mut sig = vec![0x22; pq::sig_size(scheme)];
    sig.push(1); // SIGHASH_ALL
    (pk, sig)
}

// ---------------------------------------------------------------------------------------------
// The registry and the opcodes' bytes
// ---------------------------------------------------------------------------------------------

#[test]
fn constants() {
    assert_eq!(Flags::CHECKSEQUENCEVERIFY.bits(), 1 << 10);
    assert_eq!(Flags::Vault.bits(), 1 << 11);
    assert_eq!(Flags::PqFalcon.bits(), 1 << 12);
    assert_eq!(VaultOp::OP_CHECKSETSIG.encode(), 0xc0);
    assert_eq!(VaultOp::OP_CHECKSETDORMANT.encode(), 0xc1);
    assert_eq!(VaultOp::OP_CHECKPQSIG.encode(), 0xc2);
    for b in 0..=u8::MAX {
        let expect = matches!(b, 0xc0..=0xc2);
        assert_eq!(VaultOp::decode(b).is_some(), expect, "byte {b:#x}");
        if let Some(op) = VaultOp::decode(b) {
            assert_eq!(op.encode(), b);
            assert_eq!(
                opcode::PossiblyBad::from(op),
                opcode::PossiblyBad::Bad(opcode::Bad::Unknown(b))
            );
        }
    }
    // never 0xbb-0xbf (mapping §2)
    for b in 0xbb..=0xbf {
        assert!(VaultOp::decode(b).is_none());
    }
    assert_eq!(VaultOp::OP_CHECKPQSIG.name(), "OP_CHECKPQSIG");
    assert_eq!(pq::pub_key_size(1), 32);
    assert_eq!(pq::sig_size(1), 7856);
    assert_eq!(pq::pub_key_size(2), 897);
    assert_eq!(pq::sig_size(2), 666);
    assert_eq!(pq::pub_key_size(3), 0);
    assert!(!pq::is_known_scheme(0) && !pq::is_known_scheme(3));
    let mut h = Sha256::new();
    h.update([2u8, 0xaa, 0xbb]);
    assert_eq!(
        pq::key_hash(2, &[0xaa, 0xbb]),
        <[u8; 32]>::from(h.finalize())
    );
}

// ---------------------------------------------------------------------------------------------
// OP_CHECKSEQUENCEVERIFY (ycash6 vault_csv_vectors)
// ---------------------------------------------------------------------------------------------

fn csv_eval(arg: i64, tx_sequence: u32, flags: Flags) -> Result<(), Error> {
    let checker = Mock {
        sequence: Some((4, tx_sequence)),
        ..Mock::default()
    };
    eval(&S::new().n(arg).op(OP_CSV), flags, &checker).map(|_| ())
}

#[test]
fn csv_vectors() {
    // Without the flag: OP_NOP3, as upstream.
    assert_eq!(csv_eval(10, 0, Flags::empty()), Ok(()));
    assert_eq!(
        csv_eval(10, 0, Flags::DiscourageUpgradableNOPs),
        Err(Error::DiscourageUpgradableNOPs)
    );
    // ... and the flag does not discourage it.
    assert_eq!(
        csv_eval(10, 10, CSV | Flags::DiscourageUpgradableNOPs),
        Ok(())
    );

    // With it: BIP112.
    assert_eq!(csv_eval(10, 10, CSV), Ok(()));
    assert_eq!(csv_eval(10, 11, CSV), Ok(()));
    assert_eq!(csv_eval(10, 9, CSV), Err(Error::UnsatisfiedLockTime));
    assert_eq!(csv_eval(0, 0, CSV), Ok(()));
    assert_eq!(csv_eval(65535, 65535, CSV), Ok(()));
    assert_eq!(csv_eval(-1, 10, CSV), Err(Error::NegativeLockTime));
    // The input's disable flag defeats the check.
    assert_eq!(csv_eval(10, u32::MAX, CSV), Err(Error::UnsatisfiedLockTime));
    assert_eq!(
        csv_eval(10, SEQUENCE_LOCKTIME_DISABLE_FLAG | 20, CSV),
        Err(Error::UnsatisfiedLockTime)
    );
    // An operand with the disable flag is a NOP (BIP112's extension point).
    assert_eq!(
        csv_eval(i64::from(SEQUENCE_LOCKTIME_DISABLE_FLAG), 0, CSV),
        Ok(())
    );
    assert_eq!(
        csv_eval(
            i64::from(SEQUENCE_LOCKTIME_DISABLE_FLAG | SEQUENCE_LOCKTIME_TYPE_FLAG),
            0,
            CSV
        ),
        Ok(())
    );
    // Ycash: an operand with the type flag (time-based) fails, whatever the input says.
    assert_eq!(
        csv_eval(
            i64::from(SEQUENCE_LOCKTIME_TYPE_FLAG | 1),
            SEQUENCE_LOCKTIME_TYPE_FLAG | 5,
            CSV
        ),
        Err(Error::UnsatisfiedLockTime)
    );
    assert_eq!(
        csv_eval(i64::from(SEQUENCE_LOCKTIME_TYPE_FLAG), 0, CSV),
        Err(Error::UnsatisfiedLockTime)
    );
    // A height operand against a time-typed input fails (apples to apples).
    assert_eq!(
        csv_eval(1, SEQUENCE_LOCKTIME_TYPE_FLAG | 5, CSV),
        Err(Error::UnsatisfiedLockTime)
    );
    // Bits outside the mask and the type flag are ignored on both sides.
    assert_eq!(csv_eval(0x3fbf_0000 | 10, 10, CSV), Ok(()));
    assert_eq!(csv_eval(10, 0x3fbf_0000 | 10, CSV), Ok(()));
    // A 5-byte operand is accepted (as CLTV); 2^32 masks to 0.
    assert_eq!(csv_eval(0x1_0000_0000, 0, CSV), Ok(()));
    // A 6-byte operand is a number error.
    assert!(matches!(
        csv_eval(0x100_0000_0000, 0, CSV),
        Err(Error::Num(_))
    ));

    // Empty stack.
    let checker = Mock {
        sequence: Some((4, 0)),
        ..Mock::default()
    };
    assert_eq!(
        eval(&S::new().op(OP_CSV), CSV, &checker).map(|_| ()),
        Err(Error::InvalidStackOperation(None))
    );
    // CSV leaves its operand (like CLTV); the null checker refuses every sequence.
    assert_eq!(
        eval(&S::new().n(5).op(OP_CSV), CSV, &NullSignatureChecker()).map(|_| ()),
        Err(Error::UnsatisfiedLockTime)
    );
    let checker = Mock {
        sequence: Some((4, 5)),
        ..Mock::default()
    };
    let stack = eval(&S::new().n(5).op(OP_CSV), CSV, &checker).expect("satisfied");
    assert_eq!(stack.len(), 1);
    // A pre-BIP68 (v1) transaction cannot satisfy CSV.
    let checker = Mock {
        sequence: Some((1, 5)),
        ..Mock::default()
    };
    assert_eq!(
        eval(&S::new().n(5).op(OP_CSV), CSV, &checker).map(|_| ()),
        Err(Error::UnsatisfiedLockTime)
    );
    // Unexecuted, it is skipped.
    assert!(
        eval(
            &S::new().op(OP_0).op(OP_IF).op(OP_CSV).op(OP_ENDIF).op(OP_1),
            CSV,
            &NullSignatureChecker()
        )
        .is_ok()
    );
}

#[test]
fn check_sequence_helper() {
    use interpreter::check_sequence;
    assert!(check_sequence(4, 10, 10));
    assert!(check_sequence(2, 10, 9));
    assert!(!check_sequence(1, 10, 9));
    assert!(!check_sequence(4, 9, 10));
    assert!(!check_sequence(4, SEQUENCE_LOCKTIME_DISABLE_FLAG, 0));
    assert!(check_sequence(
        4,
        SEQUENCE_LOCKTIME_TYPE_FLAG | 5,
        i64::from(SEQUENCE_LOCKTIME_TYPE_FLAG | 5)
    ));
    assert!(!check_sequence(4, SEQUENCE_LOCKTIME_TYPE_FLAG | 5, 5));
}

// ---------------------------------------------------------------------------------------------
// The opcodes without the flag (ycash6 vault_opcodes_without_flag, T-4)
// ---------------------------------------------------------------------------------------------

#[test]
fn opcodes_without_flag() {
    let set_id = set_id_bytes(0x5a);
    let checker = Mock {
        threshold: Some(1),
        sigs_ok: true,
        released: true,
        pq_any: true,
        lock_time_ok: true,
        ..Mock::default()
    };
    let pre_activation = [
        Flags::empty(),
        Flags::P2SH | Flags::CHECKLOCKTIMEVERIFY,
        CSV,
    ];
    for flags in pre_activation {
        let full = S::new()
            .d(&good_sig(1))
            .d(&set_id)
            .op(OP_1)
            .op(OP_CHECKSETSIG);
        assert_eq!(
            eval(&full, flags, &checker).map(|_| ()),
            Err(Error::BadOpcode)
        );
        let d = S::new().d(&set_id).op(OP_CHECKSETDORMANT);
        assert_eq!(eval(&d, flags, &checker).map(|_| ()), Err(Error::BadOpcode));
        for op in [OP_CHECKSETSIG, OP_CHECKSETDORMANT, OP_CHECKPQSIG] {
            assert_eq!(
                eval(&S::new().op(op), flags, &checker).map(|_| ()),
                Err(Error::BadOpcode)
            );
        }
        // Unexecuted, they are skipped, as any unknown byte.
        let skipped = S::new()
            .op(OP_0)
            .op(OP_IF)
            .op(OP_CHECKSETSIG)
            .op(OP_CHECKSETDORMANT)
            .op(OP_CHECKPQSIG)
            .op(OP_ENDIF)
            .op(OP_1);
        assert_eq!(eval(&skipped, flags, &checker).map(|s| s.len()), Ok(1));
    }
    // 0xba-0xbf and 0xc3.. stay bad with every new flag.
    for b in (0xba..=0xbf).chain(0xc3..=0xff) {
        let r = eval(&S::new().op(b), CSV | VAULT | FALCON, &checker);
        assert_eq!(r.map(|_| ()), Err(Error::BadOpcode), "byte {b:#x}");
    }
    assert_eq!(*checker.set_sig_calls.borrow(), 0);
    assert_eq!(*checker.pq_calls.borrow(), 0);

    // The scriptSig side (T-4): before the upgrade, BAD_OPCODE where executed; after it, the
    // bare opcode fails on the empty stack, and operands are refused by SigPushOnly.
    let (pk, sig) = fake_key(pq::SCHEME_SLH_DSA_SHA2_128S);
    let cases: [(u8, S); 3] = [
        (OP_CHECKSETSIG, S::new().d(&good_sig(1)).d(&set_id).op(OP_1)),
        (OP_CHECKSETDORMANT, S::new().d(&set_id)),
        (
            OP_CHECKPQSIG,
            pq_operands(pq::SCHEME_SLH_DSA_SHA2_128S, &sig, &pk, &[0x33; 32]),
        ),
    ];
    let spk_true = S::new().op(OP_1);
    for (op, operands) in cases {
        let bare = S::new().op(op);
        let full = operands.clone().op(op);
        let skipped = S::new().op(OP_0).op(OP_IF).op(op).op(OP_ENDIF);
        for flags in pre_activation {
            assert_eq!(
                verify(&bare.0, &spk_true.0, flags, &checker),
                Err(ierr(Error::BadOpcode))
            );
            assert_eq!(
                verify(&full.0, &spk_true.0, flags, &checker),
                Err(ierr(Error::BadOpcode))
            );
            assert_eq!(verify(&skipped.0, &spk_true.0, flags, &checker), Ok(true));
            assert_eq!(
                verify(&full.0, &spk_true.0, flags | Flags::SigPushOnly, &checker),
                Err(script::Error::SigPushOnly)
            );
            assert_eq!(
                verify(&bare.0, &spk_true.0, flags | VAULT, &checker),
                Err(ierr(Error::InvalidStackOperation(None)))
            );
            assert_eq!(
                verify(
                    &full.0,
                    &spk_true.0,
                    flags | VAULT | Flags::SigPushOnly,
                    &checker
                ),
                Err(script::Error::SigPushOnly)
            );
        }
    }
}

// ---------------------------------------------------------------------------------------------
// OP_CHECKSETSIG (ycash6 vault_checksetsig)
// ---------------------------------------------------------------------------------------------

#[test]
fn checksetsig() {
    let set_id = set_id_bytes(0x5a);
    let (sig1, sig2, sig3) = (good_sig(1), good_sig(2), good_sig(3));

    // Pop order: role on top, then setId, then k sigs; handed over in push order.
    {
        let checker = Mock {
            threshold: Some(2),
            sigs_ok: true,
            ..Mock::default()
        };
        let s = S::new()
            .d(&sig3)
            .d(&sig1)
            .d(&sig2)
            .d(&set_id)
            .op(OP_1)
            .op(OP_CHECKSETSIG);
        let stack = eval(&s, VAULT, &checker).expect("ok");
        assert_eq!(*checker.last_set.borrow(), Some((set_id, 1)));
        assert_eq!(*checker.set_sig_calls.borrow(), 1);
        assert_eq!(*checker.last_sigs.borrow(), vec![sig1, sig2]);
        // Exactly k popped; success pushes 1.
        assert_eq!(stack.len(), 2);
        assert_eq!(stack.rget(1).unwrap().as_slice(), &sig3[..]);
        assert_eq!(top(&stack), vec![1]);
    }
    // Role 2 (cancel).
    {
        let checker = Mock {
            threshold: Some(1),
            sigs_ok: true,
            ..Mock::default()
        };
        let s = S::new().d(&sig1).d(&set_id).op(OP_2).op(OP_CHECKSETSIG);
        assert!(eval(&s, VAULT, &checker).is_ok());
        assert_eq!(checker.last_set.borrow().map(|(_, r)| r), Some(2));
    }
    // Operands in the wrong order, wrong sizes, wrong roles.
    {
        let checker = Mock {
            threshold: Some(1),
            sigs_ok: true,
            ..Mock::default()
        };
        let bad = [
            S::new().d(&sig1).op(OP_1).d(&set_id),
            S::new().d(&sig1).d(&[7; 31]).op(OP_1),
            S::new().d(&sig1).d(&[7; 33]).op(OP_1),
            S::new().d(&sig1).d(&set_id).op(OP_0),
            S::new().d(&sig1).d(&set_id).op(OP_3),
            S::new().d(&sig1).d(&set_id).op(OP_1NEGATE),
            S::new().d(&sig1).d(&set_id).d(&[1, 0]),
        ];
        for s in bad {
            assert_eq!(
                eval(&s.op(OP_CHECKSETSIG), VAULT, &checker).map(|_| ()),
                Err(Error::SetSig)
            );
        }
        for s in [S::new().d(&set_id), S::new()] {
            assert_eq!(
                eval(&s.op(OP_CHECKSETSIG), VAULT, &checker).map(|_| ()),
                Err(Error::InvalidStackOperation(None))
            );
        }
        assert_eq!(*checker.set_sig_calls.borrow(), 0);
    }
    // k from the checker: unknown set, too few signatures, zero.
    {
        for (threshold, s) in [
            (None, S::new().d(&sig1)),
            (Some(3), S::new().d(&sig1).d(&sig2)),
            (Some(0), S::new().d(&sig1)),
        ] {
            let checker = Mock {
                threshold,
                sigs_ok: true,
                ..Mock::default()
            };
            let s = s.d(&set_id).op(OP_1).op(OP_CHECKSETSIG);
            assert_eq!(eval(&s, VAULT, &checker).map(|_| ()), Err(Error::SetSig));
            assert_eq!(*checker.set_sig_calls.borrow(), 0);
        }
    }
    // Signature shape: 65 bytes, header 31..=34, low S.
    {
        let checker = Mock {
            threshold: Some(1),
            sigs_ok: true,
            ..Mock::default()
        };
        let one = |sig: &[u8]| {
            eval(
                &S::new().d(sig).d(&set_id).op(OP_1).op(OP_CHECKSETSIG),
                VAULT,
                &checker,
            )
            .map(|_| ())
        };
        assert_eq!(one(&[1; 64]), Err(Error::SetSig));
        let mut longer = sig1.to_vec();
        longer.push(0);
        assert_eq!(one(&longer), Err(Error::SetSig));
        for header in [27u8, 28, 29, 30, 35, 0] {
            let mut s = sig1;
            s[0] = header;
            assert_eq!(one(&s), Err(Error::SetSig));
        }
        for header in [31u8, 32, 33, 34] {
            let mut s = sig1;
            s[0] = header;
            assert_eq!(one(&s), Ok(()));
        }
        // s = n/2 is low, n/2 + 1 is high.
        let half = hex::decode("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0")
            .unwrap();
        let mut s = sig1;
        s[33..].copy_from_slice(&half);
        assert_eq!(one(&s), Ok(()));
        assert!(is_compact_set_signature(&s));
        s[64] = 0xA1;
        assert_eq!(one(&s), Err(Error::SetSig));
        s[33..].fill(0xff);
        assert_eq!(one(&s), Err(Error::SetSig));
    }
    // The checker's verdict: a failure is an error, never a false result.
    {
        let checker = Mock {
            threshold: Some(1),
            sigs_ok: false,
            ..Mock::default()
        };
        let s = S::new()
            .d(&sig1)
            .d(&set_id)
            .op(OP_1)
            .op(OP_CHECKSETSIG)
            .op(OP_NOT);
        assert_eq!(eval(&s, VAULT, &checker).map(|_| ()), Err(Error::SetSig));
        assert_eq!(*checker.set_sig_calls.borrow(), 1);
    }
    // At most one OP_CHECKSETSIG per evaluation, executed; one in an unexecuted branch is fine.
    {
        let checker = Mock {
            threshold: Some(1),
            sigs_ok: true,
            ..Mock::default()
        };
        let twice = S::new()
            .d(&sig1)
            .d(&set_id)
            .op(OP_1)
            .op(OP_CHECKSETSIG)
            .op(OP_DROP)
            .d(&sig2)
            .d(&set_id)
            .op(OP_2)
            .op(OP_CHECKSETSIG);
        assert_eq!(
            eval(&twice, VAULT, &checker).map(|_| ()),
            Err(Error::SetSigCount)
        );
        assert_eq!(*checker.set_sig_calls.borrow(), 1);
        let branch = S::new()
            .d(&sig1)
            .d(&set_id)
            .op(OP_1)
            .op(OP_CHECKSETSIG)
            .op(OP_0)
            .op(OP_IF)
            .op(OP_CHECKSETSIG)
            .op(OP_ENDIF);
        assert!(eval(&branch, VAULT, &checker).is_ok());
        // The counter is per evaluation: a fresh one may use it again.
        let s = S::new().d(&sig1).d(&set_id).op(OP_1).op(OP_CHECKSETSIG);
        assert!(eval(&s, VAULT, &checker).is_ok());
        // ... and per script component: the scriptSig and the scriptPubKey are two evaluations.
        let spk = S::new().d(&set_id).op(OP_2).op(OP_CHECKSETSIG);
        let sig = S::new()
            .d(&sig2)
            .d(&sig1)
            .d(&set_id)
            .op(OP_1)
            .op(OP_CHECKSETSIG)
            .op(OP_DROP);
        assert_eq!(verify(&sig.0, &spk.0, VAULT, &checker), Ok(true));
    }
    // The defaults fail closed: the existing checkers cannot satisfy it.
    let s = S::new().d(&sig1).d(&set_id).op(OP_1).op(OP_CHECKSETSIG);
    assert_eq!(
        eval(&s, VAULT, &NullSignatureChecker()).map(|_| ()),
        Err(Error::SetSig)
    );
    #[cfg(feature = "signature-validation")]
    {
        let cb = interpreter::CallbackTransactionSignatureChecker {
            sighash: &|_, _| Some([0; 32]),
            lock_time: 0,
            is_final: false,
        };
        assert_eq!(eval(&s, VAULT, &cb).map(|_| ()), Err(Error::SetSig));
        assert_eq!(
            eval(&S::new().n(5).op(OP_CSV), CSV, &cb).map(|_| ()),
            Err(Error::UnsatisfiedLockTime)
        );
        let d = S::new().d(&set_id).op(OP_CHECKSETDORMANT);
        assert_eq!(eval(&d, VAULT, &cb).map(|s| top(&s)), Ok(vec![]));
    }
}

// ---------------------------------------------------------------------------------------------
// OP_CHECKSETDORMANT (ycash6 vault_checksetdormant)
// ---------------------------------------------------------------------------------------------

#[test]
fn checksetdormant() {
    let set_id = set_id_bytes(0x33);
    let mut checker = Mock {
        released: true,
        ..Mock::default()
    };
    let d = S::new().d(&set_id).op(OP_CHECKSETDORMANT);
    let stack = eval(&d, VAULT, &checker).expect("ok");
    assert_eq!((stack.len(), top(&stack)), (1, vec![1]));
    assert_eq!(*checker.last_dormant.borrow(), Some(set_id));

    checker.released = false;
    let stack = eval(&d, VAULT, &checker).expect("ok");
    assert_eq!((stack.len(), top(&stack)), (1, vec![]));
    // ... so OP_VERIFY fails on a live set (the OWNER-RELEASED branch).
    assert_eq!(
        eval(&d.clone().op(OP_VERIFY), VAULT, &checker).map(|_| ()),
        Err(Error::Verify)
    );
    for bad in [S::new().d(&[1; 31]), S::new().d(&[1; 33])] {
        assert_eq!(
            eval(&bad.op(OP_CHECKSETDORMANT), VAULT, &checker).map(|_| ()),
            Err(Error::SetSig)
        );
    }
    assert_eq!(
        eval(&S::new().op(OP_CHECKSETDORMANT), VAULT, &checker).map(|_| ()),
        Err(Error::InvalidStackOperation(None))
    );
    // Not limited in count.
    let twice = d.clone().op(OP_DROP).d(&set_id).op(OP_CHECKSETDORMANT);
    assert!(eval(&twice, VAULT, &checker).is_ok());
    // The null checker says not released.
    assert_eq!(
        eval(&d, VAULT, &NullSignatureChecker()).map(|s| top(&s)),
        Ok(vec![])
    );
}

// ---------------------------------------------------------------------------------------------
// OP_CHECKPQSIG (ycash6 pq_script_tests)
// ---------------------------------------------------------------------------------------------

#[test]
fn pq_good_shapes_and_flags() {
    for scheme in [pq::SCHEME_SLH_DSA_SHA2_128S, pq::SCHEME_FN_DSA_512] {
        let (pk, sig) = fake_key(scheme);
        let kh = pq::key_hash(scheme, &pk);
        let checker = Mock {
            expected_pq: Some((scheme, sig[..sig.len() - 1].to_vec(), 1, pk.clone())),
            ..Mock::default()
        };
        let ss = pq_script_sig(&sig, &pk);
        let spk = pqpkh(&kh, scheme);
        let all = STANDARD | CSV | VAULT | FALCON;
        assert_eq!(verify(&ss.0, &spk.0, all, &checker), Ok(true));
        // the policy sigops: 20 per OP_CHECKPQSIG, none in the consensus count
        assert_eq!(spk.code().pq_sig_op_count(), pq::SIGOP_COST);
        assert_eq!(spk.code().sig_op_count(false), 0);
        assert_eq!(spk.code().sig_op_count(true), 0);
        // Falcon needs its flag; SLH-DSA does not.
        let no_falcon = verify(&ss.0, &spk.0, STANDARD | CSV | VAULT, &checker);
        if scheme == pq::SCHEME_FN_DSA_512 {
            assert_eq!(no_falcon, Err(ierr(Error::PqScheme)));
        } else {
            assert_eq!(no_falcon, Ok(true));
        }
        // no vault flag: a bad opcode
        assert_eq!(
            verify(&ss.0, &spk.0, STANDARD | CSV | FALCON, &checker),
            Err(ierr(Error::BadOpcode))
        );
        // a verdict of false pushes false
        let refuse = Mock::default();
        assert_eq!(verify(&ss.0, &spk.0, all, &refuse), Ok(false));
        assert_eq!(*refuse.pq_calls.borrow(), 1);
        // a key that does not hash to the key hash pushes false, without asking the checker
        let other = pqpkh(&[0x44; 32], scheme);
        let any = Mock {
            pq_any: true,
            ..Mock::default()
        };
        assert_eq!(verify(&ss.0, &other.0, all, &any), Ok(false));
        assert_eq!(*any.pq_calls.borrow(), 0);
        // the stack after: exactly one element (CleanStack passes above), true
        let stack = eval(
            &pq_operands(scheme, &sig, &pk, &kh).op(OP_CHECKPQSIG),
            VAULT | FALCON,
            &checker,
        )
        .expect("ok");
        assert_eq!((stack.len(), top(&stack)), (1, vec![1]));
    }
}

#[test]
fn pq_scheme_errors() {
    let (pk, sig) = fake_key(1);
    let kh = pq::key_hash(1, &pk);
    let checker = Mock {
        pq_any: true,
        ..Mock::default()
    };
    let flags = VAULT | FALCON;
    let base = pq_script_sig(&sig, &pk).d(&kh);
    // unknown schemes, a non-one-byte scheme element
    for bad in [
        base.clone().n(0),
        base.clone().n(3),
        base.clone().n(16),
        base.clone().d(&[1, 0]),
        base.clone().d(&[]),
    ] {
        assert_eq!(
            eval(&bad.op(OP_CHECKPQSIG), flags, &checker).map(|_| ()),
            Err(Error::PqScheme)
        );
    }
    // stack too small
    assert_eq!(
        eval(&S::new().n(1).op(OP_CHECKPQSIG), flags, &checker).map(|_| ()),
        Err(Error::InvalidStackOperation(None))
    );
    // the scheme is checked before the key hash
    assert_eq!(
        eval(
            &S::new().d(&[1; 31]).n(3).op(OP_CHECKPQSIG),
            flags,
            &checker
        )
        .map(|_| ()),
        Err(Error::PqScheme)
    );
    // key hash of the wrong size
    for kh_len in [0usize, 31, 33] {
        let s = pq_script_sig(&sig, &pk).d(&vec![9; kh_len]).n(1);
        assert_eq!(
            eval(&s.op(OP_CHECKPQSIG), flags, &checker).map(|_| ()),
            Err(Error::PqSize)
        );
    }
    assert_eq!(*checker.pq_calls.borrow(), 0);
}

#[test]
fn pq_canonical_chunking() {
    let checker = Mock {
        pq_any: true,
        ..Mock::default()
    };
    let flags = VAULT | FALCON;
    // SLH-DSA: the signature (7857 bytes with its hash type) is 16 chunks, the key 1.
    let scheme = pq::SCHEME_SLH_DSA_SHA2_128S;
    let (pk, sig) = fake_key(scheme);
    let kh = pq::key_hash(scheme, &pk);
    let tail = |s: S| s.d(&kh).n(i64::from(scheme)).op(OP_CHECKPQSIG);
    let run = |s: S| eval(&tail(s), flags, &checker).map(|st| top(&st));

    assert_eq!(run(pq_script_sig(&sig, &pk)), Ok(vec![1]));

    // counts: 0, too many, two-byte element
    let sc = chunks(&sig);
    let with = |sig_count: S, pk_part: S| {
        let mut s = S::new();
        for c in &sc {
            s = s.d(c);
        }
        S([s.0, sig_count.0, pk_part.0].concat())
    };
    let pk_part = S::new().d(&pk).n(1);
    assert_eq!(
        run(with(S::new().n(0), pk_part.clone())),
        Err(Error::PqChunk)
    );
    assert_eq!(
        run(with(S::new().n(17), pk_part.clone())),
        Err(Error::PqChunk)
    );
    assert_eq!(
        run(with(S::new().d(&[16, 0]), pk_part.clone())),
        Err(Error::PqChunk)
    );
    // the key's count: 0, 2 (max is 1 for 32 bytes)
    assert_eq!(
        run(with(S::new().n(16), S::new().d(&pk).n(0))),
        Err(Error::PqChunk)
    );
    assert_eq!(
        run(with(S::new().n(16), S::new().d(&pk).d(&pk).n(2))),
        Err(Error::PqChunk)
    );
    // fewer items than the count says: stack exhausted
    let short = S::new().d(&sig[..520]).n(16).d(&pk).n(1);
    assert_eq!(run(short), Err(Error::InvalidStackOperation(None)));

    // a non-final chunk shorter than 520 bytes (same total): not canonical
    let mut s = S::new();
    s = s.d(&sig[..519]);
    s = s.d(&sig[519..1039]);
    for c in sig[1039..].chunks(520) {
        s = s.d(c);
    }
    let n = 2 + sig[1039..].chunks(520).count();
    assert_eq!(n, 16);
    assert_eq!(run(s.n(n as i64).d(&pk).n(1)), Err(Error::PqChunk));
    // the right chunking of the wrong total size
    let (pk_short, sig_short) = (&pk[..31], &sig[..sig.len() - 1]);
    assert_eq!(run(pq_script_sig(&sig, pk_short)), Err(Error::PqSize));
    assert_eq!(run(pq_script_sig(sig_short, &pk)), Err(Error::PqSize));

    // Falcon: key 897 = 520 + 377, signature 667 = 520 + 147.
    let scheme = pq::SCHEME_FN_DSA_512;
    let (pk, sig) = fake_key(scheme);
    let kh = pq::key_hash(scheme, &pk);
    let run = |s: S| {
        eval(
            &s.d(&kh).n(i64::from(scheme)).op(OP_CHECKPQSIG),
            flags,
            &checker,
        )
        .map(|st| top(&st))
    };
    assert_eq!(run(pq_script_sig(&sig, &pk)), Ok(vec![1]));
    // three key chunks (max is two)
    let s = S::new()
        .d(&sig[..520])
        .d(&sig[520..])
        .n(2)
        .d(&pk[..300])
        .d(&pk[300..600])
        .d(&pk[600..])
        .n(3);
    assert_eq!(run(s), Err(Error::PqChunk));
    // a one-chunk key of 897 bytes cannot be pushed (over 520): the parser refuses it
    let mut raw = S::new().d(&sig[..520]).d(&sig[520..]).n(2).0;
    raw.push(0x4d);
    raw.extend_from_slice(&(pk.len() as u16).to_le_bytes());
    raw.extend_from_slice(&pk);
    let r = S(raw)
        .n(1)
        .d(&kh)
        .n(i64::from(scheme))
        .op(OP_CHECKPQSIG)
        .code()
        .eval(flags, &checker, Stack::new());
    assert!(matches!(
        r,
        Err(script::Error::Opcode(opcode::Error::PushSize(_)))
    ));
}

#[test]
fn pq_hashtypes() {
    let scheme = pq::SCHEME_SLH_DSA_SHA2_128S;
    let (pk, mut sig) = fake_key(scheme);
    let kh = pq::key_hash(scheme, &pk);
    let checker = Mock {
        pq_any: true,
        ..Mock::default()
    };
    for (ht, defined) in [
        (0x01u8, true),
        (0x02, true),
        (0x03, true),
        (0x81, true),
        (0x82, true),
        (0x83, true),
        (0x00, false),
        (0x04, false),
        (0x80, false),
        (0x84, false),
        (0x41, false),
        (0xff, false),
    ] {
        *sig.last_mut().unwrap() = ht;
        let s = pq_operands(scheme, &sig, &pk, &kh).op(OP_CHECKPQSIG);
        // without StrictEnc every hash type reaches the checker
        let before = *checker.pq_calls.borrow();
        assert_eq!(eval(&s, VAULT, &checker).map(|st| top(&st)), Ok(vec![1]));
        assert_eq!(*checker.pq_calls.borrow(), before + 1);
        assert_eq!(
            checker.last_pq.borrow().as_ref().map(|p| p.2),
            Some(i32::from(ht))
        );
        let strict = eval(&s, VAULT | Flags::StrictEnc, &checker).map(|st| top(&st));
        if defined {
            assert_eq!(strict, Ok(vec![1]), "{ht:#x}");
        } else {
            assert!(
                matches!(
                    strict,
                    Err(Error::SignatureEncoding(signature::Error::SigHashType(_)))
                ),
                "{ht:#x}"
            );
        }
    }
}

#[test]
fn pq_one_per_evaluation() {
    let scheme = pq::SCHEME_SLH_DSA_SHA2_128S;
    let (pk, sig) = fake_key(scheme);
    let kh = pq::key_hash(scheme, &pk);
    let checker = Mock {
        pq_any: true,
        ..Mock::default()
    };
    // the argument items (sig chunks, s, pk, p, keyHash, scheme): 16 + 1 + 1 + 1 + 2 = 21
    let args = pq_operands(scheme, &sig, &pk, &kh);
    let n = 21i64;
    let mut amplify = args.clone();
    for _ in 0..n {
        amplify = amplify.n(n - 1).op(OP_PICK);
    }
    let twice = amplify.op(OP_CHECKPQSIG).op(OP_DROP).op(OP_CHECKPQSIG);
    assert_eq!(
        eval(&twice, VAULT, &checker).map(|_| ()),
        Err(Error::PqCount)
    );
    assert_eq!(*checker.pq_calls.borrow(), 1);
    // unexecuted second one is fine
    let branch = args
        .clone()
        .op(OP_CHECKPQSIG)
        .op(OP_0)
        .op(OP_IF)
        .op(OP_CHECKPQSIG)
        .op(OP_ENDIF);
    assert!(eval(&branch, VAULT, &checker).is_ok());
    // OP_CHECKSETSIG and OP_CHECKPQSIG are counted separately
    let set_id = set_id_bytes(1);
    let both = S::new()
        .d(&good_sig(1))
        .d(&set_id)
        .op(OP_1)
        .op(OP_CHECKSETSIG)
        .op(OP_DROP)
        .raw(&args.0)
        .op(OP_CHECKPQSIG);
    let checker = Mock {
        pq_any: true,
        threshold: Some(1),
        sigs_ok: true,
        ..Mock::default()
    };
    assert_eq!(eval(&both, VAULT, &checker).map(|s| top(&s)), Ok(vec![1]));
}

#[test]
fn pq_sigops() {
    assert_eq!(pq_sig_op_count(&S::new().code()), 0);
    assert_eq!(
        pq_sig_op_count(&S::new().op(OP_CHECKPQSIG).op(OP_CHECKPQSIG).code()),
        2 * pq::SIGOP_COST
    );
    // inside a push: not an opcode
    assert_eq!(pq_sig_op_count(&S::new().d(&[OP_CHECKPQSIG]).code()), 0);
    // disabled opcodes and over-long pushes do not stop the walk (zcashd's GetOp reads them)
    let mut long = vec![0x4d, 0x09, 0x02];
    long.extend([0u8; 521]);
    assert_eq!(
        pq_sig_op_count(&S::new().op(0x7e).raw(&long).op(OP_CHECKPQSIG).code()),
        pq::SIGOP_COST
    );
    // a truncated push stops it
    assert_eq!(
        pq_sig_op_count(
            &S::new()
                .op(OP_CHECKPQSIG)
                .raw(&[0x05, 0x01])
                .op(OP_CHECKPQSIG)
                .code()
        ),
        pq::SIGOP_COST
    );
    // the set opcodes and CSV are not sigops; the legacy count is untouched
    let s = S::new()
        .op(OP_CHECKSETSIG)
        .op(OP_CHECKSETDORMANT)
        .op(OP_CSV)
        .op(OP_CHECKPQSIG)
        .op(OP_CHECKSIG);
    assert_eq!(s.code().pq_sig_op_count(), pq::SIGOP_COST);
    assert_eq!(s.code().sig_op_count(false), 1);
}
