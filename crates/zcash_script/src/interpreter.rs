//! Execution of opcodes

use alloc::vec::Vec;
use core::num::TryFromIntError;
use core::slice::Iter;

use thiserror::Error;

#[cfg(feature = "signature-validation")]
use crate::external::pubkey::PubKey;
use crate::{num, script, signature};

/// Any error that can happen during interpretation of a single opcode.
#[allow(missing_docs)]
#[derive(Clone, PartialEq, Eq, Debug, Error)]
pub enum Error {
    #[error("OP_RETURN encountered")]
    OpReturn,

    /// __NB__: This doesn’t take an “actual count” argument, because `OpCount` depends on
    ///         conditional execution and thus can only be checked incrementally. However, we could
    ///         statically check a “minimum operation count” for a script, which could then include
    ///         the minimum in the error.
    #[error("operation count exceeded maxmimum of {}", MAX_OP_COUNT)]
    OpCount,

    #[error("stack depth exceeded maxmimum of {} entries", MAX_STACK_DEPTH)]
    StackSize(Option<TryFromIntError>),

    #[error(
        "signature count wasn’t in the range 1..={}{}",
        MAX_PUBKEY_COUNT,
        .0.map_or("", |e| ": {e}")
    )]
    SigCount(Option<TryFromIntError>),

    #[error(
        "public key count wasn’t in the range 1..={}{}",
        MAX_PUBKEY_COUNT,
        .0.map_or("", |e| ": {e}")
    )]
    PubKeyCount(Option<TryFromIntError>),

    // Failed verify operations
    #[error("verify operation failed")]
    Verify,

    // Logical/Format/Canonical errors
    #[error("bad opcode encountered")]
    BadOpcode,

    #[error("{}", .0.map_or("invalid stack operation encountered", |(elem, max)| "tried to retrieve element {elem} from a stack with {max} elements"))]
    InvalidStackOperation(Option<(usize, usize)>),

    #[error("unbalanced conditional encountered")]
    UnbalancedConditional,

    // OP_CHECKLOCKTIMEVERIFY
    #[error("negative lock time encountered")]
    NegativeLockTime,

    #[error("unsatisfied locktime condition")]
    UnsatisfiedLockTime,

    #[error("signature encoding error: {0}")]
    SignatureEncoding(signature::Error),

    #[error("non-minimal data encountered when minimal data required")]
    MinimalData,

    #[error("signature null dummy error")]
    SigNullDummy,

    #[error("public key type error")]
    PubKeyType,

    // softfork safeness
    #[error("discouraged upgradable NOP encountered")]
    DiscourageUpgradableNOPs,

    // Ycash vault primitive (`OP_CHECKSETSIG` / `OP_CHECKSETDORMANT`); ycash6
    // `SCRIPT_ERR_SETSIG` and `SCRIPT_ERR_SETSIG_COUNT`.
    #[error("OP_CHECKSETSIG or OP_CHECKSETDORMANT failed")]
    SetSig,

    #[error("more than one OP_CHECKSETSIG in a script evaluation")]
    SetSigCount,

    // Ycash post-quantum signatures (`OP_CHECKPQSIG`); ycash6 `SCRIPT_ERR_PQ_*`.
    #[error("OP_CHECKPQSIG scheme unknown or not active")]
    PqScheme,

    #[error("OP_CHECKPQSIG key or signature chunking not canonical")]
    PqChunk,

    #[error("OP_CHECKPQSIG key, key hash or signature of the wrong size")]
    PqSize,

    #[error("more than one OP_CHECKPQSIG in a script evaluation")]
    PqCount,

    // extensions (these don’t exist in C++, and thus map to `UnknownError`)
    /// Corresponds to the `scriptnum_error` exception in C++.
    #[error("script number error: {0}")]
    Num(num::Error),
}

impl Error {
    /// Convert errors that don’t exist in the C++ code into the cases that do.
    pub(crate) fn normalize(&self) -> Self {
        match self {
            Self::InvalidStackOperation(Some(_)) => Self::InvalidStackOperation(None),
            Self::SignatureEncoding(sig_err) => match sig_err {
                signature::Error::SigHashType(Some(_)) => {
                    Self::from(signature::Error::SigHashType(None))
                }
                signature::Error::SigDER(Some(_)) => Self::from(signature::Error::SigDER(None)),
                _ => self.clone(),
            },
            Self::StackSize(Some(_)) => Self::StackSize(None),
            Self::SigCount(Some(_)) => Self::SigCount(None),
            Self::PubKeyCount(Some(_)) => Self::PubKeyCount(None),
            _ => self.clone(),
        }
    }
}

impl From<num::Error> for Error {
    fn from(value: num::Error) -> Self {
        Error::Num(value)
    }
}

impl From<signature::Error> for Error {
    fn from(value: signature::Error) -> Self {
        Error::SignatureEncoding(value)
    }
}

#[cfg(feature = "signature-validation")]
/// Threshold for lock_time: below this value it is interpreted as block number,
/// otherwise as UNIX timestamp.
const LOCKTIME_THRESHOLD: i64 = 500_000_000; // Tue Nov  5 00:53:20 1985 UTC

/// The maximum number of operations allowed in a script component.
pub(crate) const MAX_OP_COUNT: u8 = 201;

/// The maximum number of pubkeys (and signatures, by implication) allowed in CHECKMULTISIG.
pub(crate) const MAX_PUBKEY_COUNT: u8 = 20;

bitflags::bitflags! {
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    /// Script verification flags
    pub struct Flags: u32 {
        /// Evaluate P2SH subscripts (softfork safe,
        /// [BIP16](https://github.com/bitcoin/bips/blob/master/bip-0016.mediawiki).
        const P2SH = 1 << 0;

        /// Passing a non-strict-DER signature or one with undefined hashtype to a checksig operation causes script failure.
        /// Evaluating a pubkey that is not (0x04 + 64 bytes) or (0x02 or 0x03 + 32 bytes) by checksig causes script failure.
        /// (softfork safe, but not used or intended as a consensus rule).
        const StrictEnc = 1 << 1;

        /// Passing a non-strict-DER signature or one with S > order/2 to a checksig operation causes script failure
        /// (softfork safe, [BIP62](https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki) rule 5).
        const LowS = 1 << 3;

        /// verify dummy stack item consumed by CHECKMULTISIG is of zero-length (softfork safe, [BIP62](https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki) rule 7).
        const NullDummy = 1 << 4;

        /// Using a non-push operator in the scriptSig causes script failure (softfork safe, [BIP62](https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki) rule 2).
        const SigPushOnly = 1 << 5;

        /// Require minimal encodings for all push operations (OP_0... OP_16, OP_1NEGATE where possible, direct
        /// pushes up to 75 bytes, OP_PUSHDATA1 up to 255 bytes, OP_PUSHDATA2 for anything larger). Evaluating
        /// any other push causes the script to fail ([BIP62](https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki) rule 3).
        /// In addition, whenever a stack element is interpreted as a number, it must be of minimal length ([BIP62](https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki) rule 4).
        /// (softfork safe)
        const MinimalData = 1 << 6;

        /// Discourage use of NOPs reserved for upgrades (NOP1-10)
        ///
        /// Provided so that nodes can avoid accepting or mining transactions
        /// containing executed NOP's whose meaning may change after a soft-fork,
        /// thus rendering the script invalid; with this flag set executing
        /// discouraged NOPs fails the script. This verification flag will never be
        /// a mandatory flag applied to scripts in a block. NOPs that are not
        /// executed, e.g.  within an unexecuted IF ENDIF block, are *not* rejected.
        const DiscourageUpgradableNOPs = 1 << 7;

        /// Require that only a single stack element remains after evaluation. This changes the success criterion from
        /// "At least one stack element must remain, and when interpreted as a boolean, it must be true" to
        /// "Exactly one stack element must remain, and when interpreted as a boolean, it must be true".
        /// (softfork safe, [BIP62](https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki) rule 6)
        /// Note: CLEANSTACK should never be used without P2SH.
        const CleanStack = 1 << 8;

        /// Verify CHECKLOCKTIMEVERIFY
        ///
        /// See [BIP65](https://github.com/bitcoin/bips/blob/master/bip-0065.mediawiki) for details.
        const CHECKLOCKTIMEVERIFY = 1 << 9;

        /// Verify CHECKSEQUENCEVERIFY (`OP_NOP3`, 0xb2), height-based relative locks only.
        ///
        /// See [BIP112](https://github.com/bitcoin/bips/blob/master/bip-0112.mediawiki) for
        /// details. Ycash sets it from the vault network upgrade (ycash6
        /// `SCRIPT_VERIFY_CHECKSEQUENCEVERIFY`); an operand with the type flag (bit 22, time-based)
        /// fails. Without it, 0xb2 is `OP_NOP3` exactly as upstream.
        const CHECKSEQUENCEVERIFY = 1 << 10;

        /// Evaluate `OP_CHECKSETSIG` (0xc0), `OP_CHECKSETDORMANT` (0xc1) and `OP_CHECKPQSIG` (0xc2),
        /// the Ycash vault primitive's opcodes (ycash6 `SCRIPT_VERIFY_VAULT`). Without it all three
        /// are bad opcodes exactly as upstream. 0xbb–0xbf are never assigned.
        const Vault = 1 << 11;

        /// Admit `OP_CHECKPQSIG` scheme 0x02 (FN-DSA-512, Falcon). Only meaningful beside
        /// [`Flags::Vault`], and set from the network's Falcon height (ycash6
        /// `SCRIPT_VERIFY_PQ_FALCON`). Without it scheme 0x02 fails with [`Error::PqScheme`];
        /// scheme 0x01 (SLH-DSA) needs no flag of its own.
        const PqFalcon = 1 << 12;
    }
}

/// This verifies that a signature is correct for the given pubkey and script code.
pub trait SignatureChecker {
    /// Check that the signature is valid.
    fn check_sig(
        &self,
        script_sig: &signature::Decoded,
        vch_pub_key: &[u8],
        script_code: &script::Code,
    ) -> bool;

    /// Return true if the lock time argument is more recent than the time the script was evaluated.
    fn check_lock_time(&self, lock_time: i64) -> bool;

    // The Ycash extensions below (ycash6 `BaseSignatureChecker`) all have defaults that fail
    // closed, so every existing checker keeps compiling and can satisfy none of them.

    /// BIP112: true iff the relative lock `sequence` (already checked by the interpreter to be
    /// non-negative, without the disable flag and without the type flag) is satisfied by this
    /// input's `nSequence` and the transaction's version. See [`check_sequence`] for the
    /// comparison a transaction checker performs.
    fn check_sequence(&self, _sequence: i64) -> bool {
        false
    }

    /// The number of signatures `role` ([`SET_ROLE_UNLOCK`] or [`SET_ROLE_CANCEL`]) of the set
    /// `set_id` requires, or `None` if the set is unknown. `set_id` is the 32 bytes as pushed
    /// (ycash6 `uint256` internal byte order).
    fn set_threshold(&self, _set_id: &[u8; 32], _role: u8) -> Option<u32> {
        None
    }

    /// True iff `sigs` (65-byte compact recoverable signatures, in push order, `sig_1` first;
    /// their shape is already checked) are by distinct current members of `set_id` over the
    /// set-signature message for `role` and this input. `script_code` is the script being
    /// evaluated, as for [`SignatureChecker::check_sig`]. Set membership changes with the chain,
    /// so an implementation must not cache this verdict.
    fn check_set_sigs(
        &self,
        _set_id: &[u8; 32],
        _role: u8,
        _sigs: &[[u8; SET_SIG_SIZE]],
        _script_code: &script::Code,
    ) -> bool {
        false
    }

    /// True iff the set `set_id` is released (dormant, wound down, or unknown) at the spending
    /// height.
    fn is_set_released(&self, _set_id: &[u8; 32]) -> bool {
        false
    }

    /// `OP_CHECKPQSIG`: true iff `sig` (the scheme's signature, without the trailing hash-type
    /// byte) verifies under `scheme` and `pub_key` over the signature hash of `script_code` and
    /// `hash_type` (the signature's last byte, decoded without strictness). The interpreter has
    /// already checked the scheme, the sizes and that `pub_key` hashes to the script's key hash.
    fn check_pq_sig(
        &self,
        _scheme: u8,
        _sig: &[u8],
        _hash_type: &signature::HashType,
        _pub_key: &[u8],
        _script_code: &script::Code,
    ) -> bool {
        false
    }
}

/// `OP_CHECKSETSIG` role 1: the set's unlock threshold.
pub const SET_ROLE_UNLOCK: u8 = 1;

/// `OP_CHECKSETSIG` role 2: the set's cancel threshold.
pub const SET_ROLE_CANCEL: u8 = 2;

/// The size of one `OP_CHECKSETSIG` signature: header (31..=34) || r || s, low S.
pub const SET_SIG_SIZE: usize = 65;

/// BIP68/BIP112: the input's relative lock is disabled.
pub const SEQUENCE_LOCKTIME_DISABLE_FLAG: u32 = 1 << 31;

/// BIP68/BIP112: the relative lock is time-based (Ycash refuses it under
/// [`Flags::CHECKSEQUENCEVERIFY`]).
pub const SEQUENCE_LOCKTIME_TYPE_FLAG: u32 = 1 << 22;

/// BIP68/BIP112: the bits of the relative lock value.
pub const SEQUENCE_LOCKTIME_MASK: u32 = 0x0000_ffff;

/// The comparison of ycash6 `TransactionSignatureChecker::CheckSequence` (BIP112): true iff
/// the operand `sequence` is satisfied by an input whose `nSequence` is `tx_sequence`, in a
/// transaction of version `tx_version`. A transaction checker implements
/// [`SignatureChecker::check_sequence`] with it.
pub fn check_sequence(tx_version: u32, tx_sequence: u32, sequence: i64) -> bool {
    let tx_sequence = i64::from(tx_sequence);
    // Fail if the transaction's version number is not set high enough to trigger BIP 68 rules.
    if tx_version < 2 {
        return false;
    }
    // Sequence numbers with their most significant bit set are not consensus constrained.
    if tx_sequence & i64::from(SEQUENCE_LOCKTIME_DISABLE_FLAG) != 0 {
        return false;
    }
    // Mask off any bits that do not have consensus-enforced meaning before the comparisons.
    let mask = i64::from(SEQUENCE_LOCKTIME_TYPE_FLAG | SEQUENCE_LOCKTIME_MASK);
    let tx_masked = tx_sequence & mask;
    let masked = sequence & mask;
    let type_flag = i64::from(SEQUENCE_LOCKTIME_TYPE_FLAG);
    // Compare apples to apples: both height-based or both time-based.
    if !((tx_masked < type_flag && masked < type_flag)
        || (tx_masked >= type_flag && masked >= type_flag))
    {
        return false;
    }
    masked <= tx_masked
}

/// A signature checker that always fails. This is helpful in testing cases that don’t involve
/// `CHECK*SIG`.
pub struct NullSignatureChecker();

impl SignatureChecker for NullSignatureChecker {
    fn check_sig(
        &self,
        _script_sig: &signature::Decoded,
        _vch_pub_key: &[u8],
        _script_code: &script::Code,
    ) -> bool {
        false
    }

    fn check_lock_time(&self, _lock_time: i64) -> bool {
        false
    }
}

/// A signature checker that uses a callback to get necessary information about the transaction
/// involved.
#[cfg(feature = "signature-validation")]
#[derive(Copy, Clone)]
pub struct CallbackTransactionSignatureChecker<'a> {
    /// The callback to be used to calculate the sighash.
    pub sighash: SighashCalculator<'a>,
    /// This is stored as an `i64` instead of the `u32` used by transactions to avoid partial
    /// conversions when reading from the stack.
    pub lock_time: i64,
    /// Whether this is the final UTXO in the transaction.
    pub is_final: bool,
}

/// Treat a stack entry as a generalized boolean. Anything other than 0 and -0 (minimal encoding not
/// required) is treated as `true`.
pub(crate) fn cast_to_bool(vch: &[u8]) -> bool {
    for i in 0..vch.len() {
        if vch[i] != 0 {
            // Can be negative zero
            if i == vch.len() - 1 && vch[i] == 0x80 {
                return false;
            }
            return true;
        }
    }
    false
}

/// Script is a stack machine (like Forth) that evaluates a predicate returning a bool indicating
/// valid or not.  There are no loops.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stack<T>(Vec<T>);

// NB: This isn’t in `impl Stack`, because that requires us to specify type parameters, even though
//     this value doesn’t care about them.
/// The maximum number of elements allowed in the _combined_ stack and altstack.
pub(crate) const MAX_STACK_DEPTH: usize = 1000;

/// Wraps a Vec (or whatever underlying implementation we choose in a way that matches the C++ impl
/// and provides us some decent chaining)
impl<T> Stack<T> {
    /// Creates an empty stack.
    pub(crate) fn new() -> Self {
        Stack(vec![])
    }

    /// Fail if the Stack doesn’t contain at least `min` elements.
    pub(crate) fn check_len(&self, min: usize) -> Result<(), Error> {
        let len = self.0.len();
        if min <= len {
            Ok(())
        } else {
            Err(Error::InvalidStackOperation(Some((min - 1, len))))
        }
    }

    fn rindex(&self, i: usize) -> Result<usize, Error> {
        let len = self.0.len();
        if i < len {
            Ok(len - i - 1)
        } else {
            Err(Error::InvalidStackOperation(Some((i, len))))
        }
    }

    /// Gets an element from the stack without removing it., counting from the right. I.e.,
    /// `rget(0)` returns the top element.
    pub(crate) fn rget(&self, i: usize) -> Result<&T, Error> {
        let idx = self.rindex(i)?;
        self.0.get(idx).ok_or(Error::InvalidStackOperation(None))
    }

    /// Removes and returns the top element from the stack.
    pub(crate) fn pop(&mut self) -> Result<T, Error> {
        self.0
            .pop()
            .ok_or(Error::InvalidStackOperation(Some((0, self.0.len()))))
    }

    /// Adds a new element to the top of the stack.
    pub(crate) fn push(&mut self, value: T) {
        self.0.push(value)
    }

    /// Returns the number of elements in the stack.
    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns an iterator over the stack.
    fn iter(&self) -> Iter<'_, T> {
        self.0.iter()
    }

    /// Returns a mutable reference to the last element of the stack.
    pub(crate) fn last_mut(&mut self) -> Result<&mut T, Error> {
        let len = self.0.len();
        self.0
            .last_mut()
            .ok_or(Error::InvalidStackOperation(Some((0, len))))
    }

    /// Returns a reference to the last element of the stack.
    pub(crate) fn last(&self) -> Result<&T, Error> {
        self.0
            .last()
            .ok_or(Error::InvalidStackOperation(Some((0, self.0.len()))))
    }

    /// Removes an element from the stack, counting from the right.
    pub(crate) fn rremove(&mut self, start: usize) -> Result<T, Error> {
        self.rindex(start).map(|rstart| self.0.remove(rstart))
    }

    /// Inserts an element at the given index, counting from the right.
    pub(crate) fn rinsert(&mut self, i: usize, element: T) -> Result<(), Error> {
        let ri = self.rindex(i)?;
        self.0.insert(ri, element);
        Ok(())
    }

    // higher-level operations

    /// Perform a unary operation on the top stack element.
    pub(crate) fn unop(&mut self, op: impl FnOnce(T) -> Result<T, Error>) -> Result<(), Error> {
        self.pop().and_then(op).map(|res| self.push(res))
    }

    /// Call a binary function on the top two stack elements.
    pub(crate) fn binfn<R>(
        &mut self,
        op: impl FnOnce(T, T) -> Result<R, Error>,
    ) -> Result<R, Error> {
        let x2 = self.pop()?;
        let x1 = self.pop()?;
        op(x1, x2)
    }

    /// Perform a binary operation on the top two stack elements.
    pub(crate) fn binop(&mut self, op: impl FnOnce(T, T) -> Result<T, Error>) -> Result<(), Error> {
        self.binfn(op).map(|res| self.push(res))
    }
}

impl<T: Clone> Stack<T> {
    /// Returns the last element of the stack as well as the remainder of the stack.
    pub(crate) fn split_last(&self) -> Result<(&T, Stack<T>), Error> {
        self.0
            .split_last()
            .ok_or(Error::InvalidStackOperation(Some((0, self.0.len()))))
            .map(|(last, rem)| (last, Stack(rem.to_vec())))
    }

    /// Copies the element at `i` (from the right) onto the top of the stack.
    pub(crate) fn repush(&mut self, i: usize) -> Result<(), Error> {
        self.rget(i).cloned().map(|v| self.push(v))
    }

    /// Moves the element at `i` (from the right) onto the top of the stack.
    pub(crate) fn move_to_top(&mut self, i: usize) -> Result<(), Error> {
        self.rremove(i).map(|v| self.push(v.clone()))
    }
}

/// This holds the various components that need to be carried between individual opcode evaluations.
///
/// **NB**: This intentionally doesn’t provide a `Clone` impl, to prevent resuse of old state.
#[derive(Debug, PartialEq, Eq)]
pub struct State {
    /// The primary evaluation stack.
    pub(crate) stack: Stack<Vec<u8>>,
    /// A secondary stack that elements can be moved to temporarily.
    pub(crate) altstack: Stack<Vec<u8>>,
    /// We keep track of how many operations have executed so far to prevent expensive-to-verify
    /// scripts
    op_count: u8,
    /// This keeps track of the conditional flags at each nesting level during execution. If we're
    /// in a branch of execution where *any* of these conditionals are false, we ignore opcodes
    /// unless those opcodes direct control flow (OP_IF, OP_ELSE, etc.).
    pub(crate) vexec: Stack<bool>,
    /// Executed `OP_CHECKSETSIG`s in this evaluation (Ycash: at most one).
    pub(crate) set_sig_count: u8,
    /// Executed `OP_CHECKPQSIG`s in this evaluation (Ycash: at most one).
    pub(crate) pq_sig_count: u8,
}

impl State {
    /// Creates a state with an initial stack, but other components empty.
    pub(crate) fn initial(stack: Stack<Vec<u8>>) -> Self {
        Self::from_parts(stack, Stack::new(), 0, Stack::new())
    }

    /// Bumps the current `op_count` by one and errors if it exceeds `MAX_OP_COUNT`.
    pub(crate) fn increment_op_count(&mut self, by: u8) -> Result<(), Error> {
        self.op_count += by;
        if self.op_count <= MAX_OP_COUNT {
            Ok(())
        } else {
            Err(Error::OpCount)
        }
    }

    /// Create an arbitrary state.
    pub(crate) fn from_parts(
        stack: Stack<Vec<u8>>,
        altstack: Stack<Vec<u8>>,
        op_count: u8,
        vexec: Stack<bool>,
    ) -> Self {
        State {
            stack,
            altstack,
            op_count,
            vexec,
            set_sig_count: 0,
            pq_sig_count: 0,
        }
    }

    /// Extract the altstack from the state.
    pub(crate) fn altstack(&self) -> &Stack<Vec<u8>> {
        &self.altstack
    }
}

/// Are we in an executing branch of the script?
pub(crate) fn should_exec(vexec: &Stack<bool>) -> bool {
    vexec.iter().all(|value| *value)
}

/// All signature hashes are 32 bytes, since they are either:
/// - a SHA-256 output (for v1 or v2 transactions).
/// - a BLAKE2b-256 output (for v3 and above transactions).
pub(crate) const SIGHASH_SIZE: usize = 32;

/// A function which is called to obtain the sighash.
///    - script_code: the scriptCode being validated. Note that this not always
///      matches script_sig, i.e. for P2SH.
///    - hash_type: the hash type being used.
///
/// The `extern "C"` function that calls this doesn’t give much opportunity for rich failure
/// reporting, but returning `None` indicates _some_ failure to produce the desired hash.
pub type SighashCalculator<'a> =
    &'a dyn Fn(&script::Code, &signature::HashType) -> Option<[u8; SIGHASH_SIZE]>;

#[cfg(feature = "signature-validation")]
impl SignatureChecker for CallbackTransactionSignatureChecker<'_> {
    fn check_sig(
        &self,
        sig: &signature::Decoded,
        vch_pub_key: &[u8],
        script_code: &script::Code,
    ) -> bool {
        let pubkey = PubKey(vch_pub_key);

        pubkey.is_valid()
            && (self.sighash)(script_code, sig.sighash_type())
                .map(|sighash| pubkey.verify(&sighash, sig.sig()))
                .unwrap_or(false)
    }

    fn check_lock_time(&self, lock_time: i64) -> bool {
        // There are two kinds of nLockTime: lock-by-blockheight
        // and lock-by-blocktime, distinguished by whether
        // nLockTime < LOCKTIME_THRESHOLD.
        //
        // We want to compare apples to apples, so fail the script
        // unless the type of nLockTime being tested is the same as
        // the nLockTime in the transaction.
        if self.lock_time < LOCKTIME_THRESHOLD && lock_time >= LOCKTIME_THRESHOLD
            || self.lock_time >= LOCKTIME_THRESHOLD && lock_time < LOCKTIME_THRESHOLD
            // Now that we know we're comparing apples-to-apples, the
            // comparison is a simple numeric one.
            || lock_time > self.lock_time
        {
            false
            // Finally the nLockTime feature can be disabled and thus
            // CHECKLOCKTIMEVERIFY bypassed if every txin has been
            // finalized by setting nSequence to maxint. The
            // transaction would be allowed into the blockchain, making
            // the opcode ineffective.
            //
            // Testing if this vin is not final is sufficient to
            // prevent this condition. Alternatively we could test all
            // inputs, but testing just this input minimizes the data
            // required to prove correct CHECKLOCKTIMEVERIFY execution.
        } else {
            !self.is_final
        }
    }
}
