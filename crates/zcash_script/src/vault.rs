//! The Ycash vault network upgrade's script extensions.
//!
//! The behavioural reference is the C++ interpreter of the Ycash 6.20.0 node line
//! (`ycash6/src/script/interpreter.cpp`, `script.h`, `crypto/pq/scheme.h` on `upgrade/vault`):
//!
//! - `OP_CHECKSEQUENCEVERIFY` (0xb2, `OP_NOP3`) under [`Flags::CHECKSEQUENCEVERIFY`] (bit 10),
//!   BIP112 with height-based locks only;
//! - `OP_CHECKSETSIG` (0xc0) and `OP_CHECKSETDORMANT` (0xc1) under [`Flags::Vault`] (bit 11);
//! - `OP_CHECKPQSIG` (0xc2) under [`Flags::Vault`], scheme 0x02 (Falcon) only with
//!   [`Flags::PqFalcon`] (bit 12).
//!
//! Without the flags every byte here behaves exactly as upstream: 0xb2 is `OP_NOP3` and
//! 0xc0–0xc2 are [`Bad::Unknown`] opcodes, decoded as such in every build (so parsing, `asm` and
//! upstream's test vectors are unchanged). The flags decide only how they evaluate. 0xbb–0xbf are
//! never assigned: DigiByte's opcodes there depend on Tapscript, which Ycash does not have.
//!
//! [`Flags::CHECKSEQUENCEVERIFY`]: interpreter::Flags::CHECKSEQUENCEVERIFY
//! [`Flags::Vault`]: interpreter::Flags::Vault
//! [`Flags::PqFalcon`]: interpreter::Flags::PqFalcon

use alloc::vec::Vec;

use sha2::{Digest, Sha256};

use crate::{
    interpreter::{self, Error, Flags, SET_SIG_SIZE, SignatureChecker, State},
    num,
    opcode::{Bad, PossiblyBad},
    script, signature,
};

/// The post-quantum scheme registry the interpreter needs (ycash6 `crypto/pq/scheme.h`). The
/// verification itself is the checker's ([`SignatureChecker::check_pq_sig`]).
pub mod pq {
    use super::{Digest, Sha256};

    /// SLH-DSA-SHA2-128s (FIPS 205, pure, empty context). Active with the vault upgrade.
    pub const SCHEME_SLH_DSA_SHA2_128S: u8 = 0x01;
    /// FN-DSA-512 (Falcon-512, padded). Active only with `Flags::PqFalcon`.
    pub const SCHEME_FN_DSA_512: u8 = 0x02;
    /// The size of a key hash, `SHA256(scheme || pk)`.
    pub const KEYHASH_SIZE: usize = 32;
    /// The largest chunk of a key or signature (`MAX_SCRIPT_ELEMENT_SIZE`).
    pub const MAX_CHUNK: usize = 520;
    /// The policy sigops of one `OP_CHECKPQSIG`.
    pub const SIGOP_COST: u32 = 20;

    /// The public key size of `scheme`, 0 for an unknown scheme.
    pub const fn pub_key_size(scheme: u8) -> usize {
        match scheme {
            SCHEME_SLH_DSA_SHA2_128S => 32,
            SCHEME_FN_DSA_512 => 897,
            _ => 0,
        }
    }

    /// The signature size of `scheme`, without the trailing hash-type byte; 0 for an unknown
    /// scheme.
    pub const fn sig_size(scheme: u8) -> usize {
        match scheme {
            SCHEME_SLH_DSA_SHA2_128S => 7856,
            SCHEME_FN_DSA_512 => 666,
            _ => 0,
        }
    }

    /// True for a registered scheme (activation is the caller's flag).
    pub const fn is_known_scheme(scheme: u8) -> bool {
        matches!(scheme, SCHEME_SLH_DSA_SHA2_128S | SCHEME_FN_DSA_512)
    }

    /// `SHA256(scheme || pk)`.
    pub fn key_hash(scheme: u8, pk: &[u8]) -> [u8; KEYHASH_SIZE] {
        let mut h = Sha256::new();
        h.update([scheme]);
        h.update(pk);
        h.finalize().into()
    }
}

/// The opcodes the vault upgrade assigns above `OP_NOP10`. They decode as [`Bad::Unknown`] and
/// evaluate as below only under [`interpreter::Flags::Vault`].
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[allow(non_camel_case_types)]
#[repr(u8)]
pub enum VaultOp {
    /// `(sig_k .. sig_1 setId role -- 1)`: `k` set signatures, `k` from the checker.
    OP_CHECKSETSIG = 0xc0,
    /// `(setId -- bool)`: whether the set is released.
    OP_CHECKSETDORMANT = 0xc1,
    /// `(sig_1 .. sig_s s pk_1 .. pk_p p keyHash schemeId -- bool)`: a post-quantum signature.
    OP_CHECKPQSIG = 0xc2,
}

impl VaultOp {
    /// Decodes a vault opcode from its byte.
    pub const fn decode(b: u8) -> Option<Self> {
        match b {
            0xc0 => Some(Self::OP_CHECKSETSIG),
            0xc1 => Some(Self::OP_CHECKSETDORMANT),
            0xc2 => Some(Self::OP_CHECKPQSIG),
            _ => None,
        }
    }

    /// The opcode's byte.
    pub const fn encode(self) -> u8 {
        self as u8
    }

    /// The opcode's name, as ycash6's `GetOpName`.
    pub const fn name(self) -> &'static str {
        match self {
            Self::OP_CHECKSETSIG => "OP_CHECKSETSIG",
            Self::OP_CHECKSETDORMANT => "OP_CHECKSETDORMANT",
            Self::OP_CHECKPQSIG => "OP_CHECKPQSIG",
        }
    }
}

impl From<VaultOp> for PossiblyBad {
    /// The opcode as it parses from a script, for authoring scripts that contain it.
    fn from(value: VaultOp) -> Self {
        PossiblyBad::Bad(Bad::Unknown(value.encode()))
    }
}

/// A set signature (ycash6 `IsCompactSetSignature`): 65 bytes, header || r || s, the header
/// 31..=34 (compressed, recoverable), and s at most half the curve order (low S).
pub fn is_compact_set_signature(sig: &[u8]) -> bool {
    const HALF_ORDER: [u8; 32] = [
        0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D, 0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B,
        0x20, 0xA0,
    ];
    sig.len() == SET_SIG_SIZE
        && sig.first().is_some_and(|header| (31..=34).contains(header))
        // s is bytes 33..65, big-endian
        && sig.get(33..).is_some_and(|s| s <= &HALF_ORDER[..])
}

/// The policy sigops of `OP_CHECKPQSIG` in one script (ycash6 `GetPQSigOpCount(const CScript&)`):
/// [`pq::SIGOP_COST`] per 0xc2 opcode, not inside pushes. Like zcashd's `GetOp` walk it stops
/// only at a truncated push. The consensus sigop count ([`script::Code::sig_op_count`]) does not
/// see 0xc2, as in ycash6.
pub fn pq_sig_op_count(code: &script::Code) -> u32 {
    let mut n: u32 = 0;
    for item in code.parse() {
        match item {
            Ok(PossiblyBad::Bad(Bad::Unknown(b))) if b == VaultOp::OP_CHECKPQSIG.encode() => {
                n = n.saturating_add(pq::SIGOP_COST)
            }
            Ok(_) | Err(crate::opcode::Error::Disabled(_) | crate::opcode::Error::PushSize(_)) => {}
            Err(crate::opcode::Error::Read { .. }) => break,
        }
    }
    n
}

fn cast_from_bool(b: bool) -> Vec<u8> {
    if b { vec![1] } else { vec![] }
}

/// `OP_CHECKSEQUENCEVERIFY` with [`interpreter::Flags::CHECKSEQUENCEVERIFY`] set:
/// `(seq -- seq)`.
pub(crate) fn eval_check_sequence_verify(
    require_minimal: bool,
    stack: &interpreter::Stack<Vec<u8>>,
    checker: &dyn SignatureChecker,
) -> Result<(), Error> {
    // nSequence, like nLockTime, is a 32-bit unsigned field, so 5-byte operands are accepted.
    let sequence = stack
        .rget(0)
        .and_then(|v| num::parse(v, require_minimal, Some(5)).map_err(Error::Num))?;
    if sequence < 0 {
        return Err(Error::NegativeLockTime);
    }
    // An operand with the disable flag is a NOP (BIP112's extension point).
    if sequence & i64::from(interpreter::SEQUENCE_LOCKTIME_DISABLE_FLAG) != 0 {
        return Ok(());
    }
    // Ycash enforces height-based relative locks only: an operand with the type flag fails.
    if sequence & i64::from(interpreter::SEQUENCE_LOCKTIME_TYPE_FLAG) != 0 {
        return Err(Error::UnsatisfiedLockTime);
    }
    if checker.check_sequence(sequence) {
        Ok(())
    } else {
        Err(Error::UnsatisfiedLockTime)
    }
}

/// Evaluates a vault opcode, which the caller has decoded under [`interpreter::Flags::Vault`].
/// Mirrors [`crate::Opcode::eval`] for an operation: it counts towards the operation limit, runs
/// only on an executing branch, and the stack-depth limit is checked after it.
pub(crate) fn eval(
    op: VaultOp,
    flags: Flags,
    script: &script::Code,
    checker: &dyn SignatureChecker,
    mut state: State,
) -> Result<State, Error> {
    state.increment_op_count(1)?;
    if interpreter::should_exec(&state.vexec) {
        match op {
            VaultOp::OP_CHECKSETSIG => eval_check_set_sig(script, checker, &mut state)?,
            VaultOp::OP_CHECKSETDORMANT => eval_check_set_dormant(checker, &mut state)?,
            VaultOp::OP_CHECKPQSIG => eval_check_pq_sig(flags, script, checker, &mut state)?,
        }
    }
    if state.stack.len() + state.altstack().len() > interpreter::MAX_STACK_DEPTH {
        Err(Error::StackSize(None))
    } else {
        Ok(state)
    }
}

fn set_id_of(v: &[u8]) -> Option<[u8; 32]> {
    <[u8; 32]>::try_from(v).ok()
}

fn eval_check_set_sig(
    script: &script::Code,
    checker: &dyn SignatureChecker,
    state: &mut State,
) -> Result<(), Error> {
    // At most one executed OP_CHECKSETSIG per script evaluation.
    state.set_sig_count = state.set_sig_count.saturating_add(1);
    if state.set_sig_count > 1 {
        return Err(Error::SetSigCount);
    }
    let stack = &mut state.stack;
    stack.check_len(2)?;
    // The templates push <setId> then <role> (OP_1 / OP_2), so role is on top.
    let role = match stack.rget(0)?.as_slice() {
        [r @ (interpreter::SET_ROLE_UNLOCK | interpreter::SET_ROLE_CANCEL)] => Some(*r),
        _ => None,
    };
    let set_id = set_id_of(stack.rget(1)?);
    let (Some(set_id), Some(role)) = (set_id, role) else {
        return Err(Error::SetSig);
    };
    stack.pop()?;
    stack.pop()?;

    let k = checker
        .set_threshold(&set_id, role)
        .and_then(|k| usize::try_from(k).ok())
        .filter(|k| 1 <= *k && *k <= stack.len())
        .ok_or(Error::SetSig)?;

    let mut sigs: Vec<[u8; SET_SIG_SIZE]> = Vec::with_capacity(k);
    for _ in 0..k {
        let sig = stack.pop()?;
        if !is_compact_set_signature(&sig) {
            return Err(Error::SetSig);
        }
        sigs.push(<[u8; SET_SIG_SIZE]>::try_from(sig.as_slice()).map_err(|_| Error::SetSig)?);
    }
    // hand them over in push order, sig_1 first
    sigs.reverse();

    if !checker.check_set_sigs(&set_id, role, &sigs, script) {
        return Err(Error::SetSig);
    }
    stack.push(cast_from_bool(true));
    Ok(())
}

fn eval_check_set_dormant(checker: &dyn SignatureChecker, state: &mut State) -> Result<(), Error> {
    let stack = &mut state.stack;
    stack.check_len(1)?;
    let set_id = set_id_of(stack.rget(0)?).ok_or(Error::SetSig)?;
    stack.pop()?;
    stack.push(cast_from_bool(checker.is_set_released(&set_id)));
    Ok(())
}

fn eval_check_pq_sig(
    flags: Flags,
    script: &script::Code,
    checker: &dyn SignatureChecker,
    state: &mut State,
) -> Result<(), Error> {
    // At most one executed OP_CHECKPQSIG per script evaluation.
    state.pq_sig_count = state.pq_sig_count.saturating_add(1);
    if state.pq_sig_count > 1 {
        return Err(Error::PqCount);
    }
    let stack = &mut state.stack;

    // 1. A registered scheme (0x02 only with PqFalcon) and a 32-byte key hash. Consensus requires
    //    one-byte elements; push minimality is MinimalData's (policy).
    stack.check_len(2)?;
    let scheme = match stack.rget(0)?.as_slice() {
        [s] if pq::is_known_scheme(*s) => *s,
        _ => return Err(Error::PqScheme),
    };
    if scheme == pq::SCHEME_FN_DSA_512 && !flags.contains(Flags::PqFalcon) {
        return Err(Error::PqScheme);
    }
    let key_hash: [u8; pq::KEYHASH_SIZE] =
        <[u8; pq::KEYHASH_SIZE]>::try_from(stack.rget(1)?.as_slice()).map_err(|_| Error::PqSize)?;

    // 2. The counts p (the key's chunks) and s (the signature's, which carry the hash-type byte):
    //    each a one-byte element 1..=ceil(len/520), with that many items under it. `i` counts
    //    items from the top, 1-based, as ycash6's `stacktop(-i)`.
    let lens = [pq::pub_key_size(scheme), pq::sig_size(scheme) + 1];
    let mut n_chunks = [0usize; 2];
    let mut i_count = [0usize; 2];
    let mut i: usize = 3;
    for part in 0..2 {
        stack.check_len(i)?;
        let max_chunks = lens[part].div_ceil(pq::MAX_CHUNK);
        let n = match stack.rget(i - 1)?.as_slice() {
            [c] if 1 <= usize::from(*c) && usize::from(*c) <= max_chunks => usize::from(*c),
            _ => return Err(Error::PqChunk),
        };
        n_chunks[part] = n;
        i_count[part] = i;
        i += n + 1;
        stack.check_len(i - 1)?;
    }

    // 3. Canonical chunking: every chunk but the last is exactly 520 bytes. Chunk k (1 = first,
    //    pushed first, deepest) is stacktop(-(iCount + n - k + 1)), i.e. rget(iCount + n - k).
    for part in 0..2 {
        let n = n_chunks[part];
        for k in 1..=n {
            let len = stack.rget(i_count[part] + n - k)?.len();
            if (k < n && len != pq::MAX_CHUNK) || len > pq::MAX_CHUNK {
                return Err(Error::PqChunk);
            }
        }
    }

    // 4. Exact sizes: the reassembled key and signature are the registry's lengths.
    let mut parts: [Vec<u8>; 2] = [Vec::new(), Vec::new()];
    for part in 0..2 {
        let n = n_chunks[part];
        for k in 1..=n {
            parts[part].extend_from_slice(stack.rget(i_count[part] + n - k)?);
        }
        if parts[part].len() != lens[part] {
            return Err(Error::PqSize);
        }
    }
    let [pub_key, sig] = parts;

    // 5. The hash type is the signature's last byte; under StrictEnc it must be defined, as for
    //    OP_CHECKSIG (the DER and LowS checks are ECDSA's and do not apply).
    let (hash_type_byte, bare_sig) = sig.split_last().ok_or(Error::PqSize)?;
    let hash_type_bits = i32::from(*hash_type_byte);
    if flags.contains(Flags::StrictEnc) {
        signature::HashType::from_bits(hash_type_bits, true)
            .map_err(|e| Error::SignatureEncoding(signature::Error::from(e)))?;
    }

    // 6, 7. A key that does not hash to keyHash, or a signature that does not verify, pushes
    //    false (OP_CHECKSIG's failure semantics; Ycash has no NULLFAIL flag).
    let success = pq::key_hash(scheme, &pub_key) == key_hash
        && signature::HashType::from_bits(hash_type_bits, false).is_ok_and(|hash_type| {
            checker.check_pq_sig(scheme, bare_sig, &hash_type, &pub_key, script)
        });

    // Clean up the stack: the i - 1 arguments.
    for _ in 1..i {
        stack.pop()?;
    }
    stack.push(cast_from_bool(success));
    Ok(())
}

#[cfg(test)]
mod tests;
