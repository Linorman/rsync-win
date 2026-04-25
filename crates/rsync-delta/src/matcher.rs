use std::collections::{HashMap, HashSet};

use crate::rollsum::rolling_checksum;
use crate::signature::{BlockSignature, DeterministicStrongChecksum, StrongChecksum};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeltaToken {
    Literal(Vec<u8>),
    Copy { offset: usize, len: usize },
}

pub fn generate_test_delta(signatures: &[BlockSignature], target: &[u8]) -> Vec<DeltaToken> {
    generate_delta_with(signatures, target, &DeterministicStrongChecksum)
}

pub fn generate_delta_with<S: StrongChecksum>(
    signatures: &[BlockSignature],
    target: &[u8],
    strong_checksum: &S,
) -> Vec<DeltaToken> {
    if target.is_empty() {
        return Vec::new();
    }

    if signatures.is_empty() {
        return vec![DeltaToken::Literal(target.to_vec())];
    }

    let index = SignatureIndex::new(signatures);
    let mut tokens = Vec::new();
    let mut literal = Vec::new();
    let mut pos = 0;

    while pos < target.len() {
        if let Some(signature) = index.find_match(target, pos, strong_checksum) {
            flush_literal(&mut tokens, &mut literal);
            tokens.push(DeltaToken::Copy {
                offset: signature.offset,
                len: signature.len,
            });
            pos += signature.len;
        } else {
            literal.push(target[pos]);
            pos += 1;
        }
    }

    flush_literal(&mut tokens, &mut literal);
    tokens
}

struct SignatureIndex<'a> {
    signatures: &'a [BlockSignature],
    lengths_desc: Vec<usize>,
    by_len_and_weak: HashMap<(usize, u32), Vec<usize>>,
}

impl<'a> SignatureIndex<'a> {
    fn new(signatures: &'a [BlockSignature]) -> Self {
        let mut lengths = HashSet::new();
        let mut by_len_and_weak: HashMap<(usize, u32), Vec<usize>> = HashMap::new();

        for (index, signature) in signatures.iter().enumerate() {
            lengths.insert(signature.len);
            by_len_and_weak
                .entry((signature.len, signature.weak))
                .or_default()
                .push(index);
        }

        let mut lengths_desc: Vec<_> = lengths.into_iter().collect();
        lengths_desc.sort_unstable_by(|a, b| b.cmp(a));

        Self {
            signatures,
            lengths_desc,
            by_len_and_weak,
        }
    }

    fn find_match<S: StrongChecksum>(
        &self,
        target: &[u8],
        pos: usize,
        strong_checksum: &S,
    ) -> Option<&'a BlockSignature> {
        for len in &self.lengths_desc {
            if target.len() - pos < *len {
                continue;
            }

            let candidate = &target[pos..pos + *len];
            let weak = rolling_checksum(candidate);
            let Some(signature_indexes) = self.by_len_and_weak.get(&(*len, weak)) else {
                continue;
            };

            let strong = strong_checksum.digest(candidate);
            for signature_index in signature_indexes {
                let signature = &self.signatures[*signature_index];
                if signature.strong == strong {
                    return Some(signature);
                }
            }
        }

        None
    }
}

fn flush_literal(tokens: &mut Vec<DeltaToken>, literal: &mut Vec<u8>) {
    if literal.is_empty() {
        return;
    }

    tokens.push(DeltaToken::Literal(std::mem::take(literal)));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apply::apply_delta;
    use crate::signature::generate_test_signatures;

    fn assert_round_trip(basis: &[u8], target: &[u8], block_size: usize) -> Vec<DeltaToken> {
        let signatures = generate_test_signatures(basis, block_size).unwrap();
        let tokens = generate_test_delta(&signatures, target);
        let reconstructed = apply_delta(basis, &tokens).unwrap();
        assert_eq!(reconstructed, target);
        tokens
    }

    #[test]
    fn emits_copy_tokens_for_identical_content() {
        let tokens = assert_round_trip(b"abcdef", b"abcdef", 2);
        assert!(tokens
            .iter()
            .all(|token| matches!(token, DeltaToken::Copy { .. })));
    }

    #[test]
    fn reconstructs_inserted_content() {
        assert_round_trip(b"abcdef", b"abXYcdef", 2);
    }

    #[test]
    fn reconstructs_deleted_content() {
        assert_round_trip(b"abcdef", b"abef", 2);
    }

    #[test]
    fn reconstructs_moved_blocks() {
        let tokens = assert_round_trip(b"abcdef", b"cdefab", 2);
        assert_eq!(
            tokens,
            vec![
                DeltaToken::Copy { offset: 2, len: 2 },
                DeltaToken::Copy { offset: 4, len: 2 },
                DeltaToken::Copy { offset: 0, len: 2 },
            ]
        );
    }

    #[test]
    fn reconstructs_empty_file_cases() {
        assert_round_trip(b"", b"", 4);
        assert_round_trip(b"", b"abc", 4);
        assert_round_trip(b"abc", b"", 4);
    }

    #[test]
    fn reconstructs_shifted_content() {
        assert_round_trip(b"abcdef", b"xabcdef", 3);
    }
}
