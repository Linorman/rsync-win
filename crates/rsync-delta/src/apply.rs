use thiserror::Error;

use crate::matcher::DeltaToken;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ApplyError {
    #[error("copy token references bytes outside the basis file: offset {offset}, len {len}, basis len {basis_len}")]
    CopyOutOfBounds {
        offset: usize,
        len: usize,
        basis_len: usize,
    },
}

pub fn apply_delta(basis: &[u8], tokens: &[DeltaToken]) -> Result<Vec<u8>, ApplyError> {
    let mut output = Vec::new();

    for token in tokens {
        match token {
            DeltaToken::Literal(bytes) => output.extend_from_slice(bytes),
            DeltaToken::Copy { offset, len } => {
                let end = offset
                    .checked_add(*len)
                    .ok_or(ApplyError::CopyOutOfBounds {
                        offset: *offset,
                        len: *len,
                        basis_len: basis.len(),
                    })?;

                let Some(bytes) = basis.get(*offset..end) else {
                    return Err(ApplyError::CopyOutOfBounds {
                        offset: *offset,
                        len: *len,
                        basis_len: basis.len(),
                    });
                };

                output.extend_from_slice(bytes);
            }
        }
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn applies_literal_and_copy_tokens() {
        let tokens = vec![
            DeltaToken::Copy { offset: 0, len: 3 },
            DeltaToken::Literal(b"XY".to_vec()),
            DeltaToken::Copy { offset: 3, len: 3 },
        ];

        assert_eq!(apply_delta(b"abcdef", &tokens).unwrap(), b"abcXYdef");
    }

    #[test]
    fn rejects_out_of_bounds_copy() {
        let tokens = vec![DeltaToken::Copy { offset: 2, len: 5 }];
        let err = apply_delta(b"abc", &tokens).unwrap_err();
        assert_eq!(
            err,
            ApplyError::CopyOutOfBounds {
                offset: 2,
                len: 5,
                basis_len: 3
            }
        );
    }
}
