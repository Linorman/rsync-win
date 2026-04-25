use std::io::{self, ErrorKind, Read, Write};

pub const RSYNC_INDEX_DONE: i32 = -1;
pub const RSYNC_INDEX_FLIST_EOF: i32 = -2;
pub const RSYNC_INDEX_FLIST_OFFSET: i32 = -101;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RsyncIndexState {
    prev_positive: i32,
    prev_negative: i32,
}

impl Default for RsyncIndexState {
    fn default() -> Self {
        Self {
            prev_positive: -1,
            prev_negative: 1,
        }
    }
}

pub fn read_u8<R: Read>(reader: &mut R) -> io::Result<u8> {
    let mut buf = [0_u8; 1];
    reader.read_exact(&mut buf)?;
    Ok(buf[0])
}

pub fn write_u8<W: Write>(writer: &mut W, value: u8) -> io::Result<()> {
    writer.write_all(&[value])
}

pub fn read_u16_le<R: Read>(reader: &mut R) -> io::Result<u16> {
    let mut buf = [0_u8; 2];
    reader.read_exact(&mut buf)?;
    Ok(u16::from_le_bytes(buf))
}

pub fn write_u16_le<W: Write>(writer: &mut W, value: u16) -> io::Result<()> {
    writer.write_all(&value.to_le_bytes())
}

pub fn read_i32_le<R: Read>(reader: &mut R) -> io::Result<i32> {
    let mut buf = [0_u8; 4];
    reader.read_exact(&mut buf)?;
    Ok(i32::from_le_bytes(buf))
}

pub fn write_i32_le<W: Write>(writer: &mut W, value: i32) -> io::Result<()> {
    writer.write_all(&value.to_le_bytes())
}

pub fn read_u32_le<R: Read>(reader: &mut R) -> io::Result<u32> {
    let mut buf = [0_u8; 4];
    reader.read_exact(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

pub fn write_u32_le<W: Write>(writer: &mut W, value: u32) -> io::Result<()> {
    writer.write_all(&value.to_le_bytes())
}

pub fn read_varint<R: Read>(reader: &mut R) -> io::Result<u32> {
    let first = read_u8(reader)?;
    let extra = varint_extra_bytes(first);
    if extra > 4 {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "rsync varint exceeds u32 width",
        ));
    }

    let mut bytes = [0_u8; 5];
    if extra == 0 {
        bytes[0] = first;
    } else {
        reader.read_exact(&mut bytes[..extra])?;
        let bit = 1_u8 << (8 - extra);
        bytes[extra] = first & (bit - 1);
    }

    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

pub fn write_varint<W: Write>(writer: &mut W, value: u32) -> io::Result<()> {
    if value > i32::MAX as u32 {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "rsync varint value exceeds non-negative i32 range",
        ));
    }

    let mut bytes = [0_u8; 5];
    bytes[1..].copy_from_slice(&value.to_le_bytes());

    let mut count = 4_usize;
    while count > 1 && bytes[count] == 0 {
        count -= 1;
    }

    let bit = 1_u8 << (7 - count + 1);
    if bytes[count] >= bit {
        count += 1;
        bytes[0] = !(bit - 1);
    } else if count > 1 {
        bytes[0] = bytes[count] | !(bit * 2 - 1);
    } else {
        bytes[0] = bytes[1];
    }

    writer.write_all(&bytes[..count])
}

pub fn read_varlong<R: Read>(reader: &mut R, min_bytes: usize) -> io::Result<u64> {
    if !(1..=8).contains(&min_bytes) {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "rsync varlong min_bytes must be in 1..=8",
        ));
    }

    let mut prefix = vec![0_u8; min_bytes];
    reader.read_exact(&mut prefix)?;
    let extra = varint_extra_bytes(prefix[0]);
    if min_bytes + extra > 8 {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "rsync varlong exceeds u64 width",
        ));
    }

    let mut bytes = [0_u8; 8];
    bytes[..min_bytes - 1].copy_from_slice(&prefix[1..]);
    if extra == 0 {
        bytes[min_bytes - 1] = prefix[0];
    } else {
        reader.read_exact(&mut bytes[min_bytes - 1..min_bytes - 1 + extra])?;
        let bit = 1_u8 << (8 - extra);
        bytes[min_bytes + extra - 1] = prefix[0] & (bit - 1);
    }

    Ok(u64::from_le_bytes(bytes))
}

pub fn write_varlong<W: Write>(writer: &mut W, value: u64, min_bytes: usize) -> io::Result<()> {
    if !(1..=8).contains(&min_bytes) {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "rsync varlong min_bytes must be in 1..=8",
        ));
    }

    let mut bytes = [0_u8; 9];
    bytes[1..].copy_from_slice(&value.to_le_bytes());

    let mut count = 8_usize;
    while count > min_bytes && bytes[count] == 0 {
        count -= 1;
    }

    let bit = 1_u8 << (7 - count + min_bytes);
    if bytes[count] >= bit {
        count += 1;
        bytes[0] = !(bit - 1);
    } else if count > min_bytes {
        bytes[0] = bytes[count] | !(bit * 2 - 1);
    } else {
        bytes[0] = bytes[count];
    }

    writer.write_all(&bytes[..count])
}

pub fn read_rsync_index<R: Read>(reader: &mut R, state: &mut RsyncIndexState) -> io::Result<i32> {
    let mut byte = read_u8(reader)?;
    let (negative, prev) = if byte == 0xff {
        byte = read_u8(reader)?;
        (true, &mut state.prev_negative)
    } else if byte == 0 {
        return Ok(RSYNC_INDEX_DONE);
    } else {
        (false, &mut state.prev_positive)
    };

    let number = if byte == 0xfe {
        let high_or_diff = read_u8(reader)?;
        let low_or_absolute = read_u8(reader)?;
        if high_or_diff & 0x80 != 0 {
            let mut bytes = [0_u8; 4];
            bytes[3] = high_or_diff & !0x80;
            bytes[0] = low_or_absolute;
            reader.read_exact(&mut bytes[1..3])?;
            i32::from_le_bytes(bytes)
        } else {
            let diff = ((high_or_diff as i32) << 8) + low_or_absolute as i32;
            prev.checked_add(diff).ok_or_else(|| {
                io::Error::new(ErrorKind::InvalidData, "rsync index delta overflow")
            })?
        }
    } else {
        prev.checked_add(byte as i32)
            .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "rsync index delta overflow"))?
    };

    *prev = number;
    if negative {
        number
            .checked_neg()
            .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "rsync negative index overflow"))
    } else {
        Ok(number)
    }
}

pub fn write_rsync_index<W: Write>(
    writer: &mut W,
    state: &mut RsyncIndexState,
    index: i32,
) -> io::Result<()> {
    let (number, diff, negative) = if index >= 0 {
        let diff = index
            .checked_sub(state.prev_positive)
            .ok_or_else(|| io::Error::new(ErrorKind::InvalidInput, "rsync index underflow"))?;
        state.prev_positive = index;
        (index, diff, false)
    } else if index == RSYNC_INDEX_DONE {
        write_u8(writer, 0)?;
        return Ok(());
    } else {
        let number = index
            .checked_neg()
            .ok_or_else(|| io::Error::new(ErrorKind::InvalidInput, "rsync index overflow"))?;
        let diff = number
            .checked_sub(state.prev_negative)
            .ok_or_else(|| io::Error::new(ErrorKind::InvalidInput, "rsync index underflow"))?;
        state.prev_negative = number;
        (number, diff, true)
    };

    if negative {
        write_u8(writer, 0xff)?;
    }
    if diff < 0xfe && diff > 0 {
        write_u8(writer, diff as u8)
    } else if !(0..=0x7fff).contains(&diff) {
        let bytes = number.to_le_bytes();
        write_u8(writer, 0xfe)?;
        write_u8(writer, bytes[3] | 0x80)?;
        write_u8(writer, bytes[0])?;
        write_u8(writer, bytes[1])?;
        write_u8(writer, bytes[2])
    } else {
        write_u8(writer, 0xfe)?;
        write_u8(writer, (diff >> 8) as u8)?;
        write_u8(writer, diff as u8)
    }
}

pub fn read_i64_le<R: Read>(reader: &mut R) -> io::Result<i64> {
    let mut buf = [0_u8; 8];
    reader.read_exact(&mut buf)?;
    Ok(i64::from_le_bytes(buf))
}

pub fn write_i64_le<W: Write>(writer: &mut W, value: i64) -> io::Result<()> {
    writer.write_all(&value.to_le_bytes())
}

pub fn read_bytes_with_u32_len<R: Read>(reader: &mut R, max_len: usize) -> io::Result<Vec<u8>> {
    let len = read_u32_le(reader)? as usize;
    if len > max_len {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            format!("wire byte string length {len} exceeds limit {max_len}"),
        ));
    }

    let mut bytes = vec![0_u8; len];
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}

pub fn write_bytes_with_u32_len<W: Write>(writer: &mut W, bytes: &[u8]) -> io::Result<()> {
    let len = u32::try_from(bytes.len()).map_err(|_| {
        io::Error::new(
            ErrorKind::InvalidInput,
            "wire byte string is too large for a u32 length",
        )
    })?;
    write_u32_le(writer, len)?;
    writer.write_all(bytes)
}

pub fn read_vstring<R: Read>(reader: &mut R, max_len: usize) -> io::Result<Vec<u8>> {
    let mut len = read_u8(reader)? as usize;
    if len & 0x80 != 0 {
        len = ((len & !0x80) * 0x100) + read_u8(reader)? as usize;
    }
    if len > max_len {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            format!("rsync vstring length {len} exceeds limit {max_len}"),
        ));
    }

    let mut bytes = vec![0_u8; len];
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}

pub fn write_vstring<W: Write>(writer: &mut W, bytes: &[u8]) -> io::Result<()> {
    if bytes.len() > 0x7fff {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "rsync vstring is too large",
        ));
    }
    if bytes.len() >= 0x80 {
        write_u8(writer, ((bytes.len() / 0x100) as u8) | 0x80)?;
    }
    write_u8(writer, (bytes.len() & 0xff) as u8)?;
    writer.write_all(bytes)
}

fn varint_extra_bytes(first: u8) -> usize {
    match first {
        0x00..=0x7f => 0,
        0x80..=0xbf => 1,
        0xc0..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf7 => 4,
        0xf8..=0xfb => 5,
        0xfc..=0xff => 6,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_little_endian_numbers() {
        let mut bytes = Vec::new();
        write_u8(&mut bytes, 0xab).unwrap();
        write_u16_le(&mut bytes, 0xbeef).unwrap();
        write_i32_le(&mut bytes, -123_456).unwrap();
        write_u32_le(&mut bytes, 0xdead_beef).unwrap();
        write_i64_le(&mut bytes, -9_876_543_210).unwrap();

        let mut cursor = bytes.as_slice();
        assert_eq!(read_u8(&mut cursor).unwrap(), 0xab);
        assert_eq!(read_u16_le(&mut cursor).unwrap(), 0xbeef);
        assert_eq!(read_i32_le(&mut cursor).unwrap(), -123_456);
        assert_eq!(read_u32_le(&mut cursor).unwrap(), 0xdead_beef);
        assert_eq!(read_i64_le(&mut cursor).unwrap(), -9_876_543_210);
    }

    #[test]
    fn round_trips_counted_bytes() {
        let mut bytes = Vec::new();
        write_bytes_with_u32_len(&mut bytes, b"abc\0def").unwrap();

        let mut cursor = bytes.as_slice();
        assert_eq!(
            read_bytes_with_u32_len(&mut cursor, 64).unwrap(),
            b"abc\0def"
        );
    }

    #[test]
    fn rejects_oversized_counted_bytes() {
        let mut bytes = Vec::new();
        write_u32_le(&mut bytes, 5).unwrap();
        bytes.extend_from_slice(b"abcde");

        let err = read_bytes_with_u32_len(&mut bytes.as_slice(), 4).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
    }

    #[test]
    fn round_trips_rsync_varints() {
        for value in [0, 30, 127, 128, 0x1234, 0x1ff, 0x12_3456, i32::MAX as u32] {
            let mut bytes = Vec::new();
            write_varint(&mut bytes, value).unwrap();

            assert_eq!(read_varint(&mut bytes.as_slice()).unwrap(), value);
        }
    }

    #[test]
    fn rejects_varints_outside_nonnegative_i32_range() {
        let err = write_varint(&mut Vec::new(), u32::MAX).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::InvalidInput);
    }

    #[test]
    fn reads_captured_protocol31_compat_flags_varint() {
        let mut bytes = [0x81, 0xff].as_slice();

        assert_eq!(read_varint(&mut bytes).unwrap(), 0x1ff);
    }

    #[test]
    fn round_trips_rsync_vstrings() {
        let values: [&[u8]; 3] = [b"", b"md4", b"xxh128 xxh3 xxh64 md5 md4 sha1 none"];

        for value in values {
            let mut bytes = Vec::new();
            write_vstring(&mut bytes, value).unwrap();

            assert_eq!(read_vstring(&mut bytes.as_slice(), 128).unwrap(), value);
        }
    }

    #[test]
    fn round_trips_rsync_varlongs() {
        for min_bytes in [3, 4] {
            for value in [0, 5, 4096, 1_777_084_468, i32::MAX as u64, u32::MAX as u64] {
                let mut bytes = Vec::new();
                write_varlong(&mut bytes, value, min_bytes).unwrap();

                assert_eq!(
                    read_varlong(&mut bytes.as_slice(), min_bytes).unwrap(),
                    value
                );
            }
        }
    }

    #[test]
    fn reads_captured_protocol31_varlongs() {
        assert_eq!(
            read_varlong(&mut [0x00, 0x05, 0x00].as_slice(), 3).unwrap(),
            5
        );
        assert_eq!(
            read_varlong(&mut [0x69, 0x34, 0x28, 0xec].as_slice(), 4).unwrap(),
            1_777_084_468
        );
    }

    #[test]
    fn reads_captured_protocol31_indexes() {
        let mut state = RsyncIndexState::default();

        assert_eq!(
            read_rsync_index(&mut [0xff, 0x65].as_slice(), &mut state).unwrap(),
            -102
        );
        assert_eq!(
            read_rsync_index(
                &mut [0xff, 0xfe, 0x80, 0x02, 0x00, 0x00].as_slice(),
                &mut state
            )
            .unwrap(),
            RSYNC_INDEX_FLIST_EOF
        );
    }

    #[test]
    fn round_trips_rsync_indexes() {
        let values = [
            0,
            2,
            RSYNC_INDEX_DONE,
            RSYNC_INDEX_FLIST_EOF,
            1000,
            1001,
            RSYNC_INDEX_FLIST_OFFSET - 1,
        ];
        let mut bytes = Vec::new();
        let mut write_state = RsyncIndexState::default();
        for value in values {
            write_rsync_index(&mut bytes, &mut write_state, value).unwrap();
        }

        let mut cursor = bytes.as_slice();
        let mut read_state = RsyncIndexState::default();
        for value in values {
            assert_eq!(
                read_rsync_index(&mut cursor, &mut read_state).unwrap(),
                value
            );
        }
        assert!(cursor.is_empty());
    }
}
