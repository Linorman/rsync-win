#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RollingChecksum {
    a: u16,
    b: u16,
    len: usize,
}

impl RollingChecksum {
    pub fn from_block(block: &[u8]) -> Self {
        let mut a = 0_i64;
        let mut b = 0_i64;

        for byte in block {
            a = i64::from(mod_u16(a + signed_byte(*byte)));
            b = i64::from(mod_u16(b + a));
        }

        Self {
            a: a as u16,
            b: b as u16,
            len: block.len(),
        }
    }

    pub fn roll(&mut self, outgoing: u8, incoming: u8) {
        assert!(self.len > 0, "cannot roll an empty checksum window");

        let outgoing = signed_byte(outgoing);
        let incoming = signed_byte(incoming);
        let a = mod_u16(i64::from(self.a) - outgoing + incoming);
        let b = mod_u16(i64::from(self.b) - (self.len as i64 * outgoing) + i64::from(a));

        self.a = a;
        self.b = b;
    }

    pub fn digest(self) -> u32 {
        (u32::from(self.b) << 16) | u32::from(self.a)
    }

    pub fn len(self) -> usize {
        self.len
    }

    pub fn is_empty(self) -> bool {
        self.len == 0
    }
}

pub fn rolling_checksum(block: &[u8]) -> u32 {
    RollingChecksum::from_block(block).digest()
}

fn mod_u16(value: i64) -> u16 {
    value.rem_euclid(65_536) as u16
}

fn signed_byte(byte: u8) -> i64 {
    i64::from(byte as i8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn computes_known_small_checksum() {
        let checksum = rolling_checksum(b"abc");
        let a = u32::from(b'a') + u32::from(b'b') + u32::from(b'c');
        let b = u32::from(b'a') + (u32::from(b'a') + u32::from(b'b')) + a;
        assert_eq!(checksum, (b << 16) | a);
    }

    #[test]
    fn matches_rsync_signed_byte_checksum_for_binary_data() {
        let checksum = rolling_checksum(&[0x80, 0xff, 0x01]);
        let a = 65_408_u32;
        let b = 65_151_u32;
        assert_eq!(checksum, (b << 16) | a);
    }

    #[test]
    fn rolling_update_matches_recomputed_window() {
        let data = b"abcdef";
        let mut rolling = RollingChecksum::from_block(&data[0..3]);

        rolling.roll(data[0], data[3]);
        assert_eq!(rolling.digest(), rolling_checksum(&data[1..4]));

        rolling.roll(data[1], data[4]);
        assert_eq!(rolling.digest(), rolling_checksum(&data[2..5]));

        rolling.roll(data[2], data[5]);
        assert_eq!(rolling.digest(), rolling_checksum(&data[3..6]));
    }
}
