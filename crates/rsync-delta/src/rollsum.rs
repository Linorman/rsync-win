#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RollingChecksum {
    a: u16,
    b: u16,
    len: usize,
}

impl RollingChecksum {
    pub fn from_block(block: &[u8]) -> Self {
        let mut a = 0_u32;
        let mut b = 0_u32;

        for byte in block {
            a = (a + u32::from(*byte)) & 0xffff;
            b = (b + a) & 0xffff;
        }

        Self {
            a: a as u16,
            b: b as u16,
            len: block.len(),
        }
    }

    pub fn roll(&mut self, outgoing: u8, incoming: u8) {
        assert!(self.len > 0, "cannot roll an empty checksum window");

        let a = mod_u16(i64::from(self.a) - i64::from(outgoing) + i64::from(incoming));
        let b = mod_u16(i64::from(self.b) - (self.len as i64 * i64::from(outgoing)) + i64::from(a));

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
