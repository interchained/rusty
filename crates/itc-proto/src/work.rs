//! Minimal 256-bit unsigned integer and Bitcoin's proof-of-work computation —
//! just enough for cumulative chainwork comparison (the seam's "more work" test).

use core::cmp::Ordering;

/// A 256-bit unsigned integer as four little-endian 64-bit limbs (`[0]` = LSB).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct U256(pub [u64; 4]);

impl U256 {
    pub const ZERO: U256 = U256([0, 0, 0, 0]);
    pub const ONE: U256 = U256([1, 0, 0, 0]);

    pub const fn from_u64(x: u64) -> U256 {
        U256([x, 0, 0, 0])
    }

    pub fn is_zero(&self) -> bool {
        self.0 == [0, 0, 0, 0]
    }

    /// Wrapping add (cumulative chainwork will not realistically overflow 256 bits).
    pub fn add(self, other: U256) -> U256 {
        let mut out = [0u64; 4];
        let mut carry = 0u128;
        for i in 0..4 {
            let s = self.0[i] as u128 + other.0[i] as u128 + carry;
            out[i] = s as u64;
            carry = s >> 64;
        }
        U256(out)
    }

    /// self - other (wrapping; caller ensures self >= other).
    pub fn sub(self, other: U256) -> U256 {
        let mut out = [0u64; 4];
        let mut borrow: i128 = 0;
        for i in 0..4 {
            let d = self.0[i] as i128 - other.0[i] as i128 - borrow;
            if d < 0 {
                out[i] = (d + (1i128 << 64)) as u64;
                borrow = 1;
            } else {
                out[i] = d as u64;
                borrow = 0;
            }
        }
        U256(out)
    }

    pub fn not(self) -> U256 {
        U256([!self.0[0], !self.0[1], !self.0[2], !self.0[3]])
    }

    pub fn bit(&self, i: usize) -> bool {
        (self.0[i / 64] >> (i % 64)) & 1 == 1
    }
    pub fn set_bit(&mut self, i: usize) {
        self.0[i / 64] |= 1u64 << (i % 64);
    }

    /// self << 1 (top bit is dropped; our divisors stay below 2^255 so the
    /// long-division remainder never needs it).
    pub fn shl1(self) -> U256 {
        let mut out = [0u64; 4];
        let mut carry = 0u64;
        for i in 0..4 {
            out[i] = (self.0[i] << 1) | carry;
            carry = self.0[i] >> 63;
        }
        U256(out)
    }

    /// Binary long division → (quotient, remainder). `divisor` must be non-zero
    /// and (for our chainwork use) below 2^255.
    pub fn div_rem(self, divisor: U256) -> (U256, U256) {
        if divisor.is_zero() {
            return (U256::ZERO, U256::ZERO);
        }
        let mut q = U256::ZERO;
        let mut r = U256::ZERO;
        for i in (0..256).rev() {
            r = r.shl1();
            if self.bit(i) {
                r.0[0] |= 1;
            }
            if r.cmp_u256(&divisor) != Ordering::Less {
                r = r.sub(divisor);
                q.set_bit(i);
            }
        }
        (q, r)
    }

    fn cmp_u256(&self, other: &U256) -> Ordering {
        for i in (0..4).rev() {
            if self.0[i] != other.0[i] {
                return self.0[i].cmp(&other.0[i]);
            }
        }
        Ordering::Equal
    }
}

impl PartialOrd for U256 {
    fn partial_cmp(&self, other: &U256) -> Option<Ordering> {
        Some(self.cmp_u256(other))
    }
}
impl Ord for U256 {
    fn cmp(&self, other: &U256) -> Ordering {
        self.cmp_u256(other)
    }
}

fn shl_u256(v: U256, shift: usize) -> U256 {
    if shift >= 256 {
        return U256::ZERO;
    }
    let mut out = v;
    for _ in 0..shift {
        out = out.shl1();
    }
    out
}

/// Decode a compact "bits" value (nBits) into a 256-bit target threshold.
pub fn target_from_compact(bits: u32) -> U256 {
    let exponent = (bits >> 24) as usize;
    let mantissa = (bits & 0x007f_ffff) as u64;
    if exponent <= 3 {
        U256::from_u64(mantissa >> (8 * (3 - exponent)))
    } else {
        shl_u256(U256::from_u64(mantissa), 8 * (exponent - 3))
    }
}

/// Bitcoin `GetBlockProof`: work = floor(2^256 / (target + 1))
/// computed as (~target / (target + 1)) + 1. Returns ZERO for a zero target.
pub fn work_from_bits(bits: u32) -> U256 {
    let target = target_from_compact(bits);
    if target.is_zero() {
        return U256::ZERO;
    }
    let divisor = target.add(U256::ONE);
    let (q, _r) = target.not().div_rem(divisor);
    q.add(U256::ONE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_and_cmp() {
        let a = U256::from_u64(u64::MAX);
        let b = U256::from_u64(1);
        let c = a.add(b);
        assert_eq!(c, U256([0, 1, 0, 0]));
        assert!(c > a);
        assert!(U256::ZERO < U256::ONE);
    }

    #[test]
    fn div_rem_small() {
        let (q, r) = U256::from_u64(100).div_rem(U256::from_u64(7));
        assert_eq!(q, U256::from_u64(14));
        assert_eq!(r, U256::from_u64(2));
    }

    #[test]
    fn difficulty_one_work() {
        // The canonical difficulty-1 block work is 0x00000000_00000000_00000001_00010001.
        assert_eq!(work_from_bits(0x1d00_ffff), U256::from_u64(0x1_0001_0001));
    }

    #[test]
    fn harder_target_is_more_work() {
        // smaller exponent => smaller target => more work
        assert!(work_from_bits(0x1c00_ffff) > work_from_bits(0x1d00_ffff));
        // regtest's very easy target still yields at least 1 unit of work
        assert!(work_from_bits(0x207f_ffff) >= U256::ONE);
    }
}
