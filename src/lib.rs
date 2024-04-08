//! The [MD5] hash function.
//!
//! ## Example
//!
//! ```
//! let digest = md5::compute(b"abcdefghijklmnopqrstuvwxyz");
//! assert_eq!(format!("{:x}", digest), "c3fcd3d76192e4007dfb496cca67e13b");
//! ```
//!
//! ## Security Warning
//!
//! The package is provided for the purposes of interoperability with protocols
//! and systems that mandate the use of MD5. However, MD5 should be considered
//! [cryptographically broken and unsuitable for further use][VU836068].
//! Collision attacks against MD5 are both practical and trivial, and
//! [theoretical attacks against MD5 have been found][ACM1724151].
//!
//! [RFC6151] advises no new protocols to be designed with any MD5-based
//! constructions, including HMAC-MD5.
//!
//! [MD5]: https://en.wikipedia.org/wiki/MD5
//!
//! [ACM1724151]: https://dl.acm.org/citation.cfm?id=1724151
//! [RFC6151]: https://tools.ietf.org/html/rfc6151
//! [VU836068]: https://www.kb.cert.org/vuls/id/836068

// The implementation is based on:
// https://people.csail.mit.edu/rivest/Md5.c
// https://tools.ietf.org/html/rfc1321

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "std")]
use std as core;

use core::convert;
use core::fmt;
use core::ops;

#[cfg(feature = "std")]
use core::io;

/// A digest.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct Digest(pub [u8; 16]);

impl convert::From<Digest> for [u8; 16] {
    #[inline]
    fn from(digest: Digest) -> Self {
        digest.0
    }
}

impl fmt::Debug for Digest {
    #[inline]
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(self, formatter)
    }
}

impl ops::Deref for Digest {
    type Target = [u8; 16];

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ops::DerefMut for Digest {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

macro_rules! implement {
    ($kind:ident, $format:expr) => {
        impl fmt::$kind for Digest {
            fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                for value in &self.0 {
                    write!(formatter, $format, value)?;
                }
                Ok(())
            }
        }
    };
}

implement!(LowerHex, "{:02x}");
implement!(UpperHex, "{:02X}");

const PADDING: [u8; 64] = {
    let mut data = [0; 64];
    data[0] = 0x80;
    data
};

#[rustfmt::skip]
const SHIFTS: [u32; 64] = [
    07, 12, 17, 22, 07, 12, 17, 22, 07, 12, 17, 22, 07, 12, 17, 22, // Round 1
    05, 09, 14, 20, 05, 09, 14, 20, 05, 09, 14, 20, 05, 09, 14, 20, // Round 2
    04, 11, 16, 23, 04, 11, 16, 23, 04, 11, 16, 23, 04, 11, 16, 23, // Round 3
    06, 10, 15, 21, 06, 10, 15, 21, 06, 10, 15, 21, 06, 10, 15, 21, // Round 4
];

// f64::floor(power * f64::abs(f64::sin(i as f64 + 1.0))) as u32
const SINES: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];

const START_HASH_VALUES: [u32; 4] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];

/// Consume data.
pub fn compute<T: AsRef<[u8]>>(data: T) -> Digest {
    let mut buffer: [u8; 64] = [0; 64];
    let mut hash_values = START_HASH_VALUES;
    let mut k = 0;

    for &value in data.as_ref() {
        buffer[k] = value;
        k += 1;

        if k == 64 {
            transform(&mut hash_values, &buffer);
            k = 0;
        }
    }

    if k > 55 {
        // Not enough space to fit length at the end of the buffer; pad and transform.
        buffer[k..64].copy_from_slice(&PADDING[..64 - k]);
        transform(&mut hash_values, &buffer);
        // Copy across zeros upto the length marker.
        buffer[..56].copy_from_slice(&PADDING[1..57])
    } else {
        // Enough space already; copy across padding.
        buffer[k..56].copy_from_slice(&PADDING[..56 - k])
    }

    // Append the data length (in bits) and run the last transform.
    let mut data_length = (data.as_ref().len() << 3) as u64;
    let mut i = 0;
    while i < 8 {
        buffer[56 + i] = data_length as u8;
        data_length >>= 8;
        i += 1;
    }

    transform(&mut hash_values, &buffer);

    let mut output: [u8; 16] = [0; 16];
    // Convert hash_values from u32 -> u8s assuming little endian format.
    for i in 0..16 {
        output[i] = hash_values[i / 4] as u8;
        hash_values[i / 4] >>= 8;
    }

    Digest(output)
}

#[inline(always)]
fn transform(hash_values: &mut [u32; 4], buffer: &[u8; 64]) {
    let mut segments: [u32; 16] = [0; 16];

    for i in 0..16 {
        let byte_start = i * 4;
        segments[i] = ((buffer[byte_start] as u32) << 0)
            + ((buffer[byte_start + 1] as u32) << 8)
            + ((buffer[byte_start + 2] as u32) << 16)
            + ((buffer[byte_start + 3] as u32) << 24);
    }

    let mut hash_a = hash_values[0];
    let mut hash_b = hash_values[1];
    let mut hash_c = hash_values[2];
    let mut hash_d = hash_values[3];

    let mut f: u32;
    let mut g: usize;

    let cycle_hashes =
        |a: &mut u32, b: &mut u32, c: &mut u32, d: &mut u32, mut f: u32, g: usize, i: usize| {
            f = f
                .wrapping_add(*a)
                .wrapping_add(SINES[i])
                .wrapping_add(segments[g]);
            *a = *d;
            *d = *c;
            *c = *b;
            *b = f.rotate_left(SHIFTS[i]).wrapping_add(*b);
        };

    for i in 0..16 {
        f = (hash_b & hash_c) | (!hash_b & hash_d);
        g = i;
        cycle_hashes(&mut hash_a, &mut hash_b, &mut hash_c, &mut hash_d, f, g, i);
    }

    for i in 16..32 {
        f = (hash_d & hash_b) | (!hash_d & hash_c);
        g = (5 * i + 1) % 16;
        cycle_hashes(&mut hash_a, &mut hash_b, &mut hash_c, &mut hash_d, f, g, i);
    }

    for i in 32..48 {
        f = hash_b ^ hash_c ^ hash_d;
        g = (3 * i + 5) % 16;
        cycle_hashes(&mut hash_a, &mut hash_b, &mut hash_c, &mut hash_d, f, g, i);
    }

    for i in 48..64 {
        f = hash_c ^ (hash_b | !hash_d);
        g = (7 * i) % 16;
        cycle_hashes(&mut hash_a, &mut hash_b, &mut hash_c, &mut hash_d, f, g, i);
    }

    hash_values[0] = hash_values[0].wrapping_add(hash_a);
    hash_values[1] = hash_values[1].wrapping_add(hash_b);
    hash_values[2] = hash_values[2].wrapping_add(hash_c);
    hash_values[3] = hash_values[3].wrapping_add(hash_d);
}

#[cfg(test)]
mod tests {
    #[test]
    fn compute() {
        let inputs = [
            "",
            "a",
            "abc",
            "message digest",
            "abcdefghijklmnopqrstuvwxyz",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "0123456789012345678901234567890123456789012345678901234567890123",
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
        ];
        let outputs = [
            "d41d8cd98f00b204e9800998ecf8427e",
            "0cc175b9c0f1b6a831c399e269772661",
            "900150983cd24fb0d6963f7d28e17f72",
            "f96b697d7cb7938d525a2f31aaf161d0",
            "c3fcd3d76192e4007dfb496cca67e13b",
            "d174ab98d277d9f5a5611c2c9f419d9f",
            "7f7bfd348709deeaace19e3f535f8c54",
            "57edf4a22be3c955ac49da2e2107b67a",
        ];
        for (input, &output) in inputs.iter().zip(outputs.iter()) {
            assert_eq!(format!("{:x}", ::compute(input)), output);
        }
    }

    #[test]
    fn index() {
        let mut digest = ::compute(b"abc");
        assert_eq!(digest[0], 0x90);
        assert_eq!(&digest[0], &0x90);
        assert_eq!(&mut digest[0], &mut 0x90);
    }
}
