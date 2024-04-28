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

const STATE: [u32; 4] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];

#[allow(clippy::zero_prefixed_literal)]
#[rustfmt::skip]
const SHIFTS: [u32; 64] = [
    07, 12, 17, 22, 07, 12, 17, 22, 07, 12, 17, 22, 07, 12, 17, 22,
    05, 09, 14, 20, 05, 09, 14, 20, 05, 09, 14, 20, 05, 09, 14, 20,
    04, 11, 16, 23, 04, 11, 16, 23, 04, 11, 16, 23, 04, 11, 16, 23,
    06, 10, 15, 21, 06, 10, 15, 21, 06, 10, 15, 21, 06, 10, 15, 21,
];

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

const PADDING: [u8; 64] = {
    let mut data = [0; 64];
    data[0] = 0x80;
    data
};

/// A digest.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct Digest(pub [u8; 16]);

/// A context.
#[derive(Clone)]
pub struct Context {
    state: [u32; 4],
    buffer: [u8; 64],
    cursor: usize,
    length: u64,
}

impl core::convert::From<Digest> for [u8; 16] {
    #[inline]
    fn from(digest: Digest) -> Self {
        digest.0
    }
}

impl core::fmt::Debug for Digest {
    #[inline]
    fn fmt(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
        core::fmt::LowerHex::fmt(self, formatter)
    }
}

impl core::ops::Deref for Digest {
    type Target = [u8; 16];

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl core::ops::DerefMut for Digest {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

macro_rules! implement {
    ($kind:ident, $format:expr) => {
        impl core::fmt::$kind for Digest {
            fn fmt(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
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

impl Context {
    /// Create a context for computing a digest.
    #[inline]
    pub fn new() -> Context {
        Context {
            state: STATE,
            buffer: [0; 64],
            cursor: 0,
            length: 0,
        }
    }

    /// Consume data.
    #[cfg(target_pointer_width = "32")]
    pub fn consume<T: AsRef<[u8]>>(&mut self, data: T) {
        consume(
            &mut self.state,
            &mut self.buffer,
            &mut self.cursor,
            &mut self.length,
            data.as_ref(),
        );
    }

    /// Consume data.
    #[cfg(target_pointer_width = "64")]
    pub fn consume<T: AsRef<[u8]>>(&mut self, data: T) {
        for chunk in data.as_ref().chunks(core::u32::MAX as usize) {
            consume(
                &mut self.state,
                &mut self.buffer,
                &mut self.cursor,
                &mut self.length,
                chunk,
            );
        }
    }

    /// Finalize and return the digest.
    pub fn compute(mut self) -> Digest {
        Digest(finalize(
            &mut self.state,
            &mut self.buffer,
            self.cursor,
            self.length,
        ))
    }
}

impl Default for Context {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl core::convert::From<Context> for Digest {
    #[inline]
    fn from(context: Context) -> Digest {
        context.compute()
    }
}

#[cfg(feature = "std")]
impl core::io::Write for Context {
    #[inline]
    fn write(&mut self, data: &[u8]) -> core::io::Result<usize> {
        self.consume(data);
        Ok(data.len())
    }

    #[inline]
    fn flush(&mut self) -> core::io::Result<()> {
        Ok(())
    }
}

/// Compute the digest of data.
#[allow(clippy::needless_range_loop)]
pub fn compute<T: AsRef<[u8]>>(data: T) -> Digest {
    let mut buffer: [u8; 64] = [0; 64];
    let mut state = STATE;
    let mut cursor = 0;

    let data = data.as_ref();
    for &value in data {
        buffer[cursor] = value;
        cursor += 1;
        if cursor == 64 {
            transform(&mut state, &buffer);
            cursor = 0;
        }
    }

    Digest(finalize(&mut state, &mut buffer, cursor, data.len() as u64))
}

#[inline(always)]
fn consume(
    state: &mut [u32; 4],
    buffer: &mut [u8; 64],
    cursor: &mut usize,
    length: &mut u64,
    data: &[u8],
) {
    for chunk in data {
        buffer[*cursor] = *chunk;
        *cursor += 1;
        if *cursor == 64 {
            transform(state, buffer);
            *cursor = 0;
        }
    }
    *length = length.wrapping_add(data.len() as u64);
}

#[allow(clippy::needless_range_loop)]
#[inline(always)]
fn finalize(
    state: &mut [u32; 4],
    buffer: &mut [u8; 64],
    cursor: usize,
    mut length: u64,
) -> [u8; 16] {
    if cursor > 55 {
        buffer[cursor..64].copy_from_slice(&PADDING[..64 - cursor]);
        transform(state, buffer);
        buffer[0..56].copy_from_slice(&PADDING[1..57])
    } else {
        buffer[cursor..56].copy_from_slice(&PADDING[..56 - cursor])
    }
    length <<= 3;
    for i in 56..64 {
        buffer[i] = length as u8;
        length >>= 8;
    }
    transform(state, buffer);

    let mut output: [u8; 16] = [0; 16];
    for i in 0..16 {
        output[i] = state[i / 4] as u8;
        state[i / 4] >>= 8;
    }
    output
}

#[allow(clippy::identity_op, clippy::needless_range_loop)]
#[inline(always)]
#[rustfmt::skip]
fn transform(state: &mut [u32; 4], buffer: &[u8; 64]) {
    let mut segments: [u32; 16] = [0; 16];

    for i in 0..16 {
        let j = i * 4;
        segments[i] =
              ((buffer[j + 0] as u32) <<  0)
            + ((buffer[j + 1] as u32) <<  8)
            + ((buffer[j + 2] as u32) << 16)
            + ((buffer[j + 3] as u32) << 24);
    }

    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];

    for i in 0..16 {
        let f = (b & c) | (!b & d);
        let g = i;
        cycle(&mut a, &mut b, &mut c, &mut d, f, segments[g], i);
    }

    for i in 16..32 {
        let f = (d & b) | (!d & c);
        let g = (5 * i + 1) % 16;
        cycle(&mut a, &mut b, &mut c, &mut d, f, segments[g], i);
    }

    for i in 32..48 {
        let f = b ^ c ^ d;
        let g = (3 * i + 5) % 16;
        cycle(&mut a, &mut b, &mut c, &mut d, f, segments[g], i);
    }

    for i in 48..64 {
        let f = c ^ (b | !d);
        let g = (7 * i) % 16;
        cycle(&mut a, &mut b, &mut c, &mut d, f, segments[g], i);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
}

#[inline(always)]
fn cycle(a: &mut u32, b: &mut u32, c: &mut u32, d: &mut u32, mut f: u32, g: u32, i: usize) {
    f = f.wrapping_add(*a).wrapping_add(SINES[i]).wrapping_add(g);
    *a = *d;
    *d = *c;
    *c = *b;
    *b = f.rotate_left(SHIFTS[i]).wrapping_add(*b);
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
            assert_eq!(format!("{:x}", super::compute(input)), output);
        }
    }

    #[test]
    fn index() {
        let mut digest = super::compute(b"abc");
        assert_eq!(digest[0], 0x90);
        assert_eq!(&digest[0], &0x90);
        assert_eq!(&mut digest[0], &mut 0x90);
    }

    #[test]
    fn overflow_count() {
        use std::io::prelude::Write;
        let data = vec![0; 8 * 1024 * 1024];
        let mut context = super::Context::new();
        for _ in 0..64 {
            context.write(&data).unwrap();
        }
        assert_eq!(
            format!("{:x}", context.compute()),
            "aa559b4e3523a6c931f08f4df52d58f2"
        );
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn overflow_length() {
        use std::io::prelude::Write;
        use std::u32::MAX;
        let data = vec![0; MAX as usize + 1];
        let mut context = super::Context::new();
        context.write(&data).unwrap();
        assert_eq!(
            format!("{:x}", context.compute()),
            "c9a5a6878d97b48cc965c1e41859f034"
        );
    }
}
