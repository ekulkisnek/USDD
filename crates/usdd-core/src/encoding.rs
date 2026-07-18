use alloc::{string::String, vec::Vec};
use core::fmt;

/// Deterministic fixed-width or explicitly length-prefixed encoding.
///
/// Integers are big-endian. Variable byte strings use a big-endian `u32`
/// length. Protocol records should prefer fixed-width hashes and addresses.
pub trait CanonicalEncode {
    fn encode_to(&self, out: &mut Vec<u8>);

    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_to(&mut out);
        out
    }
}

pub trait CanonicalDecode: Sized {
    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError>;

    fn decode_exact(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut decoder = Decoder::new(bytes);
        let value = Self::decode_from(&mut decoder)?;
        if decoder.remaining() != 0 {
            return Err(DecodeError::TrailingBytes(decoder.remaining()));
        }
        Ok(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DecodeError {
    UnexpectedEof { needed: usize, remaining: usize },
    TrailingBytes(usize),
    InvalidTag { type_name: &'static str, tag: u64 },
    InvalidLength { expected: usize, actual: usize },
    LengthOverflow,
    InvalidValue(&'static str),
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEof { needed, remaining } => {
                write!(f, "need {needed} bytes but only {remaining} remain")
            }
            Self::TrailingBytes(count) => write!(f, "{count} trailing bytes"),
            Self::InvalidTag { type_name, tag } => {
                write!(f, "invalid {type_name} tag {tag}")
            }
            Self::InvalidLength { expected, actual } => {
                write!(f, "expected length {expected}, got {actual}")
            }
            Self::LengthOverflow => f.write_str("length exceeds u32"),
            Self::InvalidValue(message) => f.write_str(message),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DecodeError {}

pub struct Decoder<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> Decoder<'a> {
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.cursor)
    }

    pub fn take(&mut self, len: usize) -> Result<&'a [u8], DecodeError> {
        if self.remaining() < len {
            return Err(DecodeError::UnexpectedEof {
                needed: len,
                remaining: self.remaining(),
            });
        }
        let start = self.cursor;
        self.cursor += len;
        Ok(&self.bytes[start..self.cursor])
    }

    pub fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }

    pub fn u16(&mut self) -> Result<u16, DecodeError> {
        let bytes: [u8; 2] = self.take(2)?.try_into().expect("fixed length");
        Ok(u16::from_be_bytes(bytes))
    }

    pub fn u32(&mut self) -> Result<u32, DecodeError> {
        let bytes: [u8; 4] = self.take(4)?.try_into().expect("fixed length");
        Ok(u32::from_be_bytes(bytes))
    }

    pub fn u64(&mut self) -> Result<u64, DecodeError> {
        let bytes: [u8; 8] = self.take(8)?.try_into().expect("fixed length");
        Ok(u64::from_be_bytes(bytes))
    }

    pub fn fixed<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        Ok(self.take(N)?.try_into().expect("fixed length"))
    }

    pub fn bytes(&mut self) -> Result<Vec<u8>, DecodeError> {
        let len = self.u32()? as usize;
        Ok(self.take(len)?.to_vec())
    }

    pub fn string(&mut self) -> Result<String, DecodeError> {
        let bytes = self.bytes()?;
        String::from_utf8(bytes).map_err(|_| DecodeError::InvalidValue("invalid UTF-8"))
    }
}

impl CanonicalEncode for u8 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        out.push(*self);
    }
}

impl CanonicalDecode for u8 {
    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decoder.u8()
    }
}

macro_rules! integer_encoding {
    ($type:ty, $method:ident) => {
        impl CanonicalEncode for $type {
            fn encode_to(&self, out: &mut Vec<u8>) {
                out.extend_from_slice(&self.to_be_bytes());
            }
        }

        impl CanonicalDecode for $type {
            fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
                decoder.$method()
            }
        }
    };
}

integer_encoding!(u16, u16);
integer_encoding!(u32, u32);
integer_encoding!(u64, u64);

impl<const N: usize> CanonicalEncode for [u8; N] {
    fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self);
    }
}

impl<const N: usize> CanonicalDecode for [u8; N] {
    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decoder.fixed()
    }
}

impl CanonicalEncode for Vec<u8> {
    fn encode_to(&self, out: &mut Vec<u8>) {
        let len = u32::try_from(self.len()).expect("canonical byte string exceeds u32");
        len.encode_to(out);
        out.extend_from_slice(self);
    }
}

impl CanonicalDecode for Vec<u8> {
    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decoder.bytes()
    }
}

impl<T: CanonicalEncode> CanonicalEncode for Option<T> {
    fn encode_to(&self, out: &mut Vec<u8>) {
        match self {
            None => 0u8.encode_to(out),
            Some(value) => {
                1u8.encode_to(out);
                value.encode_to(out);
            }
        }
    }
}

impl<T: CanonicalDecode> CanonicalDecode for Option<T> {
    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match decoder.u8()? {
            0 => Ok(None),
            1 => Ok(Some(T::decode_from(decoder)?)),
            tag => Err(DecodeError::InvalidTag {
                type_name: "Option",
                tag: tag.into(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers_are_big_endian() {
        assert_eq!(0x0102u16.encode(), [1, 2]);
        assert_eq!(0x01020304u32.encode(), [1, 2, 3, 4]);
        assert_eq!(0x0102030405060708u64.encode(), [1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn exact_decode_rejects_trailing_data() {
        assert_eq!(
            u16::decode_exact(&[0, 1, 2]),
            Err(DecodeError::TrailingBytes(1))
        );
    }
}
