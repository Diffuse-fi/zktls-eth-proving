use super::{ParseSignedError, Sign, utils::*};
// use alloc::string::String;
use core::fmt;
use ruint::{BaseConvertError, Uint, UintTryFrom, UintTryTo};

/// Signed integer wrapping a `ruint::Uint`.
///
/// This signed integer implementation is fully abstract across the number of
/// bits. It wraps a [`ruint::Uint`], and co-opts the most significant bit to
/// represent the sign. The number is represented in two's complement, using the
/// underlying `Uint`'s `u64` limbs. The limbs can be accessed via the
/// [`Signed::as_limbs()`] method, and are least-significant first.
///
/// ## Aliases
///
/// We provide aliases for every bit-width divisble by 8, from 8 to 256. These
/// are located in [`crate::aliases`] and are named `I256`, `I248` etc. Most
/// users will want [`crate::I256`].
///
/// # Usage
///
/// ```
/// # use alloy_primitives::I256;
/// // Instantiate from a number
/// let a = I256::unchecked_from(1);
/// // Use `try_from` if you're not sure it'll fit
/// let b = I256::try_from(200000382).unwrap();
///
/// // Or parse from a string :)
/// let c = "100".parse::<I256>().unwrap();
/// let d = "-0x138f".parse::<I256>().unwrap();
///
/// // Preceding plus is allowed but not recommended
/// let e = "+0xdeadbeef".parse::<I256>().unwrap();
///
/// // Underscores are ignored
/// let f = "1_000_000".parse::<I256>().unwrap();
///
/// // But invalid chars are not
/// assert!("^31".parse::<I256>().is_err());
///
/// // Math works great :)
/// let g = a * b + c - d;
///
/// // And so do comparisons!
/// assert!(e > a);
///
/// // We have some useful constants too
/// assert_eq!(I256::ZERO, I256::unchecked_from(0));
/// assert_eq!(I256::ONE, I256::unchecked_from(1));
/// assert_eq!(I256::MINUS_ONE, I256::unchecked_from(-1));
/// ```

pub type I256 = Signed<256, 4>;

#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "arbitrary", derive(derive_arbitrary::Arbitrary, proptest_derive::Arbitrary))]
pub struct Signed<const BITS: usize, const LIMBS: usize>(pub(crate) Uint<BITS, LIMBS>);

// formatting
impl<const BITS: usize, const LIMBS: usize> fmt::Debug for Signed<BITS, LIMBS> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl<const BITS: usize, const LIMBS: usize> fmt::Display for Signed<BITS, LIMBS> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (sign, abs) = self.into_sign_and_abs();
        sign.fmt(f)?;
        if f.sign_plus() { write!(f, "{abs}") } else { abs.fmt(f) }
    }
}

impl<const BITS: usize, const LIMBS: usize> fmt::Binary for Signed<BITS, LIMBS> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl<const BITS: usize, const LIMBS: usize> fmt::Octal for Signed<BITS, LIMBS> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl<const BITS: usize, const LIMBS: usize> fmt::LowerHex for Signed<BITS, LIMBS> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl<const BITS: usize, const LIMBS: usize> fmt::UpperHex for Signed<BITS, LIMBS> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl<const BITS: usize, const LIMBS: usize> Signed<BITS, LIMBS> {
    /// Mask for the highest limb.
    pub(crate) const MASK: u64 = ruint::mask(BITS);

    /// Location of the sign bit within the highest limb.
    pub(crate) const SIGN_BIT: u64 = sign_bit(BITS);

    /// Number of bits.
    pub const BITS: usize = BITS;

    /// The size of this integer type in bytes. Note that some bits may be
    /// forced zero if BITS is not cleanly divisible by eight.
    pub const BYTES: usize = Uint::<BITS, LIMBS>::BYTES;

    /// The minimum value.
    pub const MIN: Self = min();

    /// The maximum value.
    pub const MAX: Self = max();

    /// Zero (additive identity) of this type.
    pub const ZERO: Self = zero();

    /// One (multiplicative identity) of this type.
    pub const ONE: Self = one();

    /// Minus one (multiplicative inverse) of this type.
    pub const MINUS_ONE: Self = Self(Uint::<BITS, LIMBS>::MAX);

    /// Coerces an unsigned integer into a signed one. If the unsigned integer is greater than or
    /// equal to `1 << 255`, then the result will overflow into a negative value.
    #[inline]
    pub const fn from_raw(val: Uint<BITS, LIMBS>) -> Self {
        Self(val)
    }

    /// Shortcut for `val.try_into().unwrap()`.
    ///
    /// # Panics
    ///
    /// Panics if the conversion fails.
    #[inline]
    #[track_caller]
    pub fn unchecked_from<T>(val: T) -> Self
    where
        T: TryInto<Self>,
        <T as TryInto<Self>>::Error: fmt::Debug,
    {
        val.try_into().unwrap()
    }

    /// Construct a new [`Signed`] from the value.
    ///
    /// # Panics
    ///
    /// Panics if the conversion fails, for example if the value is too large
    /// for the bit-size of the [`Signed`]. The panic will be attributed to the
    /// call site.
    #[inline]
    #[track_caller]
    pub fn from<T>(value: T) -> Self
    where
        Self: UintTryFrom<T>,
    {
        match Self::uint_try_from(value) {
            Ok(n) => n,
            Err(e) => panic!("Uint conversion error: {e}"),
        }
    }

    /// # Panics
    ///
    /// Panics if the conversion fails, for example if the value is too large
    /// for the bit-size of the target type.
    #[inline]
    #[track_caller]
    pub fn to<T>(&self) -> T
    where
        Self: UintTryTo<T>,
        T: fmt::Debug,
    {
        self.uint_try_to().expect("Uint conversion error")
    }

    /// Shortcut for `self.try_into().unwrap()`.
    ///
    /// # Panics
    ///
    /// Panics if the conversion fails.
    #[inline]
    #[track_caller]
    pub fn unchecked_into<T>(self) -> T
    where
        Self: TryInto<T>,
        <Self as TryInto<T>>::Error: fmt::Debug,
    {
        self.try_into().unwrap()
    }

    /// Returns the signed integer as a unsigned integer. If the value of `self`
    /// negative, then the two's complement of its absolute value will be
    /// returned.
    #[inline]
    pub const fn into_raw(self) -> Uint<BITS, LIMBS> {
        self.0
    }

    /// Returns the sign of self.
    #[inline]
    pub const fn sign(&self) -> Sign {
        // if the last limb contains the sign bit, then we're negative
        // because we can't set any higher bits to 1, we use >= as a proxy
        // check to avoid bit comparison
        if let Some(limb) = self.0.as_limbs().last() {
            if *limb >= Self::SIGN_BIT {
                return Sign::Negative;
            }
        }
        Sign::Positive
    }

    /// Determines if the integer is odd.
    #[inline]
    pub const fn is_odd(&self) -> bool {
        if BITS == 0 { false } else { self.as_limbs()[0] % 2 == 1 }
    }

    /// Compile-time equality. NOT constant-time equality.
    #[inline]
    pub const fn const_eq(&self, other: &Self) -> bool {
        const_eq(self, other)
    }

    /// Returns `true` if `self` is zero and `false` if the number is negative
    /// or positive.
    #[inline]
    pub const fn is_zero(&self) -> bool {
        self.const_eq(&Self::ZERO)
    }

    /// Returns `true` if `self` is positive and `false` if the number is zero
    /// or negative.
    #[inline]
    pub const fn is_positive(&self) -> bool {
        !self.is_zero() && matches!(self.sign(), Sign::Positive)
    }

    /// Returns `true` if `self` is negative and `false` if the number is zero
    /// or positive.
    #[inline]
    pub const fn is_negative(&self) -> bool {
        matches!(self.sign(), Sign::Negative)
    }

    /// Returns the number of ones in the binary representation of `self`.
    #[inline]
    pub const fn count_ones(&self) -> usize {
        self.0.count_ones()
    }

    /// Returns the number of zeros in the binary representation of `self`.
    #[inline]
    pub const fn count_zeros(&self) -> usize {
        self.0.count_zeros()
    }

    /// Returns the number of leading zeros in the binary representation of
    /// `self`.
    #[inline]
    pub const fn leading_zeros(&self) -> usize {
        self.0.leading_zeros()
    }

    /// Returns the number of leading zeros in the binary representation of
    /// `self`.
    #[inline]
    pub fn trailing_zeros(&self) -> usize {
        self.0.trailing_zeros()
    }

    /// Returns the number of leading ones in the binary representation of
    /// `self`.
    #[inline]
    pub fn trailing_ones(&self) -> usize {
        self.0.trailing_ones()
    }

    /// Returns whether a specific bit is set.
    ///
    /// Returns `false` if `index` exceeds the bit width of the number.
    #[inline]
    pub const fn bit(&self, index: usize) -> bool {
        self.0.bit(index)
    }

    /// Returns a specific byte. The byte at index `0` is the least significant
    /// byte (little endian).
    ///
    /// # Panics
    ///
    /// Panics if `index` exceeds the byte width of the number.
    #[inline]
    #[track_caller]
    pub const fn byte(&self, index: usize) -> u8 {
        self.0.byte(index)
    }

    /// Return the least number of bits needed to represent the number.
    #[inline]
    pub fn bits(&self) -> u32 {
        let unsigned = self.unsigned_abs();
        let unsigned_bits = unsigned.bit_len();

        // NOTE: We need to deal with two special cases:
        //   - the number is 0
        //   - the number is a negative power of `2`. These numbers are written as `0b11..1100..00`.
        //   In the case of a negative power of two, the number of bits required
        //   to represent the negative signed value is equal to the number of
        //   bits required to represent its absolute value as an unsigned
        //   integer. This is best illustrated by an example: the number of bits
        //   required to represent `-128` is `8` since it is equal to `i8::MIN`
        //   and, therefore, obviously fits in `8` bits. This is equal to the
        //   number of bits required to represent `128` as an unsigned integer
        //   (which fits in a `u8`).  However, the number of bits required to
        //   represent `128` as a signed integer is `9`, as it is greater than
        //   `i8::MAX`.  In the general case, an extra bit is needed to
        //   represent the sign.
        let bits = if self.count_zeros() == self.trailing_zeros() {
            // `self` is zero or a negative power of two
            unsigned_bits
        } else {
            unsigned_bits + 1
        };

        bits as u32
    }

    /// Creates a `Signed` from a sign and an absolute value. Returns the value
    /// and a bool that is true if the conversion caused an overflow.
    #[inline]
    pub fn overflowing_from_sign_and_abs(sign: Sign, abs: Uint<BITS, LIMBS>) -> (Self, bool) {
        let value = Self(match sign {
            Sign::Positive => abs,
            Sign::Negative => twos_complement(abs),
        });

        (value, value.sign() != sign && value != Self::ZERO)
    }

    /// Creates a `Signed` from an absolute value and a negative flag. Returns
    /// `None` if it would overflow as `Signed`.
    #[inline]
    pub fn checked_from_sign_and_abs(sign: Sign, abs: Uint<BITS, LIMBS>) -> Option<Self> {
        let (result, overflow) = Self::overflowing_from_sign_and_abs(sign, abs);
        if overflow { None } else { Some(result) }
    }

    /// Convert from a decimal string.
    pub fn from_dec_str(value: &str) -> Result<Self, ParseSignedError> {
        let (sign, value) = match value.as_bytes().first() {
            Some(b'+') => (Sign::Positive, &value[1..]),
            Some(b'-') => (Sign::Negative, &value[1..]),
            _ => (Sign::Positive, value),
        };
        let abs = Uint::<BITS, LIMBS>::from_str_radix(value, 10)?;
        Self::checked_from_sign_and_abs(sign, abs).ok_or(ParseSignedError::IntegerOverflow)
    }

    /// Convert to a decimal string.
    pub fn to_dec_string(&self) -> String {
        let sign = self.sign();
        let abs = self.unsigned_abs();

        format!("{sign}{abs}")
    }

    /// Convert from a hex string.
    pub fn from_hex_str(value: &str) -> Result<Self, ParseSignedError> {
        let (sign, value) = match value.as_bytes().first() {
            Some(b'+') => (Sign::Positive, &value[1..]),
            Some(b'-') => (Sign::Negative, &value[1..]),
            _ => (Sign::Positive, value),
        };

        let value = value.strip_prefix("0x").unwrap_or(value);

        if value.len() > 64 {
            return Err(ParseSignedError::IntegerOverflow);
        }

        let abs = Uint::<BITS, LIMBS>::from_str_radix(value, 16)?;
        Self::checked_from_sign_and_abs(sign, abs).ok_or(ParseSignedError::IntegerOverflow)
    }

    /// Convert to a hex string.
    pub fn to_hex_string(&self) -> String {
        let sign = self.sign();
        let abs = self.unsigned_abs();

        format!("{sign}0x{abs:x}")
    }

    /// Splits a Signed into its absolute value and negative flag.
    #[inline]
    pub fn into_sign_and_abs(&self) -> (Sign, Uint<BITS, LIMBS>) {
        let sign = self.sign();
        let abs = match sign {
            Sign::Positive => self.0,
            Sign::Negative => twos_complement(self.0),
        };
        (sign, abs)
    }

    /// Converts `self` to a big-endian byte array of size exactly
    /// [`Self::BYTES`].
    ///
    /// # Panics
    ///
    /// Panics if the generic parameter `BYTES` is not exactly [`Self::BYTES`].
    /// Ideally this would be a compile time error, but this is blocked by
    /// Rust issue [#60551].
    ///
    /// [#60551]: https://github.com/rust-lang/rust/issues/60551
    #[inline]
    pub const fn to_be_bytes<const BYTES: usize>(&self) -> [u8; BYTES] {
        self.0.to_be_bytes()
    }

    /// Converts `self` to a little-endian byte array of size exactly
    /// [`Self::BYTES`].
    ///
    /// # Panics
    ///
    /// Panics if the generic parameter `BYTES` is not exactly [`Self::BYTES`].
    /// Ideally this would be a compile time error, but this is blocked by
    /// Rust issue [#60551].
    ///
    /// [#60551]: https://github.com/rust-lang/rust/issues/60551
    #[inline]
    pub const fn to_le_bytes<const BYTES: usize>(&self) -> [u8; BYTES] {
        self.0.to_le_bytes()
    }

    /// Converts a big-endian byte array of size exactly [`Self::BYTES`].
    ///
    /// # Panics
    ///
    /// Panics if the generic parameter `BYTES` is not exactly [`Self::BYTES`].
    /// Ideally this would be a compile time error, but this is blocked by
    /// Rust issue [#60551].
    ///
    /// [#60551]: https://github.com/rust-lang/rust/issues/60551
    ///
    /// Panics if the value is too large for the bit-size of the Uint.
    #[inline]
    pub const fn from_be_bytes<const BYTES: usize>(bytes: [u8; BYTES]) -> Self {
        Self(Uint::from_be_bytes::<BYTES>(bytes))
    }

    /// Convert from an array in LE format
    ///
    /// # Panics
    ///
    /// Panics if the given array is not the correct length.
    #[inline]
    #[track_caller]
    pub const fn from_le_bytes<const BYTES: usize>(bytes: [u8; BYTES]) -> Self {
        Self(Uint::from_le_bytes::<BYTES>(bytes))
    }

    /// Creates a new integer from a big endian slice of bytes.
    ///
    /// The slice is interpreted as a big endian number. Leading zeros
    /// are ignored. The slice can be any length.
    ///
    /// Returns [`None`] if the value is larger than fits the [`Uint`].
    pub fn try_from_be_slice(slice: &[u8]) -> Option<Self> {
        Uint::try_from_be_slice(slice).map(Self)
    }

    /// Creates a new integer from a little endian slice of bytes.
    ///
    /// The slice is interpreted as a big endian number. Leading zeros
    /// are ignored. The slice can be any length.
    ///
    /// Returns [`None`] if the value is larger than fits the [`Uint`].
    pub fn try_from_le_slice(slice: &[u8]) -> Option<Self> {
        Uint::try_from_le_slice(slice).map(Self)
    }

    /// View the array of limbs.
    #[inline(always)]
    #[must_use]
    pub const fn as_limbs(&self) -> &[u64; LIMBS] {
        self.0.as_limbs()
    }

    /// Convert to a array of limbs.
    ///
    /// Limbs are least significant first.
    #[inline(always)]
    pub const fn into_limbs(self) -> [u64; LIMBS] {
        self.0.into_limbs()
    }

    /// Construct a new integer from little-endian a array of limbs.
    ///
    /// # Panics
    ///
    /// Panics if `LIMBS` is not equal to `nlimbs(BITS)`.
    ///
    /// Panics if the value is to large for the bit-size of the Uint.
    #[inline(always)]
    #[track_caller]
    #[must_use]
    pub const fn from_limbs(limbs: [u64; LIMBS]) -> Self {
        Self(Uint::from_limbs(limbs))
    }

    /// Constructs the [`Signed`] from digits in the base `base` in big-endian.
    /// Wrapper around ruint's from_base_be
    ///
    /// # Errors
    ///
    /// * [`BaseConvertError::InvalidBase`] if the base is less than 2.
    /// * [`BaseConvertError::InvalidDigit`] if a digit is out of range.
    /// * [`BaseConvertError::Overflow`] if the number is too large to fit.
    pub fn from_base_be<I: IntoIterator<Item = u64>>(
        base: u64,
        digits: I,
    ) -> Result<Self, BaseConvertError> {
        Ok(Self(Uint::from_base_be(base, digits)?))
    }
}
