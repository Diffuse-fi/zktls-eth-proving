use super::{
    utils::{handle_overflow, twos_complement},
    Sign, Signed,
};
use core::{cmp, ops};
use ruint::Uint;

// ops impl
impl<const BITS: usize, const LIMBS: usize> Signed<BITS, LIMBS> {
    /// Computes the absolute value of `self`.
    ///
    /// # Overflow behavior
    ///
    /// The absolute value of `Self::MIN` cannot be represented as `Self` and
    /// attempting to calculate it will cause an overflow. This means that code
    /// in debug mode will trigger a panic on this case and optimized code will
    /// return `Self::MIN` without a panic.
    #[inline]
    #[track_caller]
    #[must_use]
    pub fn abs(self) -> Self {
        handle_overflow(self.overflowing_abs())
    }

    /// Computes the absolute value of `self`.
    ///
    /// Returns a tuple of the absolute version of self along with a boolean
    /// indicating whether an overflow happened. If self is the minimum
    /// value then the minimum value will be returned again and true will be
    /// returned for an overflow happening.
    #[inline]
    #[must_use]
    pub fn overflowing_abs(self) -> (Self, bool) {
        if BITS == 0 {
            return (self, false);
        }
        if self == Self::MIN {
            (self, true)
        } else {
            (Self(self.unsigned_abs()), false)
        }
    }

    /// Computes the absolute value of `self` without any wrapping or panicking.
    #[inline]
    #[must_use]
    pub fn unsigned_abs(self) -> Uint<BITS, LIMBS> {
        self.into_sign_and_abs().1
    }

    /// Negates self, overflowing if this is equal to the minimum value.
    ///
    /// Returns a tuple of the negated version of self along with a boolean
    /// indicating whether an overflow happened. If `self` is the minimum
    /// value, then the minimum value will be returned again and `true` will
    /// be returned for an overflow happening.
    #[inline]
    #[must_use]
    pub fn overflowing_neg(self) -> (Self, bool) {
        if BITS == 0 {
            return (self, false);
        }
        if self == Self::MIN {
            (self, true)
        } else {
            (Self(twos_complement(self.0)), false)
        }
    }

    /// Checked negation. Computes `-self`, returning `None` if `self == MIN`.
    #[inline]
    #[must_use]
    pub fn checked_neg(self) -> Option<Self> {
        match self.overflowing_neg() {
            (value, false) => Some(value),
            _ => None,
        }
    }

    /// Saturating negation. Computes `-self`, returning `MAX` if `self == MIN`
    /// instead of overflowing.
    #[inline]
    #[must_use]
    pub fn saturating_neg(self) -> Self {
        match self.overflowing_neg() {
            (value, false) => value,
            _ => Self::MAX,
        }
    }

    /// Wrapping (modular) negation. Computes `-self`, wrapping around at the
    /// boundary of the type.
    ///
    /// The only case where such wrapping can occur is when one negates `MIN` on
    /// a signed type (where `MIN` is the negative minimal value for the
    /// type); this is a positive value that is too large to represent in
    /// the type. In such a case, this function returns `MIN` itself.
    #[inline]
    #[must_use]
    pub fn wrapping_neg(self) -> Self {
        self.overflowing_neg().0
    }

    /// Calculates `self` + `rhs`
    ///
    /// Returns a tuple of the addition along with a boolean indicating whether
    /// an arithmetic overflow would occur. If an overflow would have
    /// occurred then the wrapped value is returned.
    #[inline]
    #[must_use]
    pub const fn overflowing_add(self, rhs: Self) -> (Self, bool) {
        let (unsigned, _) = self.0.overflowing_add(rhs.0);
        let result = Self(unsigned);

        // NOTE: Overflow is determined by checking the sign of the operands and
        //   the result.
        let overflow = matches!(
            (self.sign(), rhs.sign(), result.sign()),
            (Sign::Positive, Sign::Positive, Sign::Negative)
                | (Sign::Negative, Sign::Negative, Sign::Positive)
        );

        (result, overflow)
    }

    /// Checked integer addition. Computes `self + rhs`, returning `None` if
    /// overflow occurred.
    #[inline]
    #[must_use]
    pub const fn checked_add(self, rhs: Self) -> Option<Self> {
        match self.overflowing_add(rhs) {
            (value, false) => Some(value),
            _ => None,
        }
    }

    /// Saturating integer addition. Computes `self + rhs`, saturating at the
    /// numeric bounds instead of overflowing.
    #[inline]
    #[must_use]
    pub const fn saturating_add(self, rhs: Self) -> Self {
        let (result, overflow) = self.overflowing_add(rhs);
        if overflow {
            match result.sign() {
                Sign::Positive => Self::MIN,
                Sign::Negative => Self::MAX,
            }
        } else {
            result
        }
    }

    /// Wrapping (modular) addition. Computes `self + rhs`, wrapping around at
    /// the boundary of the type.
    #[inline]
    #[must_use]
    pub const fn wrapping_add(self, rhs: Self) -> Self {
        self.overflowing_add(rhs).0
    }

    /// Calculates `self` - `rhs`
    ///
    /// Returns a tuple of the subtraction along with a boolean indicating
    /// whether an arithmetic overflow would occur. If an overflow would
    /// have occurred then the wrapped value is returned.
    #[inline]
    #[must_use]
    pub const fn overflowing_sub(self, rhs: Self) -> (Self, bool) {
        // NOTE: We can't just compute the `self + (-rhs)` because `-rhs` does
        //   not always exist, specifically this would be a problem in case
        //   `rhs == Self::MIN`

        let (unsigned, _) = self.0.overflowing_sub(rhs.0);
        let result = Self(unsigned);

        // NOTE: Overflow is determined by checking the sign of the operands and
        //   the result.
        let overflow = matches!(
            (self.sign(), rhs.sign(), result.sign()),
            (Sign::Positive, Sign::Negative, Sign::Negative)
                | (Sign::Negative, Sign::Positive, Sign::Positive)
        );

        (result, overflow)
    }

    /// Checked integer subtraction. Computes `self - rhs`, returning `None` if
    /// overflow occurred.
    #[inline]
    #[must_use]
    pub const fn checked_sub(self, rhs: Self) -> Option<Self> {
        match self.overflowing_sub(rhs) {
            (value, false) => Some(value),
            _ => None,
        }
    }

    /// Saturating integer subtraction. Computes `self - rhs`, saturating at the
    /// numeric bounds instead of overflowing.
    #[inline]
    #[must_use]
    pub const fn saturating_sub(self, rhs: Self) -> Self {
        let (result, overflow) = self.overflowing_sub(rhs);
        if overflow {
            match result.sign() {
                Sign::Positive => Self::MIN,
                Sign::Negative => Self::MAX,
            }
        } else {
            result
        }
    }

    /// Wrapping (modular) subtraction. Computes `self - rhs`, wrapping around
    /// at the boundary of the type.
    #[inline]
    #[must_use]
    pub const fn wrapping_sub(self, rhs: Self) -> Self {
        self.overflowing_sub(rhs).0
    }

    /// Calculates `self` * `rhs`
    ///
    /// Returns a tuple of the multiplication along with a boolean indicating
    /// whether an arithmetic overflow would occur. If an overflow would
    /// have occurred then the wrapped value is returned.
    #[inline]
    #[must_use]
    pub fn overflowing_mul(self, rhs: Self) -> (Self, bool) {
        if self.is_zero() || rhs.is_zero() {
            return (Self::ZERO, false);
        }
        let sign = self.sign() * rhs.sign();
        let (unsigned, overflow_mul) = self.unsigned_abs().overflowing_mul(rhs.unsigned_abs());
        let (result, overflow_conv) = Self::overflowing_from_sign_and_abs(sign, unsigned);

        (result, overflow_mul || overflow_conv)
    }

    /// Checked integer multiplication. Computes `self * rhs`, returning None if
    /// overflow occurred.
    #[inline]
    #[must_use]
    pub fn checked_mul(self, rhs: Self) -> Option<Self> {
        match self.overflowing_mul(rhs) {
            (value, false) => Some(value),
            _ => None,
        }
    }

    /// Saturating integer multiplication. Computes `self * rhs`, saturating at
    /// the numeric bounds instead of overflowing.
    #[inline]
    #[must_use]
    pub fn saturating_mul(self, rhs: Self) -> Self {
        let (result, overflow) = self.overflowing_mul(rhs);
        if overflow {
            match self.sign() * rhs.sign() {
                Sign::Positive => Self::MAX,
                Sign::Negative => Self::MIN,
            }
        } else {
            result
        }
    }

    /// Wrapping (modular) multiplication. Computes `self * rhs`, wrapping
    /// around at the boundary of the type.
    #[inline]
    #[must_use]
    pub fn wrapping_mul(self, rhs: Self) -> Self {
        self.overflowing_mul(rhs).0
    }

    /// Calculates `self` / `rhs`
    ///
    /// Returns a tuple of the divisor along with a boolean indicating whether
    /// an arithmetic overflow would occur. If an overflow would occur then
    /// self is returned.
    ///
    /// # Panics
    ///
    /// If `rhs` is 0.
    #[inline]
    #[track_caller]
    #[must_use]
    pub fn overflowing_div(self, rhs: Self) -> (Self, bool) {
        assert!(!rhs.is_zero(), "attempt to divide by zero");
        let sign = self.sign() * rhs.sign();
        // Note, signed division can't overflow!
        let unsigned = self.unsigned_abs() / rhs.unsigned_abs();
        let (result, overflow_conv) = Self::overflowing_from_sign_and_abs(sign, unsigned);

        (result, overflow_conv && !result.is_zero())
    }

    /// Checked integer division. Computes `self / rhs`, returning `None` if
    /// `rhs == 0` or the division results in overflow.
    #[inline]
    #[must_use]
    pub fn checked_div(self, rhs: Self) -> Option<Self> {
        if rhs.is_zero() || (self == Self::MIN && rhs == Self::MINUS_ONE) {
            None
        } else {
            Some(self.overflowing_div(rhs).0)
        }
    }

    /// Saturating integer division. Computes `self / rhs`, saturating at the
    /// numeric bounds instead of overflowing.
    ///
    /// # Panics
    ///
    /// If `rhs` is 0.
    #[inline]
    #[track_caller]
    #[must_use]
    pub fn saturating_div(self, rhs: Self) -> Self {
        match self.overflowing_div(rhs) {
            (value, false) => value,
            // MIN / -1 is the only possible saturating overflow
            _ => Self::MAX,
        }
    }

    /// Wrapping (modular) division. Computes `self / rhs`, wrapping around at
    /// the boundary of the type.
    ///
    /// The only case where such wrapping can occur is when one divides `MIN /
    /// -1` on a signed type (where `MIN` is the negative minimal value for
    /// the type); this is equivalent to `-MIN`, a positive value that is
    /// too large to represent in the type. In such a case, this function
    /// returns `MIN` itself.
    ///
    /// # Panics
    ///
    /// If `rhs` is 0.
    #[inline]
    #[track_caller]
    #[must_use]
    pub fn wrapping_div(self, rhs: Self) -> Self {
        self.overflowing_div(rhs).0
    }
}

// cmp
impl<const BITS: usize, const LIMBS: usize> cmp::PartialOrd for Signed<BITS, LIMBS> {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<const BITS: usize, const LIMBS: usize> cmp::Ord for Signed<BITS, LIMBS> {
    #[inline]
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        // TODO(nlordell): Once subtraction is implemented:
        // self.saturating_sub(*other).signum64().partial_cmp(&0)

        use cmp::Ordering::*;
        use Sign::*;

        match (self.into_sign_and_abs(), other.into_sign_and_abs()) {
            ((Positive, _), (Negative, _)) => Greater,
            ((Negative, _), (Positive, _)) => Less,
            ((Positive, this), (Positive, other)) => this.cmp(&other),
            ((Negative, this), (Negative, other)) => other.cmp(&this),
        }
    }
}

// arithmetic ops - implemented above
impl<T, const BITS: usize, const LIMBS: usize> ops::Add<T> for Signed<BITS, LIMBS>
where
    T: Into<Self>,
{
    type Output = Self;

    #[inline]
    #[track_caller]
    fn add(self, rhs: T) -> Self::Output {
        handle_overflow(self.overflowing_add(rhs.into()))
    }
}

impl<T, const BITS: usize, const LIMBS: usize> ops::AddAssign<T> for Signed<BITS, LIMBS>
where
    T: Into<Self>,
{
    #[inline]
    #[track_caller]
    fn add_assign(&mut self, rhs: T) {
        *self = *self + rhs;
    }
}

impl<T, const BITS: usize, const LIMBS: usize> ops::Sub<T> for Signed<BITS, LIMBS>
where
    T: Into<Self>,
{
    type Output = Self;

    #[inline]
    #[track_caller]
    fn sub(self, rhs: T) -> Self::Output {
        handle_overflow(self.overflowing_sub(rhs.into()))
    }
}

impl<T, const BITS: usize, const LIMBS: usize> ops::SubAssign<T> for Signed<BITS, LIMBS>
where
    T: Into<Self>,
{
    #[inline]
    #[track_caller]
    fn sub_assign(&mut self, rhs: T) {
        *self = *self - rhs;
    }
}

impl<T, const BITS: usize, const LIMBS: usize> ops::Mul<T> for Signed<BITS, LIMBS>
where
    T: Into<Self>,
{
    type Output = Self;

    #[inline]
    #[track_caller]
    fn mul(self, rhs: T) -> Self::Output {
        handle_overflow(self.overflowing_mul(rhs.into()))
    }
}

impl<T, const BITS: usize, const LIMBS: usize> ops::MulAssign<T> for Signed<BITS, LIMBS>
where
    T: Into<Self>,
{
    #[inline]
    #[track_caller]
    fn mul_assign(&mut self, rhs: T) {
        *self = *self * rhs;
    }
}

impl<T, const BITS: usize, const LIMBS: usize> ops::Div<T> for Signed<BITS, LIMBS>
where
    T: Into<Self>,
{
    type Output = Self;

    #[inline]
    #[track_caller]
    fn div(self, rhs: T) -> Self::Output {
        handle_overflow(self.overflowing_div(rhs.into()))
    }
}

impl<T, const BITS: usize, const LIMBS: usize> ops::DivAssign<T> for Signed<BITS, LIMBS>
where
    T: Into<Self>,
{
    #[inline]
    #[track_caller]
    fn div_assign(&mut self, rhs: T) {
        *self = *self / rhs;
    }
}

// unary ops
impl<const BITS: usize, const LIMBS: usize> ops::Neg for Signed<BITS, LIMBS> {
    type Output = Self;

    #[inline]
    #[track_caller]
    fn neg(self) -> Self::Output {
        handle_overflow(self.overflowing_neg())
    }
}
