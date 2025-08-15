// from here https://github.com/pendle-finance/pendle-core-v2-public/blob/46d13ce4168e8c5ad9e5641dd6380fea69e48490/contracts/core/libraries/math/LogExpMath.sol

// implements structs and functions from MarketMathCore.sol
// https://github.com/pendle-finance/pendle-core-v2-public/blob/6573ff85ca28b0f4fb5f6b7e2a1468fa7d0aa00b/contracts/core/Market/MarketMathCore.sol

use crate::eth::aliases::*;


pub fn ln(a: I256) -> I256 {
    assert!(a > I256::ZERO, "ln is not defined for negative numbers and zero");
    let one_17: I256 = "100_000_000_000_000_000".parse::<I256>().unwrap();
    let one_18: I256 = "1_000_000_000_000_000_000".parse::<I256>().unwrap();

    let ln_36_lower_bound: I256 = one_18 - one_17;
    let ln_36_upper_bound: I256 = one_18 + one_17;

    if ln_36_lower_bound < a && a < ln_36_upper_bound {
        return _ln_36(a) / one_18;
    } else {
        return _ln(a);
    }
}

/**
 * @dev Intrnal high precision (36 decimal places) natural logarithm (ln(x)) with signed 18 decimal fixed point argument,
 * for x close to one.
 *
 * Should only be used if x is between LN_36_LOWER_BOUND and LN_36_UPPER_BOUND.
 */
fn _ln_36(x_inp: I256) -> I256 {
    let one_18: I256 = "1_000_000_000_000_000_000".parse::<I256>().unwrap();
    let one_36: I256 = "1__000_000_000_000_000_000_000_000_000_000_000_000".parse::<I256>().unwrap();

    let mut x = x_inp;
    // Since ln(1) = 0, a value of x close to one will yield a very small result, which makes using 36 digits
    // worthwhile.

    // First, we transform x to a 36 digit fixed point value.
    x *= one_18;

    // We will use the following Taylor expansion, which converges very rapidly. Let z = (x - 1) / (x + 1).
    // ln(x) = 2 * (z + z^3 / 3 + z^5 / 5 + z^7 / 7 + ... + z^(2 * n + 1) / (2 * n + 1))

    // Recall that 36 digit fixed point division requires multiplying by ONE_36, and multiplication requires
    // division by ONE_36.
    let z: I256 = ((x - one_36) * one_36) / (x + one_36);
    let z_squared: I256 = (z * z) / one_36;

    // num is the numerator of the series: the z^(2 * n + 1) term
    let mut num: I256 = z;

    // series_sum holds the accumulated sum of each term in the series, starting with the initial z
    let mut series_sum: I256 = num;

    // In each step, the numerator is multiplied by z^2
    num = (num * z_squared) / one_36;
    series_sum += num / I256::unchecked_from(3);

    num = (num * z_squared) / one_36;
    series_sum += num / I256::unchecked_from(5);

    num = (num * z_squared) / one_36;
    series_sum += num / I256::unchecked_from(7);

    num = (num * z_squared) / one_36;
    series_sum += num / I256::unchecked_from(9);

    num = (num * z_squared) / one_36;
    series_sum += num / I256::unchecked_from(11);

    num = (num * z_squared) / one_36;
    series_sum += num / I256::unchecked_from(13);

    num = (num * z_squared) / one_36;
    series_sum += num / I256::unchecked_from(15);

    // 8 Taylor terms are sufficient for 36 decimal precision.

    // All that remains is multiplying by 2 (non fixed point).
    return series_sum * I256::unchecked_from(2);
}

/**
 * @dev Internal natural logarithm (ln(a)) with signed 18 decimal fixed point argument.
 */
fn _ln(a_inp: I256) -> I256 {
    let one_18: I256 = "1_000_000_000_000_000_000".parse::<I256>().unwrap();
    let one_20: I256 = "100_000_000_000_000_000_000".parse::<I256>().unwrap();


    // 18 decimal constants
    let x0: I256 = "128000000000000000000".parse::<I256>().unwrap(); // 2ˆ7
    let a0: I256 = "38877084059945950922200000000000000000000000000000000000"
        .parse::<I256>()
        .unwrap(); // eˆ(x0) (no decimals)
    let x1: I256 = "64000000000000000000".parse::<I256>().unwrap(); // 2ˆ6
    let a1: I256 = "6235149080811616882910000000".parse::<I256>().unwrap(); // eˆ(x1) (no decimals)

    // 20 decimal constants
    let x2: I256 = "3200000000000000000000".parse::<I256>().unwrap(); // 2ˆ5
    let a2: I256 = "7896296018268069516100000000000000"
        .parse::<I256>()
        .unwrap(); // eˆ(x2)
    let x3: I256 = "1600000000000000000000".parse::<I256>().unwrap(); // 2ˆ4
    let a3: I256 = "888611052050787263676000000".parse::<I256>().unwrap(); // eˆ(x3)
    let x4: I256 = "800000000000000000000".parse::<I256>().unwrap(); // 2ˆ3
    let a4: I256 = "298095798704172827474000".parse::<I256>().unwrap(); // eˆ(x4)
    let x5: I256 = "400000000000000000000".parse::<I256>().unwrap(); // 2ˆ2
    let a5: I256 = "5459815003314423907810".parse::<I256>().unwrap(); // eˆ(x5)
    let x6: I256 = "200000000000000000000".parse::<I256>().unwrap(); // 2ˆ1
    let a6: I256 = "738905609893065022723".parse::<I256>().unwrap(); // eˆ(x6)
    let x7: I256 = "100000000000000000000".parse::<I256>().unwrap(); // 2ˆ0
    let a7: I256 = "271828182845904523536".parse::<I256>().unwrap(); // eˆ(x7)
    let x8: I256 = "50000000000000000000".parse::<I256>().unwrap(); // 2ˆ-1
    let a8: I256 = "164872127070012814685".parse::<I256>().unwrap(); // eˆ(x8)
    let x9: I256 = "25000000000000000000".parse::<I256>().unwrap(); // 2ˆ-2
    let a9: I256 = "128402541668774148407".parse::<I256>().unwrap(); // eˆ(x9)
    let x10: I256 = "12500000000000000000".parse::<I256>().unwrap(); // 2ˆ-3
    let a10: I256 = "113314845306682631683".parse::<I256>().unwrap(); // eˆ(x10)
    let x11: I256 = "6250000000000000000".parse::<I256>().unwrap(); // 2ˆ-4
    let a11: I256 = "106449445891785942956".parse::<I256>().unwrap(); // eˆ(x11)

    let mut a = a_inp;
    if a < one_18 {
        // Since ln(a^k) = k * ln(a), we can compute ln(a) as ln(a) = ln((1/a)^(-1)) = - ln((1/a)). If a is less
        // than one, 1/a will be greater than one, and this if statement will not be entered in the recursive call.
        // Fixed point division requires multiplying by ONE_18.
        return -_ln((one_18 * one_18) / a);
    }

    // First, we use the fact that ln^(a * b) = ln(a) + ln(b) to decompose ln(a) into a sum of powers of two, which
    // we call x_n, where x_n == 2^(7 - n), which are the natural logarithm of precomputed quantities a_n (that is,
    // ln(a_n) = x_n). We choose the first x_n, x0, to equal 2^7 because the exponential of all larger powers cannot
    // be represented as 18 fixed point decimal numbers in 256 bits, and are therefore larger than a.
    // At the end of this process we will have the sum of all x_n = ln(a_n) that apply, and the remainder of this
    // decomposition, which will be lower than the smallest a_n.
    // ln(a) = k_0 * x_0 + k_1 * x_1 + ... + k_n * x_n + ln(remainder), where each k_n equals either 0 or 1.
    // We mutate a by subtracting a_n, making it the remainder of the decomposition.

    // For reasons related to how `exp` works, the first two a_n (e^(2^7) and e^(2^6)) are not stored as fixed point
    // numbers with 18 decimals, but instead as plain integers with 0 decimals, so we need to multiply them by
    // ONE_18 to convert them to fixed point.
    // For each a_n, we test if that term is present in the decomposition (if a is larger than it), and if so divide
    // by it and compute the accumulated sum.

    let mut sum: I256 = I256::ZERO;
    if a >= a0 * one_18 {
        a /= a0; // Integer, not fixed point division
        sum += x0;
    }

    if a >= a1 * one_18 {
        a /= a1; // Integer, not fixed point division
        sum += x1;
    }

    // All other a_n and x_n are stored as 20 digit fixed point numbers, so we convert the sum and a to this format.
    sum *= I256::unchecked_from(100);
    a *= I256::unchecked_from(100);

    // Because further a_n are  20 digit fixed point numbers, we multiply by ONE_20 when dividing by them.

    if a >= a2 {
        a = (a * one_20) / a2;
        sum += x2;
    }

    if a >= a3 {
        a = (a * one_20) / a3;
        sum += x3;
    }

    if a >= a4 {
        a = (a * one_20) / a4;
        sum += x4;
    }

    if a >= a5 {
        a = (a * one_20) / a5;
        sum += x5;
    }

    if a >= a6 {
        a = (a * one_20) / a6;
        sum += x6;
    }

    if a >= a7 {
        a = (a * one_20) / a7;
        sum += x7;
    }

    if a >= a8 {
        a = (a * one_20) / a8;
        sum += x8;
    }

    if a >= a9 {
        a = (a * one_20) / a9;
        sum += x9;
    }

    if a >= a10 {
        a = (a * one_20) / a10;
        sum += x10;
    }

    if a >= a11 {
        a = (a * one_20) / a11;
        sum += x11;
    }

    // a is now a small number (smaller than a_11, which roughly equals 1.06). This means we can use a Taylor series
    // that converges rapidly for values of `a` close to one - the same one used in _ln_36.
    // Let z = (a - 1) / (a + 1).
    // ln(a) = 2 * (z + z^3 / 3 + z^5 / 5 + z^7 / 7 + ... + z^(2 * n + 1) / (2 * n + 1))

    // Recall that 20 digit fixed point division requires multiplying by ONE_20, and multiplication requires
    // division by ONE_20.
    let z: I256 = ((a - one_20) * one_20) / (a + one_20);
    let z_squared: I256 = (z * z) / one_20;

    // num is the numerator of the series: the z^(2 * n + 1) term
    let mut num: I256 = z;

    // series_sum holds the accumulated sum of each term in the series, starting with the initial z
    let mut series_sum: I256 = num;

    // In each step, the numerator is multiplied by z^2
    num = (num * z_squared) / one_20;
    series_sum += num / I256::unchecked_from(3);

    num = (num * z_squared) / one_20;
    series_sum += num / I256::unchecked_from(5);

    num = (num * z_squared) / one_20;
    series_sum += num / I256::unchecked_from(7);

    num = (num * z_squared) / one_20;
    series_sum += num / I256::unchecked_from(9);

    num = (num * z_squared) / one_20;
    series_sum += num / I256::unchecked_from(11);

    // 6 Taylor terms are sufficient for 36 decimal precision.

    // Finally, we multiply by 2 (non fixed point) to compute ln(remainder)
    series_sum *= I256::unchecked_from(2);

    // We now have the sum of all x_n present, and the Taylor approximation of the logarithm of the remainder (both
    // with 20 decimals). All that remains is to sum these two, and then drop two digits to return a 18 decimal
    // value.

    return (sum + series_sum) / I256::unchecked_from(100);
}

/**
 * @dev Natural exponentiation (e^x) with signed 18 decimal fixed point exponent.
 *
 * Reverts if `x` is smaller than MIN_NATURAL_EXPONENT, or larger than `MAX_NATURAL_EXPONENT`.
 */
pub fn exp(x_inp: I256) -> I256 {
    let one_18: I256 = "1_000_000_000_000_000_000".parse::<I256>().unwrap();
    let one_20: I256 = "100_000_000_000_000_000_000".parse::<I256>().unwrap();

    // The domain of natural exponentiation is bound by the word size and number of decimals used.
    //
    // Because internally the result will be stored using 20 decimals, the largest possible result is
    // (2^255 - 1) / 10^20, which makes the largest exponent ln((2^255 - 1) / 10^20) = 130.700829182905140221.
    // The smallest possible result is 10^(-18), which makes largest negative argument
    // ln(10^(-18)) = -41.446531673892822312.
    // We use 130.0 and -41.0 to have some safety margin.
    let max_natural_exponent: I256 = "130".parse::<I256>().unwrap() * one_18;
    let min_natural_exponent: I256 = "-41".parse::<I256>().unwrap() * one_18;

    // 18 decimal constants
    let x0: I256 = "128000000000000000000".parse::<I256>().unwrap(); // 2ˆ7
    let a0: I256 = "38877084059945950922200000000000000000000000000000000000"
        .parse::<I256>()
        .unwrap(); // eˆ(x0) (no decimals)
    let x1: I256 = "64000000000000000000".parse::<I256>().unwrap(); // 2ˆ6
    let a1: I256 = "6235149080811616882910000000".parse::<I256>().unwrap(); // eˆ(x1) (no decimals)

    // 20 decimal constants
    let x2: I256 = "3200000000000000000000".parse::<I256>().unwrap(); // 2ˆ5
    let a2: I256 = "7896296018268069516100000000000000"
        .parse::<I256>()
        .unwrap(); // eˆ(x2)
    let x3: I256 = "1600000000000000000000".parse::<I256>().unwrap(); // 2ˆ4
    let a3: I256 = "888611052050787263676000000".parse::<I256>().unwrap(); // eˆ(x3)
    let x4: I256 = "800000000000000000000".parse::<I256>().unwrap(); // 2ˆ3
    let a4: I256 = "298095798704172827474000".parse::<I256>().unwrap(); // eˆ(x4)
    let x5: I256 = "400000000000000000000".parse::<I256>().unwrap(); // 2ˆ2
    let a5: I256 = "5459815003314423907810".parse::<I256>().unwrap(); // eˆ(x5)
    let x6: I256 = "200000000000000000000".parse::<I256>().unwrap(); // 2ˆ1
    let a6: I256 = "738905609893065022723".parse::<I256>().unwrap(); // eˆ(x6)
    let x7: I256 = "100000000000000000000".parse::<I256>().unwrap(); // 2ˆ0
    let a7: I256 = "271828182845904523536".parse::<I256>().unwrap(); // eˆ(x7)
    let x8: I256 = "50000000000000000000".parse::<I256>().unwrap(); // 2ˆ-1
    let a8: I256 = "164872127070012814685".parse::<I256>().unwrap(); // eˆ(x8)
    let x9: I256 = "25000000000000000000".parse::<I256>().unwrap(); // 2ˆ-2
    let a9: I256 = "128402541668774148407".parse::<I256>().unwrap(); // eˆ(x9)

    let mut x = x_inp;

    assert!(
        x >= min_natural_exponent && x <= max_natural_exponent,
        "Invalid exponent"
    );

    if x < I256::ZERO {
        // We only handle positive exponents: e^(-x) is computed as 1 / e^x. We can safely make x positive since it
        // fits in the signed 256 bit range (as it is larger than MIN_NATURAL_EXPONENT).
        // Fixed point division requires multiplying by ONE_18.
        return (one_18 * one_18) / exp(-x);
    }

    // First, we use the fact that e^(x+y) = e^x * e^y to decompose x into a sum of powers of two, which we call x_n,
    // where x_n == 2^(7 - n), and e^x_n = a_n has been precomputed. We choose the first x_n, x0, to equal 2^7
    // because all larger powers are larger than MAX_NATURAL_EXPONENT, and therefore not present in the
    // decomposition.
    // At the end of this process we will have the product of all e^x_n = a_n that apply, and the remainder of this
    // decomposition, which will be lower than the smallest x_n.
    // exp(x) = k_0 * a_0 * k_1 * a_1 * ... + k_n * a_n * exp(remainder), where each k_n equals either 0 or 1.
    // We mutate x by subtracting x_n, making it the remainder of the decomposition.

    // The first two a_n (e^(2^7) and e^(2^6)) are too large if stored as 18 decimal numbers, and could cause
    // intermediate overflows. Instead we store them as plain integers, with 0 decimals.
    // Additionally, x0 + x1 is larger than MAX_NATURAL_EXPONENT, which means they will not both be present in the
    // decomposition.

    // For each x_n, we test if that term is present in the decomposition (if x is larger than it), and if so deduct
    // it and compute the accumulated product.

    let first_an: I256;
    if x >= x0 {
        x -= x0;
        first_an = a0;
    } else if x >= x1 {
        x -= x1;
        first_an = a1;
    } else {
        first_an = I256::ONE; // One with no decimal places
    }

    // We now transform x into a 20 decimal fixed point number, to have enhanced precision when computing the
    // smaller terms.
    x *= I256::unchecked_from(100);

    // `product` is the accumulated product of all a_n (except a0 and a1), which starts at 20 decimal fixed point
    // one. Recall that fixed point multiplication requires dividing by ONE_20.
    let mut product: I256 = one_20;

    if x >= x2 {
        x -= x2;
        product = (product * a2) / one_20;
    }
    if x >= x3 {
        x -= x3;
        product = (product * a3) / one_20;
    }
    if x >= x4 {
        x -= x4;
        product = (product * a4) / one_20;
    }
    if x >= x5 {
        x -= x5;
        product = (product * a5) / one_20;
    }
    if x >= x6 {
        x -= x6;
        product = (product * a6) / one_20;
    }
    if x >= x7 {
        x -= x7;
        product = (product * a7) / one_20;
    }
    if x >= x8 {
        x -= x8;
        product = (product * a8) / one_20;
    }
    if x >= x9 {
        x -= x9;
        product = (product * a9) / one_20;
    }

    // x10 and x11 are unnecessary here since we have high enough precision already.

    // Now we need to compute e^x, where x is small (in particular, it is smaller than x9). We use the Taylor series
    // expansion for e^x: 1 + x + (x^2 / 2!) + (x^3 / 3!) + ... + (x^n / n!).

    let mut series_sum: I256 = one_20; // The initial one in the sum, with 20 decimal places.
    let mut term: I256; // Each term in the sum, where the nth term is (x^n / n!).

    // The first term is simply x.
    term = x;
    series_sum += term;

    // Each term (x^n / n!) equals the previous one times x, divided by n. Since x is a fixed point number,
    // multiplying by it requires dividing by ONE_20, but dividing by the non-fixed point n values does not.

    term = ((term * x) / one_20) / I256::unchecked_from(2);
    series_sum += term;

    term = ((term * x) / one_20) / I256::unchecked_from(3);
    series_sum += term;

    term = ((term * x) / one_20) / I256::unchecked_from(4);
    series_sum += term;

    term = ((term * x) / one_20) / I256::unchecked_from(5);
    series_sum += term;

    term = ((term * x) / one_20) / I256::unchecked_from(6);
    series_sum += term;

    term = ((term * x) / one_20) / I256::unchecked_from(7);
    series_sum += term;

    term = ((term * x) / one_20) / I256::unchecked_from(8);
    series_sum += term;

    term = ((term * x) / one_20) / I256::unchecked_from(9);
    series_sum += term;

    term = ((term * x) / one_20) / I256::unchecked_from(10);
    series_sum += term;

    term = ((term * x) / one_20) / I256::unchecked_from(11);
    series_sum += term;

    term = ((term * x) / one_20) / I256::unchecked_from(12);
    series_sum += term;

    // 12 Taylor terms are sufficient for 18 decimal precision.

    // We now have the first a_n (with no decimals), and the product of all other a_n present, and the Taylor
    // approximation of the exponentiation of the remainder (both with 20 decimals). All that remains is to multiply
    // all three (one 20 decimal fixed point multiplication, dividing by ONE_20, and one integer multiplication),
    // and then drop two digits to return an 18 decimal value.

    return (((product * series_sum) / one_20) * first_an) / I256::unchecked_from(100);
}
