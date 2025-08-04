// from here https://github.com/pendle-finance/pendle-core-v2-public/blob/46d13ce4168e8c5ad9e5641dd6380fea69e48490/contracts/core/libraries/math/LogExpMath.sol

use crate::eth::aliases::*;

pub fn ln(a: I256) -> I256 {
    assert!(
        a > I256::ZERO,
        "ln is not defined for negative numbers and zero"
    );
    let one_17: I256 = I256::from_limbs([100_000_000_000_000_000u64, 0, 0, 0]);
    let one_18: I256 = I256::from_limbs([1_000_000_000_000_000_000u64, 0, 0, 0]);

    let ln_36_lower_bound: I256 = one_18 - one_17;
    let ln_36_upper_bound: I256 = one_18 + one_17;

    if ln_36_lower_bound < a && a < ln_36_upper_bound {
        _ln_36(a) / one_18
    } else {
        _ln(a)
    }
}

fn _ln_36(x_inp: I256) -> I256 {
    let one_18: I256 = I256::from_limbs([1_000_000_000_000_000_000u64, 0, 0, 0]);
    let one_36: I256 = "1__000_000_000_000_000_000_000_000_000_000_000_000"
        .parse::<I256>()
        .unwrap();

    let mut x = x_inp;

    x *= one_18;

    let z: I256 = ((x - one_36) * one_36) / (x + one_36);
    let z_squared: I256 = (z * z) / one_36;

    let mut num: I256 = z;

    let mut series_sum: I256 = num;

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

    series_sum * I256::unchecked_from(2)
}

fn _ln(a_inp: I256) -> I256 {
    let one_18: I256 = I256::from_limbs([1_000_000_000_000_000_000u64, 0, 0, 0]);
    let one_20: I256 = "100_000_000_000_000_000_000".parse::<I256>().unwrap();

    let x0: I256 = "128000000000000000000".parse::<I256>().unwrap(); // 2ˆ7
    let a0: I256 = "38877084059945950922200000000000000000000000000000000000"
        .parse::<I256>()
        .unwrap(); // eˆ(x0) (no decimals)
    let x1: I256 = "64000000000000000000".parse::<I256>().unwrap(); // 2ˆ6
    let a1: I256 = "6235149080811616882910000000".parse::<I256>().unwrap(); // eˆ(x1) (no decimals)

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
        return -_ln((one_18 * one_18) / a);
    }

    let mut sum: I256 = I256::ZERO;
    if a >= a0 * one_18 {
        a /= a0; // Integer, not fixed point division
        sum += x0;
    }

    if a >= a1 * one_18 {
        a /= a1; // Integer, not fixed point division
        sum += x1;
    }

    sum *= I256::unchecked_from(100);
    a *= I256::unchecked_from(100);

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

    let z: I256 = ((a - one_20) * one_20) / (a + one_20);
    let z_squared: I256 = (z * z) / one_20;

    let mut num: I256 = z;

    let mut series_sum: I256 = num;

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

    series_sum *= I256::unchecked_from(2);

    (sum + series_sum) / I256::unchecked_from(100)
}

pub fn exp(x_inp: I256) -> I256 {
    let one_18: I256 = I256::from_limbs([1_000_000_000_000_000_000u64, 0, 0, 0]);
    let one_20: I256 = "100_000_000_000_000_000_000".parse::<I256>().unwrap();

    let max_natural_exponent: I256 = "130".parse::<I256>().unwrap() * one_18;
    let min_natural_exponent: I256 = "-41".parse::<I256>().unwrap() * one_18;

    let x0: I256 = "128000000000000000000".parse::<I256>().unwrap(); // 2ˆ7
    let a0: I256 = "38877084059945950922200000000000000000000000000000000000"
        .parse::<I256>()
        .unwrap(); // eˆ(x0) (no decimals)
    let x1: I256 = "64000000000000000000".parse::<I256>().unwrap(); // 2ˆ6
    let a1: I256 = "6235149080811616882910000000".parse::<I256>().unwrap(); // eˆ(x1) (no decimals)

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
        return (one_18 * one_18) / exp(-x);
    }

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

    x *= I256::unchecked_from(100);

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

    let mut series_sum: I256 = one_20; // The initial one in the sum, with 20 decimal places.
    let mut term: I256; // Each term in the sum, where the nth term is (x^n / n!).

    term = x;
    series_sum += term;

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

    (((product * series_sum) / one_20) * first_an) / I256::unchecked_from(100)
}
