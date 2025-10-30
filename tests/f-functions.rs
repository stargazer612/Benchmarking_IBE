use ibe_schemes::f_functions::*;

#[test]
fn test_f_0() {
    let l = 128;
    let msg = [];
    assert_eq!(f_i(0, l, &msg), 0);
}

#[test]
fn test_f_1() {
    let l = 128;
    let msg = [];
    assert_eq!(f_i(1, l, &msg), 0);
}

#[test]
fn test_f_i_larger_than_l() {
    let l = 128;
    let msg = [];
    // (258 - 2)/2 = 128 >= l
    assert_eq!(f_i(258, l, &msg), 0);
}

#[test]
fn test_f_i_larger_than_msg() {
    let l = 128;
    let msg = [0, 1, 2, 3, 4, 5];
    // (128 - 2)/2 = 63 < l, but 63 > msg.len()*8
    assert_eq!(f_i(128, l, &msg), 0);
}

#[test]
fn test_f_n() {
    let l = 128;
    let msg = [
        8, 150, 201, 77, 104, 204, 30, 51, 189, 255, 234, 17, 48, 111, 0, 1,
    ];
    assert_eq!(f_i(6, l, &msg), 1);
    assert_eq!(f_i(35, l, &msg), 1);
    assert_eq!(f_i(100, l, &msg), 0);
    assert_eq!(f_i(159, l, &msg), 1);
    assert_eq!(f_i(201, l, &msg), 0);
    assert_eq!(f_i(257, l, &msg), 0);
}

#[test]
fn test_f_prime_0() {
    assert_eq!(f_prime_i(0), 1);
}

#[test]
fn test_f_prime_1() {
    assert_eq!(f_prime_i(1), 0);
}

#[test]
fn test_f_prime_n() {
    assert_eq!(f_prime_i(2), 0);
    assert_eq!(f_prime_i(5), 0);
    assert_eq!(f_prime_i(94), 0);
    assert_eq!(f_prime_i(1354154), 0);
}
