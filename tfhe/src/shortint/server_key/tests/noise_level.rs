use crate::shortint::ciphertext::NoiseLevel;
use crate::shortint::keycache::KEY_CACHE;
use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
use crate::shortint::{Ciphertext, ServerKey};

fn test_1_ct_noise_level_propagation(sk: &ServerKey, ct: &Ciphertext) {
    let test_fn = |f: &dyn Fn(&ServerKey, &Ciphertext) -> Ciphertext,
                   g: &dyn Fn(NoiseLevel) -> NoiseLevel| {
        assert!(f(sk, ct).noise_level == g(ct.noise_level));
    };

    test_fn(&ServerKey::unchecked_neg, &|a| a);
    test_fn(
        &|sk, ct| ServerKey::unchecked_neg_with_correcting_term(sk, ct).0,
        &|a| a,
    );

    let acc = sk.generate_lookup_table(|_| 0);

    test_fn(
        &|sk, ct| ServerKey::apply_lookup_table(sk, ct, &acc),
        &|_| NoiseLevel::NOMINAL,
    );
}

fn test_1_ct_assign_noise_level_propagation(sk: &ServerKey, ct: &Ciphertext) {
    let test_fn = |f: &dyn Fn(&ServerKey, &mut Ciphertext),
                   g: &dyn Fn(NoiseLevel) -> NoiseLevel| {
        let mut clone = ct.clone();
        f(sk, &mut clone);
        assert!(clone.noise_level == g(ct.noise_level));
    };

    test_fn(&ServerKey::unchecked_neg_assign, &|a| a);
    test_fn(
        &|sk, ct| {
            ServerKey::unchecked_neg_assign_with_correcting_term(sk, ct);
        },
        &|a| a,
    );

    let acc = sk.generate_lookup_table(|_| 0);

    test_fn(
        &|sk, ct| ServerKey::apply_lookup_table_assign(sk, ct, &acc),
        &|_| NoiseLevel::NOMINAL,
    );
}

fn test_2_ct_noise_level_propagation(sk: &ServerKey, ct1: &Ciphertext, ct2: &Ciphertext) {
    let test_fn = |f: &dyn Fn(&ServerKey, &Ciphertext, &Ciphertext) -> Ciphertext,
                   g: &dyn Fn(NoiseLevel, NoiseLevel) -> NoiseLevel| {
        assert!(f(sk, ct1, ct2).noise_level == g(ct1.noise_level, ct2.noise_level));
    };

    test_fn(&ServerKey::unchecked_add, &|a, b| a + b);
    test_fn(&ServerKey::unchecked_sub, &|a, b| a + b);
    test_fn(
        &|sk, ct1, ct2| ServerKey::unchecked_sub_with_correcting_term(sk, ct1, ct2).0,
        &|a, b| a + b,
    );

    let any_trivially_encrypted = ct1.degree.0 == 0 || ct2.degree.0 == 0;
    test_fn(&ServerKey::unchecked_mul_lsb, &|_, _| {
        if any_trivially_encrypted {
            NoiseLevel::ZERO
        } else {
            NoiseLevel::NOMINAL
        }
    });
    test_fn(&ServerKey::unchecked_mul_msb, &|_, _| {
        if any_trivially_encrypted {
            NoiseLevel::ZERO
        } else {
            NoiseLevel::NOMINAL
        }
    });

    test_fn(&ServerKey::unchecked_div, &|_, _| NoiseLevel::NOMINAL);
    test_fn(&ServerKey::unchecked_bitand, &|_, _| NoiseLevel::NOMINAL);
    test_fn(&ServerKey::unchecked_bitor, &|_, _| NoiseLevel::NOMINAL);
    test_fn(&ServerKey::unchecked_bitxor, &|_, _| NoiseLevel::NOMINAL);
    test_fn(&ServerKey::unchecked_equal, &|_, _| NoiseLevel::NOMINAL);
    test_fn(&ServerKey::unchecked_mul_lsb_small_carry, &|_, _| {
        NoiseLevel::NOMINAL * 2
    });
    test_fn(&ServerKey::unchecked_greater, &|_, _| NoiseLevel::NOMINAL);
    test_fn(&ServerKey::unchecked_greater_or_equal, &|_, _| {
        NoiseLevel::NOMINAL
    });
    test_fn(&ServerKey::unchecked_less, &|_, _| NoiseLevel::NOMINAL);
    test_fn(&ServerKey::unchecked_less_or_equal, &|_, _| {
        NoiseLevel::NOMINAL
    });
    test_fn(&ServerKey::unchecked_not_equal, &|_, _| NoiseLevel::NOMINAL);
    test_fn(
        &|sk, ct1, ct2| ServerKey::unchecked_evaluate_bivariate_function(sk, ct1, ct2, |_, _| 0),
        &|_, _| NoiseLevel::NOMINAL,
    );
}

fn test_2_ct_assign_noise_level_propagation(sk: &ServerKey, ct1: &Ciphertext, ct2: &Ciphertext) {
    let test_fn = |f: &dyn Fn(&ServerKey, &mut Ciphertext, &Ciphertext),
                   g: &dyn Fn(NoiseLevel, NoiseLevel) -> NoiseLevel| {
        let mut clone = ct1.clone();
        f(sk, &mut clone, ct2);
        assert!(clone.noise_level == g(ct1.noise_level, ct2.noise_level));
    };

    test_fn(&ServerKey::unchecked_add_assign, &|a, b| a + b);
    test_fn(&ServerKey::unchecked_sub_assign, &|a, b| a + b);
    test_fn(
        &|sk, ct1, ct2| {
            ServerKey::unchecked_sub_with_correcting_term_assign(sk, ct1, ct2);
        },
        &|a, b| a + b,
    );

    let any_trivially_encrypted = ct1.degree.0 == 0 || ct2.degree.0 == 0;
    test_fn(&ServerKey::unchecked_mul_lsb_assign, &|_, _| {
        if any_trivially_encrypted {
            NoiseLevel::ZERO
        } else {
            NoiseLevel::NOMINAL
        }
    });
    test_fn(&ServerKey::unchecked_mul_msb_assign, &|_, _| {
        if any_trivially_encrypted {
            NoiseLevel::ZERO
        } else {
            NoiseLevel::NOMINAL
        }
    });

    test_fn(&ServerKey::unchecked_div_assign, &|_, _| {
        NoiseLevel::NOMINAL
    });
    test_fn(&ServerKey::unchecked_bitand_assign, &|_, _| {
        NoiseLevel::NOMINAL
    });
    test_fn(&ServerKey::unchecked_bitor_assign, &|_, _| {
        NoiseLevel::NOMINAL
    });
    test_fn(&ServerKey::unchecked_bitxor_assign, &|_, _| {
        NoiseLevel::NOMINAL
    });

    test_fn(&ServerKey::unchecked_mul_lsb_small_carry_assign, &|_, _| {
        NoiseLevel::NOMINAL * 2
    });
    test_fn(
        &|sk, ct1, ct2| {
            ServerKey::unchecked_evaluate_bivariate_function_assign(sk, ct1, ct2, |_, _| 0)
        },
        &|_, _| NoiseLevel::NOMINAL,
    );
}

fn test_1_ct_1_scalar_noise_level_propagation(sk: &ServerKey, ct: &Ciphertext, scalar: u8) {
    let test_fn = |f: &dyn Fn(&ServerKey, &Ciphertext, u8) -> Ciphertext,
                   g: &dyn Fn(NoiseLevel, u8) -> NoiseLevel| {
        assert!(f(sk, ct, scalar).noise_level == g(ct.noise_level, scalar));
    };

    test_fn(&ServerKey::unchecked_scalar_add, &|a, _| a);
    test_fn(&ServerKey::unchecked_scalar_sub, &|a, _| a);
    test_fn(&ServerKey::unchecked_scalar_mul, &|a, b| a * b as usize);
    if scalar != 0 {
        test_fn(&ServerKey::unchecked_scalar_div, &|_, _| {
            NoiseLevel::NOMINAL
        });
        test_fn(&ServerKey::unchecked_scalar_mod, &|_, _| {
            NoiseLevel::NOMINAL
        });
    }
    test_fn(&ServerKey::unchecked_scalar_bitand, &|_, _| {
        NoiseLevel::NOMINAL
    });
    test_fn(&ServerKey::unchecked_scalar_bitor, &|_, _| {
        NoiseLevel::NOMINAL
    });
    test_fn(&ServerKey::unchecked_scalar_bitxor, &|_, _| {
        NoiseLevel::NOMINAL
    });
    if scalar < 8 {
        test_fn(&ServerKey::unchecked_scalar_left_shift, &|a, b| {
            a * (1 << b as usize)
        });
    }
    test_fn(&ServerKey::unchecked_scalar_right_shift, &|_, _| {
        NoiseLevel::NOMINAL
    });
}

fn test_1_ct_1_scalar_assign_noise_level_propagation(sk: &ServerKey, ct: &Ciphertext, scalar: u8) {
    let test_fn = |f: &dyn Fn(&ServerKey, &mut Ciphertext, u8),
                   g: &dyn Fn(NoiseLevel, u8) -> NoiseLevel| {
        let mut clone = ct.clone();
        f(sk, &mut clone, scalar);
        assert!(clone.noise_level == g(ct.noise_level, scalar));
    };

    test_fn(&ServerKey::unchecked_scalar_add_assign, &|a, _| a);
    test_fn(&ServerKey::unchecked_scalar_sub_assign, &|a, _| a);
    test_fn(&ServerKey::unchecked_scalar_mul_assign, &|a, b| {
        a * b as usize
    });
    if scalar != 0 {
        test_fn(&ServerKey::unchecked_scalar_div_assign, &|_, _| {
            NoiseLevel::NOMINAL
        });
        test_fn(&ServerKey::unchecked_scalar_mod_assign, &|_, _| {
            NoiseLevel::NOMINAL
        });
    }
    test_fn(&ServerKey::unchecked_scalar_bitand_assign, &|_, _| {
        NoiseLevel::NOMINAL
    });
    test_fn(&ServerKey::unchecked_scalar_bitor_assign, &|_, _| {
        NoiseLevel::NOMINAL
    });
    test_fn(&ServerKey::unchecked_scalar_bitxor_assign, &|_, _| {
        NoiseLevel::NOMINAL
    });
    if scalar < 8 {
        test_fn(&ServerKey::unchecked_scalar_left_shift_assign, &|a, b| {
            a * (1 << b as usize)
        });
    }
    test_fn(&ServerKey::unchecked_scalar_right_shift_assign, &|_, _| {
        NoiseLevel::NOMINAL
    });
}

#[test]
fn test_noise_level_propagation() {
    let keys = KEY_CACHE.get_from_param(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    let (ck, sk) = (keys.client_key(), keys.server_key());

    let trivial = sk.create_trivial(0);

    let ct2 = ck.encrypt(0);
    let ct3 = sk.add(&ct2, &ct2);

    for ct in [&trivial, &ct2, &ct3] {
        test_1_ct_noise_level_propagation(sk, ct);
        test_1_ct_assign_noise_level_propagation(sk, ct);
    }

    for ct1 in [&ct2, &ct3, &trivial] {
        for ct2 in [&ct2, &ct3, &trivial] {
            test_2_ct_noise_level_propagation(sk, ct1, ct2);
            test_2_ct_assign_noise_level_propagation(sk, ct1, ct2);
        }
    }

    for ct in [&ct2, &ct3, &trivial] {
        for scalar in 0..12 {
            test_1_ct_1_scalar_noise_level_propagation(sk, ct, scalar);
            test_1_ct_1_scalar_assign_noise_level_propagation(sk, ct, scalar);
        }
    }
}
