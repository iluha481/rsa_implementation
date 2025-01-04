use num_bigint::{BigInt, RandBigInt};
use num_traits::{Zero, One, ToPrimitive};
use rand::thread_rng;

pub struct User {
    n: BigInt,
    d: BigInt,
    c: BigInt,
}
impl User {
    pub fn new(
        p: &BigInt, 
        q: &BigInt
    ) -> Self {
        User {
            n: p * q,
            d: BigInt::from(65537u32),
            c: mod_inverse(&BigInt::from(65537u32), &((p - BigInt::one()) * (q - BigInt::one())))
        }
    }

    pub fn from_big_int(
        n: &BigInt,
        d: &BigInt,
        c: &BigInt
    ) -> Self {
        User {
            n: n.clone(),
            d: d.clone(),
            c: c.clone(),
        }
    }
    
    pub fn from_u128(
        n: u128,
        d: u128,
        c: u128
    ) -> Self{
        User::from_big_int(
            &BigInt::from(n),
            &BigInt::from(d),
            &BigInt::from(c)
        )
    }

    pub fn get_keys(
        &self
    ) -> (BigInt, BigInt, BigInt) {
        (self.n.clone(), self.d.clone(), self.c.clone())
    }
}

pub fn encrypt_message(
    message: &str,
    pk_d: &BigInt,
    pk_n: &BigInt
) -> Vec<BigInt> {
    let mut encrypted: Vec<BigInt> = Vec::new();
    for ch in message.chars() {
        encrypted.push(mod_pow(
            &BigInt::from(ch as u32), 
            pk_d, 
            pk_n));
    }
    encrypted
}

pub fn decrypt_message(
    encrypted: &Vec<BigInt>,
    sk_c: &BigInt,
    pk_n: &BigInt
) -> String {
    let mut decrypted: String = String::new();
    for i in encrypted.iter() {
        decrypted.push(
            char::from_u32(
            mod_pow(i, sk_c, pk_n)
            .to_u32()
            .unwrap() 
            )
            .unwrap()
        );
    }
    decrypted
}

fn mod_pow(
    base: &BigInt, 
    exp: &BigInt, 
    mod_: &BigInt
) -> BigInt {
    
    let mut result = BigInt::one();
    let mut base = base.clone();
    let mut exp = exp.clone();
    while exp > BigInt::zero() {
        if &exp % 2 == BigInt::one() {
            result = (result * &base) % mod_;
        }
        base = (&base * &base) % mod_;
        exp = exp / 2;
    }
    result
}

fn extended_gcd(
    a: &BigInt, 
    b: &BigInt
) -> (BigInt, BigInt, BigInt) { 
    if b.is_zero() {
        return (a.clone(), BigInt::one(), BigInt::zero() );
    }
    
    let (gcd, x1, y1) = extended_gcd(b, &(a.clone() % b.clone()));

    return (gcd, 
        y1.clone(),
        x1 - (a / b) * y1);
}

fn mod_inverse(
    d: &BigInt, 
    fi: &BigInt
) -> BigInt {
    let (gcd, x, _) = extended_gcd(d, fi);
    if gcd != BigInt::one() {

        return BigInt::from(-1i32);
    }

    (x % fi + fi) % fi
}

pub fn get_rand_prime(
    bit_size: u64,
) -> BigInt {
    let mut prime_num = thread_rng().gen_bigint(bit_size);
    while !is_prime(&prime_num, 40){
        prime_num = thread_rng().gen_bigint(bit_size);
    }
    prime_num
}

fn is_prime(
    n: &BigInt,
    k: u32
) -> bool {
    if n < &BigInt::from(2i32) {
        return false;
    }
    if n != &BigInt::from(2i32) && n % 2 == BigInt::zero()  {
        return false;
    }
    let mut d: BigInt = n - 1;
    let mut s = 0;
    while d.clone() % 2 == BigInt::zero() {
        d = d / 2;
        s += 1;
    }
    
    for _ in 0..k {
        let a = thread_rng().gen_bigint_range(
            &BigInt::from(2i32), 
            &(n - BigInt::from(2i32)));
        let mut x = mod_pow(&a, &d, n);
        if x == BigInt::one() || x == n - 1 {
            continue;
        }
        let mut composite = 1;
        for _ in 0..(s-1) {
            x = mod_pow(&x, &BigInt::from(2i32), n);
            if x == n - 1 {
                composite = 0;
                break;
            }
        }
        if composite == 1{
            return false;
        }
    }
    return true;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_decryption() {
        fn test_rsa_func() {
            let bit_size: u64 = 512;
            let user = User::new(&get_rand_prime(bit_size), &get_rand_prime(bit_size));
            let (n,d, c) = user.get_keys();
        
            let message = String::from("Hello, world!");
            let encrypted_message = encrypt_message(&message, &d, &n);
        
            assert_eq!(&message, &decrypt_message(&encrypted_message, &c, &n));    
        }
        


    }
}