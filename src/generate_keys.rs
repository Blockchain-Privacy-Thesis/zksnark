use sha2::SHA256Compress;
use rand::{ thread_rng, Rng, rngs::ThreadRng };


fn random_digits(rng: &mut ThreadRng, digits: i32) -> i32
{
    // 10^(digits-1) always yields the smallest number we want,
    // except for digits = 1 if we allow 0 for 1 digit numbers.
    let min = (10.0_f32).powi(digits - 1) as i32;

    // 10^digits is the starting number of the next digit "bracket"
    let max = (10.0_f32).powi(digits) as i32;

    // Get the number from min to max, excluding.
    rng.gen_range(min..max)
}


fn main() {
  // The goal of this function is to generate a shielded address, which can be used to
  // sign unlinkable transactions

  // First we obtain a uniformly random spending key of a specified length
  // This key is a bit sequence of said specified length
  // We will use a 252-bit length
  let mut rng = thread_rng()
  println!("{:?}", random_digits(&mut rng, 252))

  // We generate a shared key a_pk
  // This is done using a pseudo random function
  // In our case we will use the SHA256Compress function


  // We generate a secret key sk_enc
  // This is done using the same pseudo random function as with ap_k
  // Then we put this through a function based on a key agreement scheme


  // We generate a public key pk_enc
  // The public key is generated using the secret key and functions from the
  // key agreement scheme
}