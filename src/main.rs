use rand::{thread_rng, Rng};
use sha2::compress256;
use rand_core::OsRng;
use ed25519_zebra::{Signature, SigningKey, VerificationKey};

fn ed25519_generate_keypair(sk: *mut [u8; 32], vk: *mut [u8; 32]) {
    let sk = unsafe { sk.as_mut() }.unwrap();
    let vk = unsafe { vk.as_mut() }.unwrap();

    let signing_key = SigningKey::new(OsRng);

    *sk = signing_key.into();
    *vk = VerificationKey::from(&signing_key).into();
}

fn pseudo_random_function(a_sk: &Vec<u8>, t: u8) -> [u8; 512] {
    // TODO: Compress array
    //const array_length: ArrayLength::<512>;
    //let mut array_to_compress: GenericArray<u8, array_length> = GenericArray.gene;
    let mut array_to_compress: [u8; 512] = [0; 512];   // Init array used for the compress function
    for i in 0..4 { // Set first 4 bits of array
        if i < 2 {
            array_to_compress[i] = 1;
        } else {
            array_to_compress[i] = 0;
        }
    }
    for i in 0..252 {   // Spending key input
        array_to_compress[(i+4)] = a_sk[i];
    }
    for i in 255..264 {
        array_to_compress[i] = t; 
    }
    for i in 264..512 {
        array_to_compress[i] = 0;
    }
    //let mut return_array: [u32; 8] = [0; 8];
    //compress256(&mut return_array, array_to_compress);
    return array_to_compress; //return_array;
}


fn main() {
    // The goal of this function is to generate a shielded address, which can be used to
    // sign unlinkable transactions

    // First we obtain a uniformly random spending key of a specified length
    // This key is a bit sequence of said specified length
    // We will use a 252-bit length
    let mut rng = thread_rng();
    let mut a_sk: Vec<u8> = (0..252).map(|_| rng.gen_range(0..2)).collect();
    println!("{:?}", &a_sk);

    // We generate a shared key a_pk
    // This is done using a pseudo random function
    // In our case we will use the SHA256Compress function
    let mut a_pk = pseudo_random_function(&a_sk, 0);
    println!("{:?}", a_pk);

    // For testing
    let mut a_pk_test: [u8; 32] = [0; 32];
    for i in 0..32 {
        a_pk_test[i] = a_pk[i];
    }

    // We generate a secret key sk_enc
    // This is done using the same pseudo random function as with ap_k
    // Then we put this through a function based on a key agreement scheme
    let pseudo_random_number = pseudo_random_function(&a_sk, 1);
    println!("{:?}", pseudo_random_number
);

    // For testing
    let mut a_pk_test: [u8; 32] = [0; 32];
    for i in 0..32 {
        a_pk_test[i] = a_pk[i];
    }


    // We generate a public key pk_enc
    // The public key is generated using the secret key and functions from the
    // key agreement scheme
}