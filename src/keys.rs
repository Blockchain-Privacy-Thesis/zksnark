use std::convert::{TryFrom, TryInto};
use std::io::{self, Read, Write};
use std::mem;
use aes::Aes256;
use blake2b_simd::{Hash as Blake2bHash, Params};
use fpe::ff1::{BinaryNumeralString, FF1};
use group::{
    ff::{Field, PrimeField},
    prime::PrimeCurveAffine,
    Curve, GroupEncoding,
};
use pasta_curves::pallas;
use rand::RngCore;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};


#[no_mangle]
pub fn ed25519_generate_keypair(sk: *mut [u8; 32], vk: *mut [u8; 32]) {
    let sk = unsafe { sk.as_mut() }.unwrap();
    let vk = unsafe { vk.as_mut() }.unwrap();

    let signing_key = SigningKey::new(OsRng);

    *sk = signing_key.into();
    *vk = VerificationKey::from(&signing_key).into();
}

pub fn clamp_curve25519(x: *mut [u8; 32]) {
  x[0] &= 0b0001_1111;  // Clear bit 0, 1, and 2 of first byte
  x[31] &= 0b1111_1110; // Clear bit 7 of last byte
  x[31] |= 0b0000_0010;; // Set bit 6 of last byte
}

/// A signing key, from which all key material is derived.
#[derive(Debug, Copy, Clone)]
pub struct SigningKey([u8; 32]);

impl SigningKey {
    /// Generates a random signing key.
    pub(crate) fn random(rng: &mut impl RngCore) -> Self {
        loop {
            let mut bytes = [0; 32];
            rng.fill_bytes(&mut bytes);
            let sk = SigningKey::from_bytes(bytes);
            if sk.is_some().into() {
                break sk.unwrap();
            }
        }
    }

    /// Returns the raw bytes of the signing key.
    pub fn to_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}


#[derive(Debug, Clone)]
pub struct AddressSigningKey([u8; 32]);
impl AddressSigningKey {
  /// Return the raw bytes of the Address Signing Key
  pub fn to_bytes(&self) -> &[u8; 32] {
      &self.0
  }
  /// Construct a Address Signing Key from bytes
  pub fn from_bytes(bytes: [u8; 32]) -> Self {
      AddressSigningKey(bytes)
  }
}

#[derive(Debug, Clone)]
pub struct ReceivingKey([u8; 32]);
impl ReceivingKey {
  /// Return the raw bytes of the Receiving Key
  pub fn to_bytes(&self) -> &[u8; 32] {
    &self.0
  }
  /// Construct a Receiving Key from bytes
  pub fn from_bytes(bytes: [u8; 32]) -> Self {
    ReceivingKey(bytes)
  }
}

#[derive(Debug, Clone)]
pub struct TransmissionKey([u8; 32]);
impl TransmissionKey {
  /// Return the raw bytes of the Receiving Key
  pub fn to_bytes(&self) -> &[u8; 32] {
    &self.0
  }
  /// Construct a Receiving Key from bytes
  pub fn from_bytes(bytes: [u8; 32]) -> Self {
    TransmissionKey(bytes)
  }
}


#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IncomingViewingKey {
  a_pk: AddressSigningKey,
  sk_enc: ReceivingKey,
}
impl IncomingViewingKey {
  pub fn to_bytes(&self) -> [u8; 64] {
    let mut result = [0u8; 64];
    result[..32].copy_from_slice(self.a_pk.to_bytes());
    result[32..].copy_from_slice(&self.sk_enc.0.to_repr());
    result
  }

  /// Parses an incoming viewing key from its raw encoding
  pub fn from_bytes(bytes: &[u8; 64]) -> CtOption<Self> {
    IncomingViewingKey {
      a_pk: AddressSigningKey(bytes[..32].into()),
      sk_enc: ReceivingKey(sk_enc.into()),
    }
  }
}


#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShieldedAddress {
  a_pk: AddressSigningKey,
  pk_enc: TransmissionKey
}
impl ShieldedAddress {
  pub fn to_bytes(&self) -> [u8; 64] {
    let mut result = [0u8; 64];
    result[..32].copy_from_slice(self.a_pk.to_bytes());
    result[32..].copy_from_slice(&self.pk_enc.0.to_repr());
    result
  }

  /// Parses an shielded address from its raw encoding
  pub fn from_bytes(bytes: &[u8; 64]) -> CtOption<Self> {
    IncomingViewingKey {
      a_pk: AddressSigningKey(bytes[..32].into()),
      sk_enc: TransmissionKey(pk_enc.into()),
    }
  }
}
