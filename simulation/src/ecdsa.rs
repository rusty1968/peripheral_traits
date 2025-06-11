use p256::{
    ecdsa::{Signature, SigningKey, VerifyingKey}
};
use proposed_traits::{digest::DigestAlgorithm, ecdsa::{Error, ErrorKind}};
use proposed_traits::ecdsa::{Curve, EcdsaKeyGen, EcdsaSign, EcdsaVerify, ErrorType};
use p256::ecdsa::signature::hazmat::{PrehashVerifier, PrehashSigner};
use rand::{CryptoRng, RngCore};

/// Digest algorithm for SHA-256
pub struct Sha2_256;

impl DigestAlgorithm for Sha2_256 {
    const OUTPUT_BITS: usize = 256;
    type DigestOutput = [u8; 32];
}

pub struct P256Sha256;

impl Curve for P256Sha256 {
    type DigestType = Sha2_256;
}


#[derive(Debug)]
pub enum EcdsaCryptoError {
    InvalidSignature,
    SigningError,
    KeyGenError,
}

impl Error for EcdsaCryptoError {
    fn kind(&self) -> ErrorKind {
        match self {
            Self::InvalidSignature => ErrorKind::InvalidSignature,
            Self::SigningError => ErrorKind::SigningError,
            Self::KeyGenError => ErrorKind::KeyGenError,
        }
    }
}

pub struct P256KeyGen;

impl ErrorType for P256KeyGen {
    type Error = EcdsaCryptoError;
}

impl EcdsaKeyGen for P256KeyGen {
    type PrivateKey<'a> = SigningKey;
    type PublicKey<'a> = VerifyingKey;

    fn generate_key_pair<R: RngCore + CryptoRng>(
        &mut self,
        mut rng: R,
        priv_key: &mut Self::PrivateKey<'_>,
        pub_key: &mut Self::PublicKey<'_>,
    ) -> Result<(), Self::Error> {
        let sk = SigningKey::random(&mut rng);
        let vk = VerifyingKey::from(&sk);
        *priv_key = sk;
        *pub_key = vk;
        Ok(())
    }
}

pub struct P256Verifier;

impl ErrorType for P256Verifier {
    type Error = EcdsaCryptoError;
}

impl EcdsaVerify<P256Sha256> for P256Verifier {
    type PublicKey = VerifyingKey;
    type Signature = Signature;

    fn verify(
        &mut self,
        public_key: &Self::PublicKey,
        digest: <Sha2_256 as DigestAlgorithm>::DigestOutput,
        signature: &Self::Signature,
    ) -> Result<(), Self::Error> {
        public_key
            .verify_prehash(&digest, signature)
            .map_err(|_| EcdsaCryptoError::InvalidSignature)
    }
}

pub struct P256Signer;

impl ErrorType for P256Signer {
    type Error = EcdsaCryptoError;
}

impl EcdsaSign<P256Sha256> for P256Signer {
    type PrivateKey<'a> = SigningKey;
    type Signature = Signature;

    fn sign<R: RngCore + CryptoRng>(
        &mut self,
        private_key: &Self::PrivateKey<'_>,
        digest: <Sha2_256 as DigestAlgorithm>::DigestOutput,
        _rng: R,
    ) -> Result<Self::Signature, Self::Error> {
        private_key
            .sign_prehash(&digest)
            .map_err(|_| EcdsaCryptoError::SigningError)
    }
}
