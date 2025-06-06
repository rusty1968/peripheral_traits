use core::fmt::Debug;
use rand_core::{CryptoRng, RngCore};
// use crate::common::ToBytesFromBytes; // Removed because it does not exist

pub trait Error: core::fmt::Debug {
    /// Convert error to a generic error kind
    ///
    /// By using this method, errors freely defined by HAL implementations
    /// can be converted to a set of generic errors upon which generic
    /// code can act.
    fn kind(&self) -> ErrorKind;
}

pub trait ErrorType {
    /// Error type.
    type Error: Error;
}

/// Error kind.
///
/// This represents a common set of digest operation errors. Implementations are
/// free to define more specific or additional error types. However, by providing
/// a mapping to these common errors, generic code can still react to them.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[non_exhaustive]
pub enum ErrorKind {
    Busy,
    InvalidSignature,
    KeyGenError,
    SigningError,
    Other,
}

/// Trait for ECDSA key generation.
///
/// This trait defines the methods required for generating ECDSA key pairs.
pub trait EcdsaKeyGen: ErrorType {
    type PrivateKeyOut<'a>; // Removed ToBytesFromBytes bound
    type PublicKeyOut<'a>; // Removed ToBytesFromBytes bound

    /// Generates an ECDSA key pair.
    ///
    /// # Parameters
    /// - `rng`: The entropy source.
    ///
    /// # Returns
    /// A result containing the generated private and public keys, or an error.    
    fn generate_key_pair<R: RngCore + CryptoRng>(
        &mut self,
        rng: R,
        priv_key: &mut Self::PrivateKeyOut<'_>,
        pub_key: &mut Self::PublicKeyOut<'_>,
    ) -> Result<(), Self::Error>;
}

/// Trait for ECDSA signing.
///
/// This trait defines the methods required for signing messages using ECDSA.
pub trait EcdsaSign: ErrorType {
    type PrivateKeyIn<'a>;
    type Message;
    type Signature;

    /// Signs a message hash using the private key and elliptic curve.
    ///
    /// # Parameters
    /// - `private_key`: The private key to use for signing.
    /// - `message_hash`: The hash of the message to sign.
    ///
    /// # Returns
    /// A result containing the generated signature, or an error.    
    fn sign<R>(
        &mut self,
        private_key: &Self::PrivateKeyIn<'_>,
        message: Self::Message,
        rng: R,
    ) -> Result<Self::Signature, Self::Error>
    where
        R: RngCore + CryptoRng;
}

/// Trait for ECDSA verification.
///
/// This trait defines the methods required for verifying ECDSA signatures.
pub trait EcdsaVerify: ErrorType {
    type PublicKey;
    type Message;
    type Signature;

    /// Verifies an ECDSA signature.
    ///
    /// # Parameters
    /// - `public_key`: The public key to use for verification.
    /// - `message_hash`: The hash of the message to verify.
    /// - `signature`: The signature to verify.
    ///
    /// # Returns
    /// A result indicating whether the signature is valid, or an error.    
    fn verify(
        &mut self,
        public_key: &Self::PublicKey,
        message: Self::Message,
        signature: &Self::Signature,
    ) -> Result<(), Self::Error>;
}
