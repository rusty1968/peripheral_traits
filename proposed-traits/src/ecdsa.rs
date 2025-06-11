use core::fmt::Debug;
use crate::digest::DigestAlgorithm;

pub trait Error: core::fmt::Debug {
    /// Convert error to a generic error kind
    ///
    /// By using this method, errors freely defined by HAL implementations
    /// can be converted to a set of generic errors upon which generic
    /// code can act.
    fn kind(&self) -> ErrorKind;
}

impl Error for core::convert::Infallible {
    fn kind(&self) -> ErrorKind {
        match *self {}
    }
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

pub trait Curve {
    type DigestType: DigestAlgorithm;
}

/// Trait for ECDSA key generation over a specific elliptic curve.
pub trait EcdsaKeyGen: ErrorType {
    type PrivateKey<'a>;
    type PublicKey<'a>;

    fn generate_key_pair<R: rand_core::RngCore + rand_core::CryptoRng>(
        &mut self,
        rng: R,
        priv_key: &mut Self::PrivateKey<'_>,
        pub_key: &mut Self::PublicKey<'_>,
    ) -> Result<(), Self::Error>;
}

/// Trait for ECDSA signing using a digest algorithm.
pub trait EcdsaSign<C: Curve>: ErrorType {
    type PrivateKey<'a>;
    type Signature;

    /// Signs a digest produced by a compatible hash function.
    ///
    /// # Parameters
    /// - `private_key`: The private key used for signing.
    /// - `digest`: The digest output from a hash function.
    /// - `rng`: A cryptographically secure random number generator.
    fn sign<R: rand_core::RngCore + rand_core::CryptoRng>(
        &mut self,
        private_key: &Self::PrivateKey<'_>,
        digest: <<C as Curve>::DigestType as DigestAlgorithm>::DigestOutput,
        rng: R,
    ) -> Result<Self::Signature, Self::Error>;
}

/// Trait for ECDSA signature verification using a digest algorithm.
pub trait EcdsaVerify<C: Curve>: ErrorType {
    type PublicKey;
    type Signature;

    /// Verifies a signature against a digest.
    ///
    /// # Parameters
    /// - `public_key`: The public key used for verification.
    /// - `digest`: The digest output from a hash function.
    /// - `signature`: The signature to verify.
    fn verify(
        &mut self,
        public_key: &Self::PublicKey,
        digest: <<C as Curve>::DigestType as DigestAlgorithm>::DigestOutput,
        signature: &Self::Signature,
    ) -> Result<(), Self::Error>;
}
