use core::num::NonZeroU32;

use crate::common::{FromBytes, ToBytes};

pub enum PaddingMode {
    Pkcs1v15,
    Pss,
}

pub enum RsaSize {
    Size2048,
    Size3072,
    Size4096,
    Other(NonZeroU32),
}

pub enum ErrorKind {
    InvalidLength,
    SignError,
    VerifyError,
}

pub trait Error: core::fmt::Debug {
    /// Convert error to a generic error kind
    ///
    /// By using this method, errors freely defined by HAL implementations
    /// can be converted to a set of generic errors upon which generic
    /// code can act.
    fn kind(&self) -> ErrorKind;
}

/// RSA error type trait.
///
// This just defines the error type, to be used by the other  traits.
pub trait ErrorType {
    /// Error type
    type Error: Error;
}

pub trait RsaKeys {
    type PrivateKey;
    type PublicKey;
}

pub trait RsaSignature {
    type Signature;
}

pub trait RsaKeyGen: ErrorType + RsaKeys {
    fn generate_keys(bits: RsaSize) -> Result<(Self::PrivateKey, Self::PublicKey), Self::Error>;
}

pub trait RsaSign: ErrorType + RsaKeys + RsaSignature {
    type Message;
    fn sign(
        &self,
        private_key: &Self::PrivateKey,
        message: Self::Message,
        padding_mode: PaddingMode,
    ) -> Result<Self::Signature, Self::Error>;
}

pub trait RsaVerify: ErrorType + RsaKeys + RsaSignature {
    type Message: ToBytes + FromBytes;
    fn verify(
        &mut self,
        public_key: &Self::PublicKey,
        message: Self::Message,
        padding_mode: PaddingMode,
        signature: &Self::Signature,
    ) -> Result<Self::Signature, Self::Error>;
}
