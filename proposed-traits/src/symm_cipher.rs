use crate::serde::Serde;

/// Error kind.
///
/// This represents a common set of digest operation errors. Implementations are
/// free to define more specific or additional error types. However, by providing
/// a mapping to these common errors, generic code can still react to them.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[non_exhaustive]
pub enum ErrorKind {
     /// Failed to initialize the hash computation context.
    InitializationError,

    /// General hardware failure during hash computation.
    HardwareFailure,

    /// Insufficient permissions to access the hardware or perform the Mac computation.
    PermissionDenied,

    /// The Mac operation context has not been initialized.
    InvalidState,
}

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

pub trait SymmCipherCtrl: ErrorType {
    type InitParams<'a>: where Self: 'a;
    type OpContext<'a>: SymmetricCipherOp where Self: 'a;

    /// Init instance of the crypto function with the given context.
    ///
    /// # Parameters
    ///
    /// - `init_params`: The context or configuration parameters for the crypto function.
    ///
    /// # Returns
    ///
    /// A new instance of the hash function.
    fn init<'a>(&'a mut self, init_params: Self::InitParams<'a>) -> Result<Self::OpContext<'a>, Self::Error>;
}


pub trait SymmetricCipherOp {

    /// Associated type for the plaintext.
    type PlainText : Serde;

    /// Associated type for the ciphertext.
    type Ciphertext: Serde;


    /// Encrypt the given plaintext.
    ///
    /// # Parameters
    ///
    /// - `plaintext`: The data to be encrypted.
    ///
    /// # Returns
    ///
    /// A `Result` containing the ciphertext on success, or a `Self::Error` on failure.
    fn encrypt(&mut self, plaintext: Self::Plaintext) -> Result<Self::Ciphertext, Self::Error>;

    /// Decrypt the given ciphertext.
    ///
    /// # Parameters
    ///
    /// - `ciphertext`: The data to be decrypted.
    ///
    /// # Returns
    ///
    /// A `Result` containing the plaintext on success, or a `Self::Error` on failure.
    fn decrypt(&mut self, ciphertext: Self::Ciphertext) -> Result<Self::Plaintext, Self::Error>;
}
