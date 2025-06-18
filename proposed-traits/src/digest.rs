use core::fmt::Debug;

/// Common error kinds for digest operations.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[non_exhaustive]
pub enum ErrorKind {
    /// The input data length is not valid for the hash function.
    InvalidInputLength,
    /// The specified hash algorithm is not supported by the hardware or software implementation.
    UnsupportedAlgorithm,
    /// Failed to allocate memory for the hash computation.
    MemoryAllocationFailure,
    /// Failed to initialize the hash computation context.
    InitializationError,
    /// Error occurred while updating the hash computation with new data.
    UpdateError,
    /// Error occurred while finalizing the hash computation.
    FinalizationError,
    /// The hardware accelerator is busy and cannot process the hash computation.
    Busy,
    /// General hardware failure during hash computation.
    HardwareFailure,
    /// The specified output size is not valid for the hash function.
    InvalidOutputSize,
    /// Insufficient permissions to access the hardware or perform the hash computation.
    PermissionDenied,
    /// The hash computation context has not been initialized.
    NotInitialized,
}

/// Trait for converting implementation-specific errors into a common error kind.
pub trait Error: Debug {
    /// Returns a generic error kind corresponding to the specific error.
    fn kind(&self) -> ErrorKind;
}

impl Error for core::convert::Infallible {
    fn kind(&self) -> ErrorKind {
        match *self {}
    }
}

/// Trait for types that associate with a specific error type.
pub trait ErrorType {
    /// The associated error type.
    type Error: Error;
}

/// Trait representing a digest algorithm and its output characteristics.
pub trait DigestAlgorithm {
    /// The number of bits in the digest output.
    const OUTPUT_BITS: usize;

    /// The type representing the digest output.
    type DigestOutput: AsRef<[u8]>;
}

/// Trait for initializing a digest operation for a specific algorithm.
pub trait DigestInit<A: DigestAlgorithm>: ErrorType {
    /// The type representing the operational context for the digest.
    type OpContext<'a>: DigestOp<Output = A::DigestOutput>
    where
        Self: 'a;

    /// Initializes the digest operation with the specified algorithm.
    ///
    /// # Parameters
    ///
    /// - `algo`: A zero-sized type representing the digest algorithm to use.
    ///
    /// # Returns
    ///
    /// A result containing the operational context for the digest, or an error.
    fn init<'a>(&'a mut self, algo: A) -> Result<Self::OpContext<'a>, Self::Error>;
}

/// Optional trait for resetting a digest context to its initial state.
pub trait DigestCtrlReset: ErrorType {
    /// Resets the digest context.
    ///
    /// # Returns
    ///
    /// A result indicating success or failure.
    fn reset(&mut self) -> Result<(), Self::Error>;
}

/// Trait for performing digest operations.
pub trait DigestOp: ErrorType {
    /// The type of the digest output.
    type Output;

    /// Updates the digest state with the provided input data.
    ///
    /// # Parameters
    ///
    /// - `input`: A byte slice containing the data to hash.
    ///
    /// # Returns
    ///
    /// A result indicating success or failure.
    fn update(&mut self, input: &[u8]) -> Result<(), Self::Error>;

    /// Finalizes the digest computation and returns the result.
    ///
    /// # Returns
    ///
    /// A result containing the digest output, or an error.
    fn finalize(self) -> Result<Self::Output, Self::Error>;
}
