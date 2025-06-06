/// Error kind.
///
/// This represents a common set of digest operation errors. Implementations are
/// free to define more specific or additional error types. However, by providing
/// a mapping to these common errors, generic code can still react to them.
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

    /// Insufficient permissions to access the hardware or perform the Mac computation.
    PermissionDenied,

    /// The Mac operation context has not been initialized.
    InvalidState,
}

pub trait Error: core::fmt::Debug {
    /// Convert error to a generic error kind
    ///
    /// By using this method, errors freely defined by Algo implementations
    /// can be converted to a set of generic errors upon which generic
    /// code can act.
    fn kind(&self) -> ErrorKind;
}

impl Error for core::convert::Infallible {
    /// Convert error to a generic Mac error kind.
    ///
    /// By using this method, Mac errors freely defined by Algo implementations
    /// can be converted to a set of generic I2C errors upon which generic
    /// code can act.    
    fn kind(&self) -> ErrorKind {
        match *self {}
    }
}

pub trait ErrorType {
    /// Error type.
    type Error: Error;
}

pub trait McCtrlReset: ErrorType {
    /// Reset instance to its initial state.
    ///
    /// # Returns
    ///
    /// A `Result` indicating success or failure. On success, returns `Ok(())`. On failure, returns a `CryptoError`.    
    fn reset(&mut self) -> Result<(), Self::Error>;
}

pub trait MacInit: ErrorType {
    type InitParams<'a>
    where
        Self: 'a;
    type OpContext<'a>: MacOp
    where
        Self: 'a;

    /// Init instance of the crypto function with the given context.
    ///
    /// # Parameters
    ///
    /// - `init_params`: The context or configuration parameters for the crypto function.
    ///
    /// # Returns
    ///
    /// A new instance of the hash function.
    fn init<'a>(
        &'a mut self,
        init_params: Self::InitParams<'a>,
    ) -> Result<Self::OpContext<'a>, Self::Error>;
}

/// Message Authentication Code Operation
pub trait MacOp: ErrorType {
    /// Update state using provided input data.
    ///
    /// # Parameters
    ///
    /// - `input`: The input data to be hashed. This can be any type that implements `AsRef<[u8]>`.
    ///
    /// # Returns
    ///
    /// A `Result` indicating success or failure. On success, returns `Ok(())`. On failure, returns a `CryptoError`.    
    fn update(&mut self, input: &[u8]) -> Result<(), Self::Error>;

    /// Finalize the computation and produce the output.
    ///
    /// # Parameters
    ///
    /// - `out`: A mutable slice to store the hash output. The length of the slice must be at least `MAX_OUTPUT_SIZE`.
    ///
    /// # Returns
    ///
    /// A `Result` indicating success or failure. On success, returns `Ok(())`. On failure, returns a `CryptoError`.    
    fn finalize(&mut self, tag: &mut [u8]) -> Result<(), Self::Error>;
}
