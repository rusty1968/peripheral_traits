/// Represents the category of an error that occurred during OTP memory operations.
/// #[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[non_exhaustive]
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum ErrorKind {
    /// The specified address is out of bounds or invalid.
    InvalidAddress,

    /// The memory is locked and cannot be written to.
    MemoryLocked,

    /// A write operation failed due to hardware or timing issues.
    WriteFailed,

    /// A read operation failed due to hardware or timing issues.
    ReadFailed,

    /// The lock operation failed or was not acknowledged.
    LockFailed,

    /// An unspecified or unknown error occurred.
    Unknown,
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

/// A generic trait representing a One-Time Programmable (OTP) memory interface.
///
/// This trait abstracts the basic operations for interacting with OTP memory,
/// which is typically used for storing immutable configuration data such as
/// device IDs, cryptographic keys, or calibration values.
///
/// The trait is generic over the data type `T`, allowing implementations for
/// various word widths (e.g., `u8`, `u16`, `u32`, `u64`).
///
/// # Type Parameters
///
/// - `T`: The data type used for memory operations. Must implement `Copy` and `Default`.
///
/// # Errors
///
/// All methods return a `Result` to handle potential errors such as invalid
/// addresses or attempts to write to locked memory.
pub trait OtpMemory<T>: ErrorType + Send + Sync
where
    T: Copy + Default,
{
    /// Reads a value of type `T` from the specified memory address.
    ///
    /// # Parameters
    /// - `address`: The offset from the base address of the OTP memory.
    ///
    /// # Returns
    /// - `Ok(T)`: The value read from memory.
    /// - `Err(OtpError)`: If the address is invalid or inaccessible.
    fn read(&self, address: usize) -> Result<T, Self::Error>;

    /// Writes a value of type `T` to the specified memory address.
    ///
    /// # Parameters
    /// - `address`: The offset from the base address of the OTP memory.
    /// - `data`: The value to write.
    ///
    /// # Returns
    /// - `Ok(())`: If the write was successful.
    /// - `Err(OtpError)`: If the memory is locked or the address is invalid.
    fn write(&mut self, address: usize, data: T) -> Result<(), Self::Error>;

    /// Permanently locks the OTP memory to prevent further writes.
    ///
    /// # Returns
    /// - `Ok(())`: If the lock operation was successful.
    /// - `Err(OtpError)`: If the lock operation failed.
    fn lock(&mut self) -> Result<(), Self::Error>;

    /// Checks whether the OTP memory is currently locked.
    ///
    /// # Returns
    /// - `true`: If the memory is locked.
    /// - `false`: If the memory is still writable.
    fn is_locked(&self) -> bool;
}
