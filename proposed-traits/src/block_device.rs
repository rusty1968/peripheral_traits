pub enum ErrorKind {
    ReadError,
    ProgramError,
    EraseError,
    OutOfBounds,
}

pub trait Error: core::fmt::Debug {
    /// Convert a specific NOR flash error into a generic error kind.
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

/// A trait that BlockDevice implementations can use to share an error type.
pub trait ErrorType {
    /// Errors returned by this NOR flash.
    type Error: Error;
}

/// Block devices are byte addressable but operate in units of "blocks".
pub trait BlockDevice: ErrorType {
    /// Get size of a reaadable block
    fn read_size(&self) -> usize;
    fn read(&mut self, block_addr: usize, data: &mut [u8]) -> Result<(), Self::Error>;

    fn erase_size(&self) -> usize;
    fn erase(&mut self, block_addr: usize, size_in_bytes: usize) -> Result<(), Self::Error>;

    fn program_size(&self) -> usize;
    fn program(&mut self, block_addr: usize, data: &[u8]) -> Result<(), Self::Error>;

    /// Size of the underlying device in bytes
    fn capacity(&self) -> usize;
}
