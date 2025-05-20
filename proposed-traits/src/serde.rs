// serde.rs

pub trait SerdeError: core::fmt::Debug {
    /// Convert error to a generic error kind
    ///
    /// By using this method, errors freely defined by HAL implementations
    /// can be converted to a set of generic errors upon which generic
    /// code can act.
    fn kind(&self) -> ErrorKind;
}

pub trait ErrorType {
    /// Error type.
    type Error: SerdeError;
}

/// Error kind.
///
/// This represents a common set of digest operation errors. Implementations are
/// free to define more specific or additional error types. However, by providing
/// a mapping to these common errors, generic code can still react to them.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[non_exhaustive]
pub enum ErrorKind {
    NotSupported,
    SourceBufferTooSmall,
}

pub trait OutputSize {
    const OUTPUT_SIZE: usize;
}

pub trait Serde: ErrorType {
    type OutputType;
    fn to_le_bytes(&self, dest: &mut [u8]) -> Result<(), Self::Error>;
    fn from_bytes_le(bytes: &[u8]) -> Result<Self::OutputType, Self::Error>;
}
