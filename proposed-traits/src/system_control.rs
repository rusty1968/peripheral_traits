pub enum ErrorKind {
    ClockEnalbleError,
    ClockDisableError,
    ResetEnterError,
    ResetExitError,
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

pub trait ClockControl: ErrorType {
    type PeripheralId;
    fn enable_clock(&mut self, peripheral: Self::PeripheralId) -> Result<(), Self::Error>;
    fn disable_clock(&mut self, peripheral: Self::PeripheralId) -> Result<(), Self::Error>;
}

pub trait ResetControl: ErrorType {
    type PeripheralId;
    fn enter_reset(&mut self, peripheral: Self::PeripheralId) -> Result<(), Self::Error>;
    fn exit_reset(&mut self, peripheral: Self::PeripheralId) -> Result<(), Self::Error>;
}
