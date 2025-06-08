/// Represents categories of errors that can occur during system calls.
///
/// This enum is marked as `#[non_exhaustive]` to allow future expansion without
/// breaking existing match statements. It is intended to be used as part of a
/// `SyscallError` type to provide structured error reporting across kernel services.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    // --- Task Management Errors ---
    
    /// The specified task ID does not exist or is not valid.
    InvalidTaskId,

    /// The task creation request failed due to resource exhaustion (e.g., no memory or slots).
    TaskCreationFailed,

    /// The task attempted an operation it is not permitted to perform.
    PermissionDenied,

    /// The task is not in a valid state for the requested operation.
    InvalidTaskState,

    // --- IPC Errors ---

    /// No message was available to receive.
    NoMessageAvailable,

    /// The message being replied to is invalid or expired.
    InvalidMessage,

    /// The IPC buffer was too small to hold the message or reply.
    BufferTooSmall,

    /// The IPC operation timed out.
    Timeout,

    // --- Memory and Resource Errors ---

    /// The requested memory region is invalid or inaccessible.
    InvalidMemoryAccess,

    /// The system ran out of memory or another critical resource.
    OutOfResources,

    // --- General and Unknown Errors ---

    /// The syscall arguments were invalid or malformed.
    InvalidArguments,

    /// The operation is not supported by this kernel configuration.
    NotSupported,

    /// An unspecified or unknown error occurred.
    Other,
}

pub trait Error: core::fmt::Debug {
    /// Convert error to a generic error kind
    ///
    /// By using this method, errors freely defined by implementations
    /// can be converted to a set of generic errors upon which generic
    /// code can act.
    fn kind(&self) -> ErrorKind;
}

pub trait ErrorType {
    /// Error type.
    type Error: Error;
}
