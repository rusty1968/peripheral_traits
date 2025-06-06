use crate::common::{FromBytes, ToBytes};

/// An abstraction over a message port that enables sending serialized requests
/// to a target service and receiving deserialized responses over a communication channel.
pub trait Client {
    type Error;

    /// Sends a request to a specific target service and waits for a response.
    ///
    /// # Arguments
    ///
    /// * `target` - The destination service identifier (e.g., port ID or handle).
    /// * `op` - An operation code or selector.
    /// * `request` - The request payload to serialize and send.
    ///
    /// # Returns
    ///
    /// A deserialized response of type `RS`, or an error.
    fn call<RQ, RS>(&self, target: u32, op: u16, request: &RQ) -> Result<RS, Self::Error>
    where
        RQ: ToBytes,
        RS: FromBytes;
}
