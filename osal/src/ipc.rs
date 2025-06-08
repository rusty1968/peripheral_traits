use core::time::Duration;
use crate::error::ErrorType;

pub enum IpcWaitResult {
    Notification(u32),
    MsgRcvd,
    Timeout,
}

/// Trait for inter-process communication (IPC) system calls.
pub trait IpcSyscalls: Send + Sync + ErrorType {
    type TargetId;
    type IpcFlags;
    type ReplyContext;

    /// Sends a message to a target process or service.
    fn ipc_send(
        &self,
        target: Self::TargetId,
        message: impl AsRef<[u8]>,
        flags: Option<Self::IpcFlags>,
    ) -> Result<(), Self::Error>;

    /// Sends a reply to the sender of a previously received IPC message.
    ///
    /// This function is used to respond to an incoming IPC message. The `message` parameter
    /// optionally provides context about the original message being replied to — such as
    /// sender ID or message token — depending on the implementation of `Self::Request`.
    ///
    /// If `message` is `None`, the kernel may attempt to reply to the most recently received
    /// message for the current task, if such context is tracked internally.
    ///
    /// # Parameters
    /// - `message`: Optional reference to the original message context. If `None`, the kernel
    ///   may use internal state to determine the reply target.
    /// - `reply`: The reply payload to send, which must be serializable via `IntoBytes`.
    /// - `flags`: Optional flags to modify reply behavior (e.g., non-blocking, priority).
    ///
    /// # Returns
    /// - `Ok(())` if the reply was successfully sent.
    /// - `Err(Self::Error)` if the reply failed due to missing context, invalid sender, or other errors.
    ///
    /// # Notes
    /// - Implementations that do not track per-task IPC state may require `message` to be `Some(...)`.
    /// - `Self::Response` must implement `IntoBytes` to allow serialization of the reply payload.
    /// # Example
    /// ```rust
    /// let reply_data = b"OK";
    /// ipc.ipc_reply(Some(&msg), reply_data, None)?;
    /// ```
    fn ipc_reply(
        &self,
        reply_context: Option<&Self::ReplyContext>,
        message: impl AsMut<[u8]>,
        flags: Option<Self::IpcFlags>,
    ) -> Result<(), Self::Error>;

    /// Waits for a message to be received.
    ///
    /// This function blocks (or optionally times out) while waiting for an incoming IPC message
    /// or notification. The message will be written into the provided mutable buffer if received.
    ///
    /// # Arguments
    /// * `message` - A mutable buffer where the received message will be written.
    /// * `notification_mask` - A bitmask specifying which notifications can interrupt the wait.
    /// * `sender_filter` - Optional task ID for closed receive. `None` means open receive.
    /// * `timeout` - Optional timeout duration. If `None`, the call blocks indefinitely.
    ///
    /// # Returns
    /// * `Result<IpcWaitResult, Self::Error>` - Indicates the result of the wait operation.
    ///
    /// # Example
    /// ```rust
    /// use core::time::Duration;
    ///
    /// let mut buffer = [0u8; 128];
    /// let notification_mask = 0b0000_0010;
    /// let sender_filter = None;
    /// let timeout = Some(Duration::from_millis(500));
    ///
    /// match ipc.ipc_rcv(&mut buffer, notification_mask, sender_filter, timeout) {
    ///     Ok(IpcWaitResult::MsgRcvd) => {
    ///         println!("Message received: {:?}", &buffer);
    ///     }
    ///     Ok(IpcWaitResult::Notification(bits)) => {
    ///         println!("Received notification with bits: {:#X}", bits);
    ///     }
    ///     Ok(IpcWaitResult::Timeout) => {
    ///         println!("Timed out waiting for message.");
    ///     }
    ///     Err(e) => {
    ///         eprintln!("IPC receive failed: {:?}", e);
    ///     }
    /// }
    /// ```
    fn ipc_rcv(
        &self,
        message: impl AsMut<[u8]>,
        notification_mask: u32,
        sender_filter: Option<u32>,
        timeout: Option<Duration>,
    ) -> Result<IpcWaitResult, Self::Error>;
}
