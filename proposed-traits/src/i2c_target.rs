use embedded_hal::i2c::ErrorType as I2CErrorType;

/// Trait representing a target (slave) I2C device behavior.
///
/// This trait defines the methods that an I2C target device must implement to handle
/// transactions initiated by an I2C master. It includes methods for handling writes,
/// reads, stop conditions, and address match events.
pub trait I2CTarget: I2CErrorType {
    /// Called when the master initiates a write to this target.
    ///
    /// # Arguments
    ///
    /// * `data` - A slice containing the data to be written to the target.
    ///
    /// # Returns
    ///
    /// * `Result<(), I2CError>` - Returns `Ok(())` if the write is successful, or an `I2CError` if an error occurs.
    fn on_write(&mut self, data: &[u8]) -> Result<(), Self::Error>;

    /// Called when the master initiates a read from this target.
    ///
    /// # Arguments
    ///
    /// * `buffer` - A mutable slice where the read data will be stored.
    ///
    /// # Returns
    ///
    /// * `Result<usize, I2CError>` - Returns the number of bytes read if successful, or an `I2CError` if an error occurs.
    fn on_read(&mut self, buffer: &mut [u8]) -> Result<usize, Self::Error>;

    /// Called when a new I2C transaction begins.
    ///
    /// This method is invoked at the start of a transaction initiated by the controller (master).
    /// It provides a flag indicating whether the transaction is a repeated start, which allows
    /// the target (slave) device to preserve or reset internal state accordingly.
    ///
    /// # Arguments
    ///
    /// * `repeated` - A boolean flag indicating whether this transaction is a repeated start (`true`)
    ///                or a fresh start (`false`). A repeated start means the controller has not
    ///                released the bus between transactions.
    ///
    /// # Usage Model
    ///
    /// This method is distinct from `on_address_match(address: u8) -> bool`:
    ///
    /// - `on_address_match` is called during the address phase to decide whether the target should respond.
    /// - `on_transaction_start` is called after the address is matched and before the data phase begins.
    ///
    /// ## Typical Use Cases:
    /// - Reset internal state if `repeated == false`.
    /// - Preserve context (e.g., register pointer) if `repeated == true`.
    /// - Prepare buffers or state machines for read/write.
    ///
    /// ## When it's called:
    /// - After `on_address_match` returns `true`.
    /// - Before `on_read` or `on_write` is invoked.
    ///
    /// # Example
    ///
    /// ```rust
    /// fn on_transaction_start(&mut self, repeated: bool) {
    ///     if repeated {
    ///         // Continue using previous state
    ///     } else {
    ///         // Reset internal state
    ///     }
    /// }
    /// ```
    fn on_transaction_start(&mut self, repeated: bool);

    /// Optional: handle stop condition or reset.
    ///
    /// This method is called when the master sends a stop condition, indicating the end of a transaction.
    fn on_stop(&mut self);

    /// Optional: handle address match event.
    ///
    /// # Arguments
    ///
    /// * `address` - The address sent by the master.
    ///
    /// # Returns
    ///
    /// * `bool` - Returns `true` if the address matches the target's address, `false` otherwise.
    fn on_address_match(&mut self, address: u8) -> bool;
}
