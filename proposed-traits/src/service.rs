/// Trait for services that can handle interrupt notifications.
pub trait Interruptible {
    /// Returns the notification bitmask this service is interested in.
    fn notification_mask(&self) -> u32;

    /// Called when an interrupt fires with the matching notification bits.
    fn on_notification(&mut self, irq_bits: u32);
}

pub trait Service  {
    type Request : ToBytes;
    type Response : FromBytes;
    type Error;

    fn handle(&mut self, op: u16, request: Self::Request) -> Result<Self::Response, Self::Error>;

}




