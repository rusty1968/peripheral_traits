pub mod delay;
pub mod digital;
pub mod spi;
pub mod digest;

pub use digital::{SimulatedInputPin, SimulatedOutputPin};
pub use spi::SimulatedSpiBus;

pub struct SimulatedPac {
    pub busy_pin: SimulatedInputPin,
    pub reset_pin: SimulatedOutputPin,
    pub cs_pin: SimulatedOutputPin,
    pub spi_master: SimulatedSpiBus,
}

impl SimulatedPac {
    pub fn new() -> Self {
        Self {
            busy_pin: SimulatedInputPin::default(),
            reset_pin: SimulatedOutputPin::new(),
            cs_pin: SimulatedOutputPin::new(),
            spi_master: SimulatedSpiBus::default(),
        }
    }
}
