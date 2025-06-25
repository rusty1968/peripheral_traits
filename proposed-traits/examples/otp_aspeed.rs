//! ASPEED-specific OTP (One-Time Programmable) memory traits
//!
//! This module provides specialized traits for ASPEED SoC OTP memory controllers,
//! extending the generic OTP interface to support ASPEED-specific features such as:
//! - Multiple memory regions (data, configuration, strap)
//! - Hardware strap programming with limited write attempts
//! - Protection mechanisms and security features
//! - Session-based access control
//!
//! # Supported ASPEED SoCs
//! - AST1030A0/A1
//! - AST1035A1
//! - AST1060A1/A2

use core::fmt::Debug;
use proposed_traits::otp::{ErrorType, Error, ErrorKind, OtpSession, OtpRegions};

/// ASPEED-specific OTP error kinds extending the generic error kinds
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[non_exhaustive]
pub enum AspeedErrorKind {
    /// Generic OTP error
    Generic(ErrorKind),
    /// Strap bit has no remaining write attempts
    StrapExhausted,
    /// Invalid strap bit offset  
    InvalidStrapBit,
    /// Unsupported chip version
    UnsupportedChip,
    /// Hardware is in locked state
    HardwareLocked,
    /// Invalid image format or checksum
    InvalidImage,
}

/// ASPEED-specific error type that implements the generic Error trait
#[derive(Debug, Copy, Clone)]
pub struct AspeedOtpError {
    kind: AspeedErrorKind,
}

impl AspeedOtpError {
    pub fn new(kind: AspeedErrorKind) -> Self {
        Self { kind }
    }
    
    pub fn aspeed_kind(&self) -> AspeedErrorKind {
        self.kind
    }
}

impl Error for AspeedOtpError {
    fn kind(&self) -> ErrorKind {
        match self.kind {
            AspeedErrorKind::Generic(kind) => kind,
            AspeedErrorKind::StrapExhausted => ErrorKind::WriteExhausted,
            AspeedErrorKind::InvalidStrapBit => ErrorKind::InvalidAddress,
            AspeedErrorKind::UnsupportedChip => ErrorKind::Unknown,
            AspeedErrorKind::HardwareLocked => ErrorKind::MemoryLocked,
            AspeedErrorKind::InvalidImage => ErrorKind::Unknown,
        }
    }
}

impl core::convert::From<ErrorKind> for AspeedOtpError {
    fn from(kind: ErrorKind) -> Self {
        Self::new(AspeedErrorKind::Generic(kind))
    }
}

/// ASPEED chip version information
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AspeedChipVersion {
    /// AST1030 A0 revision
    Ast1030A0,
    /// AST1030 A1 revision
    Ast1030A1,
    /// AST1035 A1 revision
    Ast1035A1,
    /// AST1060 A1 revision
    Ast1060A1,
    /// AST1060 A2 revision
    Ast1060A2,
    /// Unknown or unsupported version
    Unknown,
}

/// Memory region types in ASPEED OTP
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AspeedOtpRegion {
    /// Data region (2048 double-words, 0x0000-0x0FFF)
    Data,
    /// Configuration region (32 double-words, 0x800-0x81F)
    Configuration,
    /// Strap region (64 bits, multiple programming options)
    Strap,
    /// SCU protection region (2 double-words, 0x1C-0x1D)
    ScuProtection,
}

/// Protection status for different OTP regions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtectionStatus {
    /// Memory lock status (prevents all modifications)
    pub memory_locked: bool,
    /// Key return protection status
    pub key_protected: bool,
    /// Strap region protection status
    pub strap_protected: bool,
    /// Configuration region protection status
    pub config_protected: bool,
    /// Data region protection status
    pub data_protected: bool,
    /// Security region protection status
    pub security_protected: bool,
    /// Security region size in bytes
    pub security_size: u32,
}

/// Strap bit programming status
#[derive(Debug, Clone, Copy)]
pub struct StrapStatus {
    /// Current strap bit value
    pub value: bool,
    /// Programming options available
    pub options: [u8; 7],
    /// Remaining write attempts
    pub remaining_writes: u8,
    /// Next writable option
    pub writable_option: u8,
    /// Protection status for this strap bit
    pub protected: bool,
}

/// Session information provided during OTP session establishment
#[derive(Debug, Clone)]
pub struct SessionInfo {
    /// Chip version detected
    pub chip_version: AspeedChipVersion,
    /// Version name string
    pub version_name: [u8; 10],
    /// Current protection status
    pub protection_status: ProtectionStatus,
    /// Tool version information
    pub tool_version: [u8; 32],
    /// Software revision ID
    pub software_revision: u32,
    /// Number of cryptographic keys stored
    pub key_count: u32,
}



/// Core ASPEED OTP session management trait
///
/// This trait extends the generic OtpSession with ASPEED-specific session information
/// and protection status management.
pub trait AspeedOtpSession: ErrorType + OtpSession<SessionInfo = SessionInfo> {
    /// Get current protection status
    ///
    /// # Returns
    /// - `Ok(ProtectionStatus)`: Current protection status
    /// - `Err(Self::Error)`: Failed to read protection status
    ///
    /// # Errors
    /// - No active session
    /// - Hardware access failure
    fn get_protection_status(&self) -> Result<ProtectionStatus, Self::Error>;
}

/// ASPEED OTP data region operations
///
/// The data region provides 2048 double-words (8KB) of general-purpose OTP storage
/// suitable for cryptographic keys, certificates, and user data.
/// 
/// This trait extends the generic OtpRegions trait for data region specific operations.
pub trait AspeedOtpData: AspeedOtpSession + OtpRegions<u32, Region = AspeedOtpRegion> {
    /// Read data from the OTP data region
    ///
    /// # Arguments
    /// - `offset`: Word offset within the data region (0-2047)
    /// - `buffer`: Buffer to store read data
    ///
    /// # Returns
    /// - `Ok(())`: Data read successfully
    /// - `Err(Self::Error)`: Read operation failed
    ///
    /// # Errors
    /// - No active session
    /// - Invalid offset or buffer length
    /// - Hardware access failure
    /// - Boundary violation (offset + buffer.len() > 2048)
    fn read_data(&self, offset: u32, buffer: &mut [u32]) -> Result<(), Self::Error> {
        self.read_region(AspeedOtpRegion::Data, offset as usize, buffer)
    }

    /// Program data to the OTP data region
    ///
    /// # Arguments
    /// - `offset`: Word offset within the data region (0-2047)
    /// - `data`: Data to program
    ///
    /// # Returns
    /// - `Ok(())`: Data programmed and verified successfully
    /// - `Err(Self::Error)`: Programming operation failed
    ///
    /// # Errors
    /// - No active session
    /// - Data region is protected
    /// - Invalid offset or data length
    /// - Programming verification failed
    /// - Hardware programming failure
    /// - Boundary violation (offset + data.len() > 2048)
    fn program_data(&mut self, offset: u32, data: &[u32]) -> Result<(), Self::Error> {
        self.write_region(AspeedOtpRegion::Data, offset as usize, data)
    }

    /// Get the maximum data region capacity in words
    fn data_capacity(&self) -> u32 {
        2048
    }
}

/// ASPEED OTP configuration region operations
///
/// The configuration region provides 32 double-words (128 bytes) for system
/// configuration data, boot parameters, and security settings.
pub trait AspeedOtpConfig: AspeedOtpSession {
    /// Read configuration data
    ///
    /// # Arguments
    /// - `offset`: Word offset within the configuration region (0-31)
    /// - `buffer`: Buffer to store read configuration data
    ///
    /// # Returns
    /// - `Ok(())`: Configuration read successfully
    /// - `Err(Self::Error)`: Read operation failed
    ///
    /// # Errors
    /// - No active session
    /// - Invalid offset or buffer length
    /// - Hardware access failure
    /// - Boundary violation (offset + buffer.len() > 32)
    fn read_config(&self, offset: u32, buffer: &mut [u32]) -> Result<(), Self::Error>;

    /// Program configuration data
    ///
    /// # Arguments
    /// - `offset`: Word offset within the configuration region (0-31)
    /// - `data`: Configuration data to program
    ///
    /// # Returns
    /// - `Ok(())`: Configuration programmed successfully
    /// - `Err(Self::Error)`: Programming operation failed
    ///
    /// # Errors
    /// - No active session
    /// - Configuration region is protected
    /// - Invalid offset or data length
    /// - Programming verification failed
    /// - Boundary violation (offset + data.len() > 32)
    fn program_config(&mut self, offset: u32, data: &[u32]) -> Result<(), Self::Error>;

    /// Get the maximum configuration region capacity in words
    fn config_capacity(&self) -> u32 {
        32
    }
}

/// ASPEED OTP strap programming operations
///
/// Hardware straps control SoC pin multiplexing, boot modes, and other
/// hardware configuration. Each strap bit has limited write attempts.
pub trait AspeedOtpStrap: AspeedOtpSession {
    /// Read all strap bits
    ///
    /// # Arguments
    /// - `buffer`: 2-word buffer to store strap bits (64 bits total)
    ///
    /// # Returns
    /// - `Ok(())`: Strap bits read successfully
    /// - `Err(Self::Error)`: Read operation failed
    ///
    /// # Errors
    /// - No active session
    /// - Invalid buffer size (must be exactly 2 words)
    /// - Hardware access failure
    fn read_straps(&self, buffer: &mut [u32; 2]) -> Result<(), Self::Error>;

    /// Get status for a specific strap bit
    ///
    /// # Arguments
    /// - `bit_offset`: Strap bit number (0-63)
    ///
    /// # Returns
    /// - `Ok(StrapStatus)`: Current status of the strap bit
    /// - `Err(Self::Error)`: Failed to get strap status
    ///
    /// # Errors
    /// - No active session
    /// - Invalid strap bit offset (> 63)
    /// - Hardware access failure
    fn get_strap_status(&self, bit_offset: u8) -> Result<StrapStatus, Self::Error>;

    /// Program a single strap bit
    ///
    /// # Arguments
    /// - `bit_offset`: Strap bit number (0-63)
    /// - `value`: Value to program (true or false)
    ///
    /// # Returns
    /// - `Ok(())`: Strap bit programmed successfully
    /// - `Err(Self::Error)`: Programming operation failed
    ///
    /// # Errors
    /// - No active session
    /// - Strap region is protected
    /// - Invalid strap bit offset
    /// - No remaining write attempts for this bit
    /// - Programming verification failed
    fn program_strap_bit(&mut self, bit_offset: u8, value: bool) -> Result<(), Self::Error>;

    /// Get total number of strap bits
    fn strap_bit_count(&self) -> u8 {
        64
    }
}

/// ASPEED OTP image programming operations
///
/// Supports programming complete OTP images containing data, configuration,
/// and strap settings with verification and validation.
pub trait AspeedOtpImage: AspeedOtpSession + AspeedOtpData + AspeedOtpConfig + AspeedOtpStrap {
    /// Program a complete OTP image
    ///
    /// This method programs all regions (data, config, strap) from a single
    /// image with proper verification and validation.
    ///
    /// # Arguments
    /// - `image_data`: Complete OTP image data
    ///
    /// # Returns
    /// - `Ok(())`: Image programmed successfully
    /// - `Err(Self::Error)`: Image programming failed
    ///
    /// # Errors
    /// - No active session
    /// - Invalid image format or checksum
    /// - One or more regions are protected
    /// - Programming verification failed
    fn program_image(&mut self, image_data: &[u8]) -> Result<(), Self::Error>;

    /// Validate an OTP image without programming
    ///
    /// # Arguments
    /// - `image_data`: OTP image data to validate
    ///
    /// # Returns
    /// - `Ok(())`: Image is valid and can be programmed
    /// - `Err(Self::Error)`: Image validation failed
    ///
    /// # Errors
    /// - Invalid image format
    /// - Checksum mismatch
    /// - Unsupported chip version in image
    /// - Image too large for available OTP space
    fn validate_image(&self, image_data: &[u8]) -> Result<(), Self::Error>;
}

/// ASPEED OTP security and protection operations
///
/// Provides advanced security features including protection control,
/// key management, and secure boot support.
pub trait AspeedOtpSecurity: AspeedOtpSession {
    /// Enable protection for a specific region
    ///
    /// # Arguments
    /// - `region`: Region to protect
    ///
    /// # Returns
    /// - `Ok(())`: Protection enabled successfully
    /// - `Err(Self::Error)`: Failed to enable protection
    ///
    /// # Errors
    /// - No active session
    /// - Invalid region
    /// - Hardware access failure
    /// - Region already protected
    fn enable_region_protection(&mut self, region: AspeedOtpRegion) -> Result<(), Self::Error>;

    /// Check if a region is protected
    ///
    /// # Arguments
    /// - `region`: Region to check
    ///
    /// # Returns
    /// - `Ok(bool)`: Protection status (true = protected)
    /// - `Err(Self::Error)`: Failed to check protection status
    fn is_region_protected(&self, region: AspeedOtpRegion) -> Result<bool, Self::Error>;

    /// Enable global memory lock (irreversible)
    ///
    /// This operation permanently locks all OTP regions and cannot be undone.
    /// Use with extreme caution.
    ///
    /// # Returns
    /// - `Ok(())`: Memory lock enabled successfully
    /// - `Err(Self::Error)`: Failed to enable memory lock
    ///
    /// # Errors
    /// - No active session
    /// - Hardware access failure
    /// - Memory already locked
    fn enable_memory_lock(&mut self) -> Result<(), Self::Error>;

    /// Check if memory is globally locked
    ///
    /// # Returns
    /// - `Ok(bool)`: Lock status (true = locked)
    /// - `Err(Self::Error)`: Failed to check lock status
    fn is_memory_locked(&self) -> Result<bool, Self::Error>;

    /// Get number of cryptographic keys stored
    ///
    /// # Returns
    /// - `Ok(u32)`: Number of keys stored in OTP
    /// - `Err(Self::Error)`: Failed to get key count
    fn get_key_count(&self) -> Result<u32, Self::Error>;

    /// Enable soak programming mode for difficult bits
    ///
    /// Soak mode uses extended programming timing for bits that are
    /// difficult to program with standard timing.
    ///
    /// # Arguments
    /// - `enable`: True to enable soak mode, false to disable
    ///
    /// # Returns
    /// - `Ok(())`: Soak mode setting applied successfully
    /// - `Err(Self::Error)`: Failed to set soak mode
    fn set_soak_mode(&mut self, enable: bool) -> Result<(), Self::Error>;
}

/// Full ASPEED OTP controller interface
///
/// This convenience trait combines all ASPEED OTP capabilities into a single
/// interface for devices that support all features.
pub trait AspeedOtpController:
    AspeedOtpSession + AspeedOtpData + AspeedOtpConfig + AspeedOtpStrap + AspeedOtpImage + AspeedOtpSecurity
{
    /// Get the detected chip version
    fn chip_version(&self) -> AspeedChipVersion;

    /// Get a human-readable version string
    fn version_string(&self) -> &str;

    /// Perform a complete OTP health check
    ///
    /// This method validates the OTP controller state, protection settings,
    /// and performs basic functionality tests.
    ///
    /// # Returns
    /// - `Ok(())`: OTP controller is healthy
    /// - `Err(Self::Error)`: Health check failed
    fn health_check(&mut self) -> Result<(), Self::Error>;
}

// Automatic implementation for types that implement all required traits
impl<T> AspeedOtpController for T
where
    T: AspeedOtpSession
        + AspeedOtpData
        + AspeedOtpConfig
        + AspeedOtpStrap
        + AspeedOtpImage
        + AspeedOtpSecurity,
{
    fn chip_version(&self) -> AspeedChipVersion {
        // Default implementation - should be overridden by implementors
        AspeedChipVersion::Unknown
    }

    fn version_string(&self) -> &str {
        // Default implementation - should be overridden by implementors
        "Unknown"
    }

    fn health_check(&mut self) -> Result<(), Self::Error> {
        // Default implementation performs basic checks
        // Implementors should override with comprehensive testing
        
        // Check if session can be established
        let _session_info = self.begin_session()?;
        
        // Check protection status
        let _protection = self.get_protection_status()?;
        
        // Check memory lock status
        let _locked = self.is_memory_locked()?;
        
        // End session
        self.end_session()?;
        
        Ok(())
    }
}

// Example controller for demonstration purposes (not in test module)
pub struct ExampleOtpController;

// Example error type
#[derive(Debug, Clone, Copy)]
pub struct ExampleError;

impl proposed_traits::otp::Error for ExampleError {
    fn kind(&self) -> proposed_traits::otp::ErrorKind {
        proposed_traits::otp::ErrorKind::WriteFailed
    }
}

impl ErrorType for ExampleOtpController {
    type Error = ExampleError;
}

impl proposed_traits::otp::OtpSession for ExampleOtpController {
    type SessionInfo = SessionInfo;

    fn begin_session(&mut self) -> Result<SessionInfo, Self::Error> {
        Ok(SessionInfo {
            chip_version: AspeedChipVersion::Ast1060A1,
            version_name: *b"AST1060A1\0",
            protection_status: ProtectionStatus {
                memory_locked: false,
                key_protected: false,
                strap_protected: false,
                config_protected: false,
                data_protected: false,
                security_protected: false,
                security_size: 0,
            },
            tool_version: [0; 32],
            software_revision: 0x12345678,
            key_count: 5,
        })
    }

    fn end_session(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    fn is_session_active(&self) -> bool {
        true
    }
}

impl proposed_traits::otp::OtpRegions<u32> for ExampleOtpController {
    type Region = AspeedOtpRegion;

    fn read_region(&self, _region: Self::Region, _offset: usize, _buffer: &mut [u32]) -> Result<(), Self::Error> {
        Ok(())
    }

    fn write_region(&mut self, _region: Self::Region, _offset: usize, _data: &[u32]) -> Result<(), Self::Error> {
        Ok(())
    }

    fn region_capacity(&self, region: Self::Region) -> usize {
        match region {
            AspeedOtpRegion::Data => 2048,
            AspeedOtpRegion::Configuration => 32,
            AspeedOtpRegion::Strap => 2,
            AspeedOtpRegion::ScuProtection => 2,
        }
    }

    fn region_alignment(&self, _region: Self::Region) -> usize {
        4
    }
}

impl AspeedOtpSession for ExampleOtpController {
    fn get_protection_status(&self) -> Result<ProtectionStatus, Self::Error> {
        Ok(ProtectionStatus {
            memory_locked: false,
            key_protected: false,
            strap_protected: false,
            config_protected: false,
            data_protected: false,
            security_protected: false,
            security_size: 0,
        })
    }
}

impl AspeedOtpData for ExampleOtpController {
    fn read_data(&self, _offset: u32, _buffer: &mut [u32]) -> Result<(), Self::Error> {
        Ok(())
    }

    fn program_data(&mut self, _offset: u32, _data: &[u32]) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl AspeedOtpConfig for ExampleOtpController {
    fn read_config(&self, _offset: u32, _buffer: &mut [u32]) -> Result<(), Self::Error> {
        Ok(())
    }

    fn program_config(&mut self, _offset: u32, _data: &[u32]) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl AspeedOtpStrap for ExampleOtpController {
    fn read_straps(&self, _buffer: &mut [u32; 2]) -> Result<(), Self::Error> {
        Ok(())
    }

    fn get_strap_status(&self, _bit_offset: u8) -> Result<StrapStatus, Self::Error> {
        Ok(StrapStatus {
            value: false,
            options: [0; 7],
            remaining_writes: 3,
            writable_option: 1,
            protected: false,
        })
    }

    fn program_strap_bit(&mut self, _bit_offset: u8, _value: bool) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl AspeedOtpImage for ExampleOtpController {
    fn program_image(&mut self, _image_data: &[u8]) -> Result<(), Self::Error> {
        Ok(())
    }

    fn validate_image(&self, _image_data: &[u8]) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl AspeedOtpSecurity for ExampleOtpController {
    fn enable_region_protection(&mut self, _region: AspeedOtpRegion) -> Result<(), Self::Error> {
        Ok(())
    }

    fn is_region_protected(&self, _region: AspeedOtpRegion) -> Result<bool, Self::Error> {
        Ok(false)
    }

    fn enable_memory_lock(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    fn is_memory_locked(&self) -> Result<bool, Self::Error> {
        Ok(false)
    }

    fn get_key_count(&self) -> Result<u32, Self::Error> {
        Ok(5)
    }

    fn set_soak_mode(&mut self, _enable: bool) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proposed_traits::otp::ErrorType;

    // Mock error type for testing
    #[derive(Debug, Clone, Copy)]
    struct MockError;

    impl Error for MockError {
        fn kind(&self) -> ErrorKind {
            ErrorKind::WriteFailed
        }
    }

    // Mock OTP controller for testing
    struct MockOtpController;

    impl ErrorType for MockOtpController {
        type Error = MockError;
    }

    impl OtpSession for MockOtpController {
        type SessionInfo = SessionInfo;

        fn begin_session(&mut self) -> Result<SessionInfo, Self::Error> {
            Ok(SessionInfo {
                chip_version: AspeedChipVersion::Ast1060A1,
                version_name: *b"AST1060A1\0",
                protection_status: ProtectionStatus {
                    memory_locked: false,
                    key_protected: false,
                    strap_protected: false,
                    config_protected: false,
                    data_protected: false,
                    security_protected: false,
                    security_size: 0,
                },
                tool_version: [0; 32],
                software_revision: 0x12345678,
                key_count: 5,
            })
        }

        fn end_session(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }

        fn is_session_active(&self) -> bool {
            true
        }
    }

    impl AspeedOtpSession for MockOtpController {
        fn get_protection_status(&self) -> Result<ProtectionStatus, Self::Error> {
            Ok(ProtectionStatus {
                memory_locked: false,
                key_protected: false,
                strap_protected: false,
                config_protected: false,
                data_protected: false,
                security_protected: false,
                security_size: 0,
            })
        }
    }

    impl OtpRegions<u32> for MockOtpController {
        type Region = AspeedOtpRegion;

        fn read_region(&self, _region: Self::Region, _offset: usize, _buffer: &mut [u32]) -> Result<(), Self::Error> {
            Ok(())
        }

        fn write_region(&mut self, _region: Self::Region, _offset: usize, _data: &[u32]) -> Result<(), Self::Error> {
            Ok(())
        }

        fn region_capacity(&self, region: Self::Region) -> usize {
            match region {
                AspeedOtpRegion::Data => 2048,
                AspeedOtpRegion::Configuration => 32,
                AspeedOtpRegion::Strap => 2,
                AspeedOtpRegion::ScuProtection => 2,
            }
        }

        fn region_alignment(&self, _region: Self::Region) -> usize {
            4 // 4-byte alignment for u32
        }
    }

    impl AspeedOtpData for MockOtpController {
        fn read_data(&self, _offset: u32, _buffer: &mut [u32]) -> Result<(), Self::Error> {
            Ok(())
        }

        fn program_data(&mut self, _offset: u32, _data: &[u32]) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    impl AspeedOtpConfig for MockOtpController {
        fn read_config(&self, _offset: u32, _buffer: &mut [u32]) -> Result<(), Self::Error> {
            Ok(())
        }

        fn program_config(&mut self, _offset: u32, _data: &[u32]) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    impl AspeedOtpStrap for MockOtpController {
        fn read_straps(&self, _buffer: &mut [u32; 2]) -> Result<(), Self::Error> {
            Ok(())
        }

        fn get_strap_status(&self, _bit_offset: u8) -> Result<StrapStatus, Self::Error> {
            Ok(StrapStatus {
                value: false,
                options: [0; 7],
                remaining_writes: 3,
                writable_option: 1,
                protected: false,
            })
        }

        fn program_strap_bit(&mut self, _bit_offset: u8, _value: bool) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    impl AspeedOtpImage for MockOtpController {
        fn program_image(&mut self, _image_data: &[u8]) -> Result<(), Self::Error> {
            Ok(())
        }

        fn validate_image(&self, _image_data: &[u8]) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    impl AspeedOtpSecurity for MockOtpController {
        fn enable_region_protection(&mut self, _region: AspeedOtpRegion) -> Result<(), Self::Error> {
            Ok(())
        }

        fn is_region_protected(&self, _region: AspeedOtpRegion) -> Result<bool, Self::Error> {
            Ok(false)
        }

        fn enable_memory_lock(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }

        fn is_memory_locked(&self) -> Result<bool, Self::Error> {
            Ok(false)
        }

        fn get_key_count(&self) -> Result<u32, Self::Error> {
            Ok(5)
        }

        fn set_soak_mode(&mut self, _enable: bool) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[test]
    fn test_mock_controller_implements_full_interface() {
        let mut controller = MockOtpController;
        
        // Test that it implements AspeedOtpController
        assert_eq!(controller.chip_version(), AspeedChipVersion::Unknown);
        assert_eq!(controller.version_string(), "Unknown");
        
        // Test health check
        controller.health_check().unwrap();
    }

    #[test]
    fn test_session_info_creation() {
        let session_info = SessionInfo {
            chip_version: AspeedChipVersion::Ast1060A1,
            version_name: *b"AST1060A1\0",
            protection_status: ProtectionStatus {
                memory_locked: false,
                key_protected: true,
                strap_protected: false,
                config_protected: false,
                data_protected: false,
                security_protected: true,
                security_size: 1024,
            },
            tool_version: [0; 32],
            software_revision: 0x12345678,
            key_count: 10,
        };

        assert_eq!(session_info.chip_version, AspeedChipVersion::Ast1060A1);
        assert!(session_info.protection_status.key_protected);
        assert!(!session_info.protection_status.memory_locked);
        assert_eq!(session_info.key_count, 10);
    }

    #[test]
    fn test_region_types() {
        let regions = [
            AspeedOtpRegion::Data,
            AspeedOtpRegion::Configuration,
            AspeedOtpRegion::Strap,
            AspeedOtpRegion::ScuProtection,
        ];

        for region in &regions {
            // Test that regions can be compared
            assert_eq!(*region, *region);
        }
    }

    #[test]
    fn test_chip_versions() {
        let versions = [
            AspeedChipVersion::Ast1030A0,
            AspeedChipVersion::Ast1030A1,
            AspeedChipVersion::Ast1035A1,
            AspeedChipVersion::Ast1060A1,
            AspeedChipVersion::Ast1060A2,
            AspeedChipVersion::Unknown,
        ];

        for version in &versions {
            // Test that versions can be compared
            assert_eq!(*version, *version);
        }
    }
}

/// Example demonstrating ASPEED OTP controller usage
fn main() {
    println!("ASPEED OTP Controller Example");
    println!("============================");
    
    // Create an example ASPEED OTP controller
    let mut controller = ExampleOtpController;
    
    // Demonstrate session management
    println!("1. Establishing OTP session...");
    match controller.begin_session() {
        Ok(session_info) => {
            println!("   ✓ Session established successfully");
            println!("   Chip version: {:?}", session_info.chip_version);
            println!("   Software revision: 0x{:08X}", session_info.software_revision);
            println!("   Key count: {}", session_info.key_count);
        }
        Err(_) => println!("   ✗ Failed to establish session"),
    }
    
    // Demonstrate data operations
    println!("\n2. Testing data region operations...");
    match controller.read_data(0, &mut [0u32; 4]) {
        Ok(_) => println!("   ✓ Data read successful"),
        Err(_) => println!("   ✗ Data read failed"),
    }
    
    let test_data = [0x12345678, 0xDEADBEEF, 0xCAFEBABE, 0xFEEDFACE];
    match controller.program_data(0, &test_data) {
        Ok(_) => println!("   ✓ Data programming successful"),
        Err(_) => println!("   ✗ Data programming failed"),
    }
    
    // Demonstrate strap operations
    println!("\n3. Testing strap operations...");
    let mut strap_buffer = [0u32; 2];
    match controller.read_straps(&mut strap_buffer) {
        Ok(_) => println!("   ✓ Strap read successful"),
        Err(_) => println!("   ✗ Strap read failed"),
    }
    
    match controller.get_strap_status(5) {
        Ok(status) => {
            println!("   ✓ Strap bit 5 status:");
            println!("     Value: {}", status.value);
            println!("     Remaining writes: {}", status.remaining_writes);
            println!("     Protected: {}", status.protected);
        }
        Err(_) => println!("   ✗ Failed to get strap status"),
    }
    
    // Demonstrate soak programming
    println!("\n4. Testing soak programming...");
    match controller.set_soak_mode(true) {
        Ok(_) => println!("   ✓ Soak mode enabled"),
        Err(_) => println!("   ✗ Failed to enable soak mode"),
    }
    
    // Demonstrate protection features
    println!("\n5. Testing protection features...");
    match controller.get_protection_status() {
        Ok(status) => {
            println!("   ✓ Protection status:");
            println!("     Memory locked: {}", status.memory_locked);
            println!("     Data protected: {}", status.data_protected);
            println!("     Config protected: {}", status.config_protected);
            println!("     Strap protected: {}", status.strap_protected);
        }
        Err(_) => println!("   ✗ Failed to get protection status"),
    }
    
    // Demonstrate health check
    println!("\n6. Running health check...");
    match controller.health_check() {
        Ok(_) => println!("   ✓ Health check passed"),
        Err(_) => println!("   ✗ Health check failed"),
    }
    
    // Clean up
    println!("\n7. Terminating session...");
    match controller.end_session() {
        Ok(_) => println!("   ✓ Session terminated successfully"),
        Err(_) => println!("   ✗ Failed to terminate session"),
    }
    
    println!("\nExample completed successfully!");
    println!("\nThis example demonstrates:");
    println!("- Session-based access control");
    println!("- Multi-region OTP operations (data, config, strap)");
    println!("- Strap bit programming with status tracking");
    println!("- Soak programming for difficult bits");
    println!("- Protection mechanisms and status queries");
    println!("- Health checking and error handling");
    println!("\nThe ASPEED OTP traits extend the generic OTP traits");
    println!("to provide vendor-specific functionality while maintaining");
    println!("compatibility with generic OTP application code.");
}
