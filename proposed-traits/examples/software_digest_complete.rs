/// Software implementation of digest traits using RustCrypto crates
/// 
/// This example demonstrates how to implement the digest traits using
/// software crypto libraries. It provides working implementations for
/// SHA-256, SHA-384, and SHA-512 using the `sha2` crate.
///
/// This implementation covers both the dynamic traits (DigestRegistry, DynamicDigestOp)
/// and the static traits (DigestAlgorithm, DigestInit, DigestOp) from the proposed_traits::digest module.

use core::fmt::Debug;
use proposed_traits::digest::{
    DigestRegistry, DynamicDigestOp, ErrorType, Error, ErrorKind,
    DigestAlgorithm, DigestInit, DigestOp, DigestCtrlReset
};

// Re-export crypto crates for convenience
pub use sha2::{Sha256, Sha384, Sha512, Digest};

/// Software-specific digest error types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SoftwareDigestError {
    /// Buffer too small for output
    BufferTooSmall,
    /// Unsupported algorithm
    UnsupportedAlgorithm,
    /// Invalid state (already finalized, etc.)
    InvalidState,
    /// Generic computation error
    ComputationError,
}

impl Error for SoftwareDigestError {
    fn kind(&self) -> ErrorKind {
        match self {
            SoftwareDigestError::BufferTooSmall => ErrorKind::InvalidOutputSize,
            SoftwareDigestError::UnsupportedAlgorithm => ErrorKind::UnsupportedAlgorithm,
            SoftwareDigestError::InvalidState => ErrorKind::NotInitialized,
            SoftwareDigestError::ComputationError => ErrorKind::HardwareFailure,
        }
    }
}

/// Algorithm identifiers for software implementation
pub mod algorithms {
    pub const SHA256: u32 = 0x01;
    pub const SHA384: u32 = 0x02;
    pub const SHA512: u32 = 0x03;
}

// === Static Digest Algorithm Implementations ===

/// SHA-256 algorithm marker type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sha256Algorithm;

/// SHA-384 algorithm marker type  
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sha384Algorithm;

/// SHA-512 algorithm marker type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sha512Algorithm;

/// Fixed-size array wrapper for digest outputs
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DigestOutput<const N: usize>([u8; N]);

impl<const N: usize> DigestOutput<N> {
    pub fn new(data: [u8; N]) -> Self {
        Self(data)
    }
    
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> AsRef<[u8]> for DigestOutput<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> From<[u8; N]> for DigestOutput<N> {
    fn from(data: [u8; N]) -> Self {
        Self(data)
    }
}

// Implement DigestAlgorithm for each algorithm

impl DigestAlgorithm for Sha256Algorithm {
    const OUTPUT_BITS: usize = 256;
    type DigestOutput = [u8; 32]; // 256 bits = 32 bytes
}

impl DigestAlgorithm for Sha384Algorithm {
    const OUTPUT_BITS: usize = 384;
    type DigestOutput = [u8; 48]; // 384 bits = 48 bytes
}

impl DigestAlgorithm for Sha512Algorithm {
    const OUTPUT_BITS: usize = 512;
    type DigestOutput = [u8; 64]; // 512 bits = 64 bytes
}

/// SHA-256 specific static digest operation
pub struct Sha256StaticOp {
    hasher: Sha256,
    finalized: bool,
}

/// SHA-384 specific static digest operation
pub struct Sha384StaticOp {
    hasher: Sha384,
    finalized: bool,
}

/// SHA-512 specific static digest operation
pub struct Sha512StaticOp {
    hasher: Sha512,
    finalized: bool,
}

impl Sha256StaticOp {
    fn new() -> Self {
        Self {
            hasher: Sha256::new(),
            finalized: false,
        }
    }
}

impl Sha384StaticOp {
    fn new() -> Self {
        Self {
            hasher: Sha384::new(),
            finalized: false,
        }
    }
}

impl Sha512StaticOp {
    fn new() -> Self {
        Self {
            hasher: Sha512::new(),
            finalized: false,
        }
    }
}

impl ErrorType for Sha256StaticOp {
    type Error = SoftwareDigestError;
}

impl ErrorType for Sha384StaticOp {
    type Error = SoftwareDigestError;
}

impl ErrorType for Sha512StaticOp {
    type Error = SoftwareDigestError;
}

impl DigestOp for Sha256StaticOp {
    type Output = [u8; 32];

    fn update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        if self.finalized {
            return Err(SoftwareDigestError::InvalidState);
        }
        
        self.hasher.update(input);
        Ok(())
    }

    fn finalize(mut self) -> Result<Self::Output, Self::Error> {
        if self.finalized {
            return Err(SoftwareDigestError::InvalidState);
        }
        
        self.finalized = true;
        let result = self.hasher.finalize();
        
        // Convert to fixed-size array
        let mut output = [0u8; 32];
        output.copy_from_slice(&result);
        Ok(output)
    }
}

impl DigestOp for Sha384StaticOp {
    type Output = [u8; 48];

    fn update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        if self.finalized {
            return Err(SoftwareDigestError::InvalidState);
        }
        
        self.hasher.update(input);
        Ok(())
    }

    fn finalize(mut self) -> Result<Self::Output, Self::Error> {
        if self.finalized {
            return Err(SoftwareDigestError::InvalidState);
        }
        
        self.finalized = true;
        let result = self.hasher.finalize();
        
        // Convert to fixed-size array
        let mut output = [0u8; 48];
        output.copy_from_slice(&result);
        Ok(output)
    }
}

impl DigestOp for Sha512StaticOp {
    type Output = [u8; 64];

    fn update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        if self.finalized {
            return Err(SoftwareDigestError::InvalidState);
        }
        
        self.hasher.update(input);
        Ok(())
    }

    fn finalize(mut self) -> Result<Self::Output, Self::Error> {
        if self.finalized {
            return Err(SoftwareDigestError::InvalidState);
        }
        
        self.finalized = true;
        let result = self.hasher.finalize();
        
        // Convert to fixed-size array
        let mut output = [0u8; 64];
        output.copy_from_slice(&result);
        Ok(output)
    }
}

impl DigestCtrlReset for Sha256StaticOp {
    fn reset(&mut self) -> Result<(), Self::Error> {
        self.hasher = Sha256::new();
        self.finalized = false;
        Ok(())
    }
}

impl DigestCtrlReset for Sha384StaticOp {
    fn reset(&mut self) -> Result<(), Self::Error> {
        self.hasher = Sha384::new();
        self.finalized = false;
        Ok(())
    }
}

impl DigestCtrlReset for Sha512StaticOp {
    fn reset(&mut self) -> Result<(), Self::Error> {
        self.hasher = Sha512::new();
        self.finalized = false;
        Ok(())
    }
}

/// Software digest provider for static API
pub struct SoftwareDigestProvider;

impl SoftwareDigestProvider {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SoftwareDigestProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl ErrorType for SoftwareDigestProvider {
    type Error = SoftwareDigestError;
}

// Implement DigestInit for each algorithm

impl DigestInit<Sha256Algorithm> for SoftwareDigestProvider {
    type OpContext<'a> = Sha256StaticOp where Self: 'a;

    fn init<'a>(&'a mut self, _algo: Sha256Algorithm) -> Result<Self::OpContext<'a>, Self::Error> {
        Ok(Sha256StaticOp::new())
    }
}

impl DigestInit<Sha384Algorithm> for SoftwareDigestProvider {
    type OpContext<'a> = Sha384StaticOp where Self: 'a;

    fn init<'a>(&'a mut self, _algo: Sha384Algorithm) -> Result<Self::OpContext<'a>, Self::Error> {
        Ok(Sha384StaticOp::new())
    }
}

impl DigestInit<Sha512Algorithm> for SoftwareDigestProvider {
    type OpContext<'a> = Sha512StaticOp where Self: 'a;

    fn init<'a>(&'a mut self, _algo: Sha512Algorithm) -> Result<Self::OpContext<'a>, Self::Error> {
        Ok(Sha512StaticOp::new())
    }
}

// === Dynamic Digest Implementation ===

/// Generic wrapper for software digest implementations (dynamic API)
pub struct SoftwareDigestOp<D>
where
    D: Digest + Clone,
{
    hasher: D,
    algorithm_id: u32,
    finalized: bool,
}

impl<D> SoftwareDigestOp<D>
where
    D: Digest + Clone,
{
    pub fn new(hasher: D, algorithm_id: u32) -> Self {
        Self {
            hasher,
            algorithm_id,
            finalized: false,
        }
    }
}

impl<D> DynamicDigestOp for SoftwareDigestOp<D>
where
    D: Digest + Clone,
{
    type Error = SoftwareDigestError;
    type AlgorithmId = u32;

    fn update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        if self.finalized {
            return Err(SoftwareDigestError::InvalidState);
        }
        
        self.hasher.update(input);
        Ok(())
    }

    fn finalize(&mut self) -> Result<(), Self::Error> {
        if self.finalized {
            return Err(SoftwareDigestError::InvalidState);
        }
        
        self.finalized = true;
        Ok(())
    }

    fn output_size(&self) -> usize {
        <D as Digest>::output_size()
    }

    fn algorithm_id(&self) -> Self::AlgorithmId {
        self.algorithm_id
    }

    fn copy_output(&self, output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.finalized {
            return Err(SoftwareDigestError::InvalidState);
        }
        
        let output_size = self.output_size();
        if output.len() < output_size {
            return Err(SoftwareDigestError::BufferTooSmall);
        }

        // Clone the hasher to get the result without consuming it
        let result = self.hasher.clone().finalize();
        output[..output_size].copy_from_slice(&result);
        Ok(output_size)
    }
}

/// Software digest registry implementation
pub struct SoftwareDigestRegistry {
    supported_algorithms: &'static [u32],
}

impl SoftwareDigestRegistry {
    pub fn new() -> Self {
        Self {
            supported_algorithms: &[
                algorithms::SHA256,
                algorithms::SHA384,
                algorithms::SHA512,
            ],
        }
    }
}

impl Default for SoftwareDigestRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ErrorType for SoftwareDigestRegistry {
    type Error = SoftwareDigestError;
}

impl DigestRegistry for SoftwareDigestRegistry {
    type AlgorithmId = u32;
    type DigestOp = Box<dyn DynamicDigestOp<Error = SoftwareDigestError, AlgorithmId = u32>>;

    fn supports_algorithm(&self, algorithm_id: u32) -> bool {
        self.supported_algorithms.contains(&algorithm_id)
    }

    fn get_output_size(&self, algorithm_id: u32) -> Option<usize> {
        match algorithm_id {
            algorithms::SHA256 => Some(32),  // 256 bits = 32 bytes
            algorithms::SHA384 => Some(48),  // 384 bits = 48 bytes
            algorithms::SHA512 => Some(64),  // 512 bits = 64 bytes
            _ => None,
        }
    }

    fn create_digest(&mut self, algorithm_id: u32) -> Result<Self::DigestOp, Self::Error> {
        match algorithm_id {
            algorithms::SHA256 => {
                let op = SoftwareDigestOp::new(Sha256::new(), algorithm_id);
                Ok(Box::new(op))
            }
            algorithms::SHA384 => {
                let op = SoftwareDigestOp::new(Sha384::new(), algorithm_id);
                Ok(Box::new(op))
            }
            algorithms::SHA512 => {
                let op = SoftwareDigestOp::new(Sha512::new(), algorithm_id);
                Ok(Box::new(op))
            }
            _ => Err(SoftwareDigestError::UnsupportedAlgorithm),
        }
    }

    fn supported_algorithms(&self) -> &[u32] {
        self.supported_algorithms
    }
}

/// Convenience functions for direct use without the registry
pub mod direct {
    use super::*;

    /// Create a SHA-256 digest operation (dynamic)
    pub fn sha256_dynamic() -> SoftwareDigestOp<Sha256> {
        SoftwareDigestOp::new(Sha256::new(), algorithms::SHA256)
    }

    /// Create a SHA-384 digest operation (dynamic)
    pub fn sha384_dynamic() -> SoftwareDigestOp<Sha384> {
        SoftwareDigestOp::new(Sha384::new(), algorithms::SHA384)
    }

    /// Create a SHA-512 digest operation (dynamic)
    pub fn sha512_dynamic() -> SoftwareDigestOp<Sha512> {
        SoftwareDigestOp::new(Sha512::new(), algorithms::SHA512)
    }

    /// Create a SHA-256 digest operation (static)
    pub fn sha256_static() -> Sha256StaticOp {
        Sha256StaticOp::new()
    }

    /// Create a SHA-384 digest operation (static)
    pub fn sha384_static() -> Sha384StaticOp {
        Sha384StaticOp::new()
    }

    /// Create a SHA-512 digest operation (static)
    pub fn sha512_static() -> Sha512StaticOp {
        Sha512StaticOp::new()
    }

    /// Convenience function to compute SHA-256 hash in one call
    pub fn sha256_hash(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    /// Convenience function to compute SHA-384 hash in one call
    pub fn sha384_hash(data: &[u8]) -> [u8; 48] {
        let mut hasher = Sha384::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    /// Convenience function to compute SHA-512 hash in one call
    pub fn sha512_hash(data: &[u8]) -> [u8; 64] {
        let mut hasher = Sha512::new();
        hasher.update(data);
        hasher.finalize().into()
    }
}

/// High-level digest computer for easy use
pub struct DigestComputer {
    registry: SoftwareDigestRegistry,
    provider: SoftwareDigestProvider,
}

impl DigestComputer {
    pub fn new() -> Self {
        Self {
            registry: SoftwareDigestRegistry::new(),
            provider: SoftwareDigestProvider::new(),
        }
    }

    /// Compute digest for the given data and algorithm (dynamic API)
    pub fn compute_digest(&mut self, algorithm_id: u32, data: &[u8]) -> Result<Vec<u8>, SoftwareDigestError> {
        let mut digest_op = self.registry.create_digest(algorithm_id)?;
        digest_op.update(data)?;
        digest_op.finalize()?;

        let output_size = digest_op.output_size();
        let mut output = vec![0u8; output_size];
        let actual_size = digest_op.copy_output(&mut output)?;
        output.truncate(actual_size);
        Ok(output)
    }

    /// Compute digest with multiple updates (streaming, dynamic API)
    pub fn compute_digest_streaming<I>(&mut self, algorithm_id: u32, data_chunks: I) -> Result<Vec<u8>, SoftwareDigestError>
    where
        I: IntoIterator,
        I::Item: AsRef<[u8]>,
    {
        let mut digest_op = self.registry.create_digest(algorithm_id)?;
        
        for chunk in data_chunks {
            digest_op.update(chunk.as_ref())?;
        }
        
        digest_op.finalize()?;

        let output_size = digest_op.output_size();
        let mut output = vec![0u8; output_size];
        let actual_size = digest_op.copy_output(&mut output)?;
        output.truncate(actual_size);
        Ok(output)
    }

    /// Compute SHA-256 using static API
    pub fn compute_sha256_static(&mut self, data: &[u8]) -> Result<[u8; 32], SoftwareDigestError> {
        let mut op_context = self.provider.init(Sha256Algorithm)?;
        op_context.update(data)?;
        op_context.finalize()
    }

    /// Compute SHA-384 using static API
    pub fn compute_sha384_static(&mut self, data: &[u8]) -> Result<[u8; 48], SoftwareDigestError> {
        let mut op_context = self.provider.init(Sha384Algorithm)?;
        op_context.update(data)?;
        op_context.finalize()
    }

    /// Compute SHA-512 using static API
    pub fn compute_sha512_static(&mut self, data: &[u8]) -> Result<[u8; 64], SoftwareDigestError> {
        let mut op_context = self.provider.init(Sha512Algorithm)?;
        op_context.update(data)?;
        op_context.finalize()
    }

    /// Get information about a supported algorithm
    pub fn get_algorithm_info(&self, algorithm_id: u32) -> Option<(u32, usize, &'static str)> {
        if !self.registry.supports_algorithm(algorithm_id) {
            return None;
        }

        let size = self.registry.get_output_size(algorithm_id)?;
        let name = match algorithm_id {
            algorithms::SHA256 => "SHA-256",
            algorithms::SHA384 => "SHA-384", 
            algorithms::SHA512 => "SHA-512",
            _ => "Unknown",
        };

        Some((algorithm_id, size, name))
    }

    /// List all supported algorithms
    pub fn list_supported_algorithms(&self) -> Vec<(u32, usize, &'static str)> {
        self.registry
            .supported_algorithms()
            .iter()
            .filter_map(|&algo_id| self.get_algorithm_info(algo_id))
            .collect()
    }
}

impl Default for DigestComputer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proposed_traits::digest::{DigestOp as StaticDigestOpTrait, DynamicDigestOp as DynamicDigestOpTrait};

    #[test]
    fn test_static_api_sha256() {
        let mut provider = SoftwareDigestProvider::new();
        let mut op_context = provider.init(Sha256Algorithm).unwrap();
        
        let test_data = b"hello world";
        op_context.update(test_data).unwrap();
        let result = op_context.finalize().unwrap();
        
        assert_eq!(result.len(), 32);
        
        // Verify against direct computation
        let expected = direct::sha256_hash(test_data);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_static_api_reset() {
        let mut op_context = direct::sha256_static();
        
        op_context.update(b"first").unwrap();
        op_context.reset().unwrap();
        op_context.update(b"second").unwrap();
        let result = op_context.finalize().unwrap();
        
        // Should match direct computation of "second" only
        let expected = direct::sha256_hash(b"second");
        assert_eq!(result, expected);
    }

    #[test]
    fn test_dynamic_api_sha256() {
        let mut registry = SoftwareDigestRegistry::new();
        
        assert!(registry.supports_algorithm(algorithms::SHA256));
        assert_eq!(registry.get_output_size(algorithms::SHA256), Some(32));
        
        let mut digest_op = registry.create_digest(algorithms::SHA256).unwrap();
        let test_data = b"hello world";
        
        digest_op.update(test_data).unwrap();
        digest_op.finalize().unwrap();
        
        let mut output = vec![0u8; 32];
        let size = digest_op.copy_output(&mut output).unwrap();
        assert_eq!(size, 32);
        
        // Verify against direct computation
        let expected = direct::sha256_hash(test_data);
        assert_eq!(output.as_slice(), &expected[..]);
    }

    #[test]
    fn test_all_algorithms_static() {
        let mut computer = DigestComputer::new();
        let test_data = b"The quick brown fox jumps over the lazy dog";
        
        // Test SHA-256
        let sha256_result = computer.compute_sha256_static(test_data).unwrap();
        assert_eq!(sha256_result.len(), 32);
        
        // Test SHA-384
        let sha384_result = computer.compute_sha384_static(test_data).unwrap();
        assert_eq!(sha384_result.len(), 48);
        
        // Test SHA-512
        let sha512_result = computer.compute_sha512_static(test_data).unwrap();
        assert_eq!(sha512_result.len(), 64);
    }

    #[test]
    fn test_all_algorithms_dynamic() {
        let mut registry = SoftwareDigestRegistry::new();
        let test_data = b"The quick brown fox jumps over the lazy dog";
        
        // Collect supported algorithms to avoid borrowing conflicts
        let supported_algs: Vec<u32> = registry.supported_algorithms().iter().copied().collect();
        
        for algorithm_id in supported_algs {
            let mut digest_op = registry.create_digest(algorithm_id).unwrap();
            let expected_size = registry.get_output_size(algorithm_id).unwrap();
            
            digest_op.update(test_data).unwrap();
            digest_op.finalize().unwrap();
            
            assert_eq!(digest_op.output_size(), expected_size);
            assert_eq!(digest_op.algorithm_id(), algorithm_id);
            
            let mut output = vec![0u8; expected_size];
            let actual_size = digest_op.copy_output(&mut output).unwrap();
            assert_eq!(actual_size, expected_size);
            
            // Verify output is not all zeros (actual hash was computed)
            assert!(output.iter().any(|&b| b != 0));
        }
    }

    #[test]
    fn test_digest_computer() {
        let mut computer = DigestComputer::new();
        let test_data = b"software digest implementation test";
        
        // Test SHA-256 (dynamic)
        let sha256_result = computer.compute_digest(algorithms::SHA256, test_data).unwrap();
        assert_eq!(sha256_result.len(), 32);
        
        // Test SHA-384 (dynamic)
        let sha384_result = computer.compute_digest(algorithms::SHA384, test_data).unwrap();
        assert_eq!(sha384_result.len(), 48);
        
        // Test SHA-512 (dynamic)
        let sha512_result = computer.compute_digest(algorithms::SHA512, test_data).unwrap();
        assert_eq!(sha512_result.len(), 64);
        
        // Verify results match direct computation
        let sha256_direct = direct::sha256_hash(test_data);
        assert_eq!(sha256_result.as_slice(), &sha256_direct[..]);
        
        // Test static API equivalence
        let sha256_static = computer.compute_sha256_static(test_data).unwrap();
        assert_eq!(sha256_static.to_vec(), sha256_direct.to_vec());
    }

    #[test]
    fn test_streaming_digest() {
        let mut computer = DigestComputer::new();
        let chunks: Vec<&[u8]> = vec![b"hello", b" ", b"world"];
        
        let streaming_result = computer
            .compute_digest_streaming(algorithms::SHA256, chunks)
            .unwrap();
        
        let direct_result = computer.compute_digest(algorithms::SHA256, b"hello world").unwrap();
        
        assert_eq!(streaming_result, direct_result);
    }

    #[test]
    fn test_error_conditions() {
        let mut registry = SoftwareDigestRegistry::new();
        
        // Test unsupported algorithm
        assert!(matches!(
            registry.create_digest(0xFF),
            Err(SoftwareDigestError::UnsupportedAlgorithm)
        ));
        
        // Test double finalize (dynamic)
        let mut digest_op = registry.create_digest(algorithms::SHA256).unwrap();
        digest_op.update(b"test").unwrap();
        digest_op.finalize().unwrap();
        
        assert!(matches!(
            digest_op.finalize(),
            Err(SoftwareDigestError::InvalidState)
        ));
        
        // Test update after finalize (dynamic)
        assert!(matches!(
            digest_op.update(b"more data"),
            Err(SoftwareDigestError::InvalidState)
        ));
        
        // Test copy_output before finalize (dynamic)
        let mut digest_op2 = registry.create_digest(algorithms::SHA256).unwrap();
        digest_op2.update(b"test").unwrap();
        
        let mut output = [0u8; 32];
        assert!(matches!(
            digest_op2.copy_output(&mut output),
            Err(SoftwareDigestError::InvalidState)
        ));
        
        // Test buffer too small (dynamic)
        digest_op2.finalize().unwrap();
        let mut small_output = [0u8; 16]; // Too small for SHA-256
        assert!(matches!(
            digest_op2.copy_output(&mut small_output),
            Err(SoftwareDigestError::BufferTooSmall)
        ));
        
        // Test static API double finalize
        let mut static_op = direct::sha256_static();
        static_op.update(b"test").unwrap();
        let _result = static_op.finalize().unwrap();
        
        // Note: static API consumes self on finalize, so double finalize isn't possible
    }

    #[test]
    fn test_algorithm_info() {
        let computer = DigestComputer::new();
        
        let info = computer.get_algorithm_info(algorithms::SHA256).unwrap();
        assert_eq!(info, (algorithms::SHA256, 32, "SHA-256"));
        
        let info = computer.get_algorithm_info(algorithms::SHA384).unwrap();
        assert_eq!(info, (algorithms::SHA384, 48, "SHA-384"));
        
        let info = computer.get_algorithm_info(algorithms::SHA512).unwrap();
        assert_eq!(info, (algorithms::SHA512, 64, "SHA-512"));
        
        assert!(computer.get_algorithm_info(0xFF).is_none());
        
        let all_algorithms = computer.list_supported_algorithms();
        assert_eq!(all_algorithms.len(), 3);
        assert!(all_algorithms.contains(&(algorithms::SHA256, 32, "SHA-256")));
        assert!(all_algorithms.contains(&(algorithms::SHA384, 48, "SHA-384")));
        assert!(all_algorithms.contains(&(algorithms::SHA512, 64, "SHA-512")));
    }

    #[test]
    fn test_direct_apis() {
        let test_data = b"direct API test";
        
        // Test dynamic direct API
        let mut sha256_dynamic = direct::sha256_dynamic();
        sha256_dynamic.update(test_data).unwrap();
        sha256_dynamic.finalize().unwrap();
        
        let mut output = [0u8; 32];
        let size = sha256_dynamic.copy_output(&mut output).unwrap();
        assert_eq!(size, 32);
        
        // Test static direct API  
        let mut sha256_static = direct::sha256_static();
        sha256_static.update(test_data).unwrap();
        let static_result = sha256_static.finalize().unwrap();
        
        // Test direct hash function
        let direct_hash = direct::sha256_hash(test_data);
        
        // All should produce the same result
        assert_eq!(output, direct_hash);
        assert_eq!(static_result, &direct_hash[..]);
    }
}

/// Example usage demonstrating the software digest implementation
fn main() -> Result<(), SoftwareDigestError> {
    println!("Software Digest Implementation Example");
    println!("=====================================");
    
    // Initialize digest computer
    let mut computer = DigestComputer::new();
    
    // List supported algorithms
    println!("\nSupported algorithms:");
    for (id, size, name) in computer.list_supported_algorithms() {
        println!("  - {} (ID: 0x{:02X}, Output: {} bytes)", name, id, size);
    }
    
    // Test data
    let test_data = b"The quick brown fox jumps over the lazy dog";
    println!("\nTest data: {:?}", core::str::from_utf8(test_data).unwrap());
    
    // Demonstrate dynamic API
    println!("\nDynamic API results:");
    for &algorithm_id in [algorithms::SHA256, algorithms::SHA384, algorithms::SHA512].iter() {
        let hash_result = computer.compute_digest(algorithm_id, test_data)?;
        let (_, _, name) = computer.get_algorithm_info(algorithm_id).unwrap();
        
        println!("  {}: {}", name, hex_encode(&hash_result));
    }
    
    // Demonstrate static API
    println!("\nStatic API results:");
    
    let sha256_static = computer.compute_sha256_static(test_data)?;
    println!("  SHA-256: {}", hex_encode(&sha256_static));
    
    let sha384_static = computer.compute_sha384_static(test_data)?;
    println!("  SHA-384: {}", hex_encode(&sha384_static));
    
    let sha512_static = computer.compute_sha512_static(test_data)?;
    println!("  SHA-512: {}", hex_encode(&sha512_static));
    
    // Demonstrate streaming computation
    println!("\nStreaming digest example (dynamic API):");
    let chunks: &[&[u8]] = &[b"The quick brown fox ", b"jumps over ", b"the lazy dog"];
    let streaming_result = computer.compute_digest_streaming(algorithms::SHA256, chunks)?;
    let direct_result = computer.compute_digest(algorithms::SHA256, test_data)?;
    
    println!("  Streaming result: {}", hex_encode(&streaming_result));
    println!("  Direct result:    {}", hex_encode(&direct_result));
    println!("  Results match: {}", streaming_result == direct_result);
    
    // Demonstrate direct API usage
    println!("\nDirect API usage:");
    let direct_sha256 = direct::sha256_hash(test_data);
    println!("  SHA-256 (direct): {}", hex_encode(&direct_sha256));
    
    // Use the trait-based API directly
    println!("\nLow-level trait usage:");
    let mut registry = SoftwareDigestRegistry::new();
    let mut digest_op = registry.create_digest(algorithms::SHA256)?;
    
    // Process data in chunks
    for chunk in test_data.chunks(10) {
        digest_op.update(chunk)?;
    }
    
    digest_op.finalize()?;
    let mut output = vec![0u8; digest_op.output_size()];
    let size = digest_op.copy_output(&mut output)?;
    output.truncate(size);
    
    println!("  SHA-256 (low-level): {}", hex_encode(&output));
    
    // Demonstrate static trait usage
    println!("\nStatic trait usage:");
    let mut provider = SoftwareDigestProvider::new();
    let mut sha256_op = provider.init(Sha256Algorithm)?;
    
    // Process the same data
    for chunk in test_data.chunks(15) {
        sha256_op.update(chunk)?;
    }
    
    let static_result = sha256_op.finalize()?;
    println!("  SHA-256 (static):    {}", hex_encode(&static_result));
    
    // Verify all approaches give the same result
    println!("\nResult verification:");
    let all_same = direct_sha256.as_slice() == streaming_result &&
                   streaming_result == output &&
                   output == static_result.as_slice();
    println!("  All digest methods produce identical results: {}", all_same);
    
    println!("\nSoftware digest implementation completed successfully!");
    println!("Both static and dynamic trait APIs are fully working!");
    
    Ok(())
}

/// Simple hex encoding for display purposes
fn hex_encode(data: &[u8]) -> String {
    data.iter()
        .map(|byte| format!("{:02x}", byte))
        .collect::<String>()
}
