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

/// Generic wrapper for software digest implementations
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

    /// Create a SHA-256 digest operation
    pub fn sha256() -> SoftwareDigestOp<Sha256> {
        SoftwareDigestOp::new(Sha256::new(), algorithms::SHA256)
    }

    /// Create a SHA-384 digest operation
    pub fn sha384() -> SoftwareDigestOp<Sha384> {
        SoftwareDigestOp::new(Sha384::new(), algorithms::SHA384)
    }

    /// Create a SHA-512 digest operation
    pub fn sha512() -> SoftwareDigestOp<Sha512> {
        SoftwareDigestOp::new(Sha512::new(), algorithms::SHA512)
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
}

impl DigestComputer {
    pub fn new() -> Self {
        Self {
            registry: SoftwareDigestRegistry::new(),
        }
    }

    /// Compute digest for the given data and algorithm
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

    /// Compute digest with multiple updates (streaming)
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

// Implement DigestAlgorithm for each algorithm
impl DigestAlgorithm for Sha256Algorithm {
    const OUTPUT_BITS: usize = 256;
    type DigestOutput = Vec<u8>;
}

impl DigestAlgorithm for Sha384Algorithm {
    const OUTPUT_BITS: usize = 384;
    type DigestOutput = Vec<u8>;
}

impl DigestAlgorithm for Sha512Algorithm {
    const OUTPUT_BITS: usize = 512;
    type DigestOutput = Vec<u8>;
}

/// Static digest operation context
pub struct StaticDigestOp<D>
where
    D: Digest,
{
    hasher: D,
    finalized: bool,
}

impl<D> StaticDigestOp<D>
where
    D: Digest,
{
    fn new(hasher: D) -> Self {
        Self {
            hasher,
            finalized: false,
        }
    }
}

impl<D> ErrorType for StaticDigestOp<D>
where
    D: Digest,
{
    type Error = SoftwareDigestError;
}

impl<D> DigestOp for StaticDigestOp<D>
where
    D: Digest,
{
    type Output = Vec<u8>;

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
        Ok(result.to_vec())
    }
}

impl<D> DigestCtrlReset for StaticDigestOp<D>
where
    D: Digest + Default,
{
    fn reset(&mut self) -> Result<(), Self::Error> {
        self.hasher = D::default();
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
    type OpContext<'a> = StaticDigestOp<Sha256> where Self: 'a;

    fn init<'a>(&'a mut self, _algo: Sha256Algorithm) -> Result<Self::OpContext<'a>, Self::Error> {
        Ok(StaticDigestOp::new(Sha256::new()))
    }
}

impl DigestInit<Sha384Algorithm> for SoftwareDigestProvider {
    type OpContext<'a> = StaticDigestOp<Sha384> where Self: 'a;

    fn init<'a>(&'a mut self, _algo: Sha384Algorithm) -> Result<Self::OpContext<'a>, Self::Error> {
        Ok(StaticDigestOp::new(Sha384::new()))
    }
}

impl DigestInit<Sha512Algorithm> for SoftwareDigestProvider {
    type OpContext<'a> = StaticDigestOp<Sha512> where Self: 'a;

    fn init<'a>(&'a mut self, _algo: Sha512Algorithm) -> Result<Self::OpContext<'a>, Self::Error> {
        Ok(StaticDigestOp::new(Sha512::new()))
    }
}

/// Helper function to encode binary data as hex string
fn hex_encode(data: &[u8]) -> String {
    data.iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_direct() {
        let test_data = b"hello world";
        let expected = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
        
        let result = direct::sha256_hash(test_data);
        assert_eq!(hex_encode(&result), expected);
    }

    #[test]
    fn test_dynamic_api() {
        let mut registry = SoftwareDigestRegistry::new();
        let test_data = b"The quick brown fox jumps over the lazy dog";
        
        // Test SHA-256
        let mut digest_op = registry.create_digest(algorithms::SHA256).unwrap();
        assert_eq!(digest_op.output_size(), 32);
        assert_eq!(digest_op.algorithm_id(), algorithms::SHA256);
        
        digest_op.update(test_data).unwrap();
        digest_op.finalize().unwrap();
        
        let mut output = vec![0u8; 32];
        let size = digest_op.copy_output(&mut output).unwrap();
        assert_eq!(size, 32);
        
        // Expected SHA-256 of the test data
        let expected = "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592";
        assert_eq!(hex_encode(&output), expected);
    }

    #[test]
    fn test_static_api() {
        let mut provider = SoftwareDigestProvider::new();
        let test_data = b"The quick brown fox jumps over the lazy dog";
        
        // Test SHA-256 static API
        let mut digest_op = provider.init(Sha256Algorithm).unwrap();
        digest_op.update(test_data).unwrap();
        let output = digest_op.finalize().unwrap();
        
        // Expected SHA-256 of the test data
        let expected = "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592";
        assert_eq!(hex_encode(&output), expected);
    }

    #[test]
    fn test_all_algorithms() {
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
            
            // Verify we got actual digest data (not all zeros)
            assert!(output.iter().any(|&b| b != 0));
        }
    }

    #[test]
    fn test_streaming() {
        let mut computer = DigestComputer::new();
        let test_data = b"The quick brown fox jumps over the lazy dog";
        
        // Compute hash all at once
        let result1 = computer.compute_digest(algorithms::SHA256, test_data).unwrap();
        
        // Compute hash in chunks
        let chunks: Vec<&[u8]> = test_data.chunks(10).collect();
        let result2 = computer.compute_digest_streaming(algorithms::SHA256, chunks).unwrap();
        
        assert_eq!(result1, result2);
    }

    #[test]
    fn test_error_conditions() {
        let mut registry = SoftwareDigestRegistry::new();
        
        // Test unsupported algorithm
        assert!(registry.create_digest(0xFF).is_err());
        
        // Test finalized state errors
        let mut digest_op = registry.create_digest(algorithms::SHA256).unwrap();
        digest_op.update(b"test").unwrap();
        digest_op.finalize().unwrap();
        
        // Should not be able to update after finalize
        assert!(digest_op.update(b"more data").is_err());
        
        // Should not be able to finalize again
        assert!(digest_op.finalize().is_err());
        
        // Test buffer too small
        let mut small_output = vec![0u8; 10]; // Too small for SHA-256
        assert!(digest_op.copy_output(&mut small_output).is_err());
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
    
    // Compute hashes for all supported algorithms
    println!("\nDigest computation:");
    for &algorithm_id in &[algorithms::SHA256, algorithms::SHA384, algorithms::SHA512] {
        let result = computer.compute_digest(algorithm_id, test_data)?;
        let (_, _, name) = computer.get_algorithm_info(algorithm_id).unwrap();
        println!("  {}: {}", name, hex_encode(&result));
    }
    
    // Demonstrate direct functions
    println!("\nDirect function usage:");
    let direct_sha256 = direct::sha256_hash(test_data);
    println!("  SHA-256 (direct): {}", hex_encode(&direct_sha256));
    
    // Use the trait-based API
    println!("\nTrait-based API usage:");
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
    println!("  SHA-256 (trait): {}", hex_encode(&output));
    
    // Demonstrate static API
    println!("\nStatic API usage:");
    let mut provider = SoftwareDigestProvider::new();
    let mut sha256_op = provider.init(Sha256Algorithm)?;
    sha256_op.update(test_data)?;
    let static_result = sha256_op.finalize()?;
    println!("  SHA-256 (static): {}", hex_encode(&static_result));
    
    Ok(())
}
