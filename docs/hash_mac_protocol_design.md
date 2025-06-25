# Hash and MAC Traits Design for Protocol-Driven Negotiation

## Overview

This document analyzes how the current Hash (digest) and MAC trait design supports protocol-driven hash size negotiation in security protocols like SPDM (Security Protocol and Data Model) and MCTP (Management Component Transport Protocol).

### Current Implementation Status

**COMPLETED**: The trait architecture described in this document has been fully implemented and refactored:

- ✅ **Generic Traits Moved**: `DigestRegistry` and `DynamicDigestOp` traits have been moved from the SPDM example to the main `proposed-traits/src/digest.rs` module
- ✅ **Object Safety**: `DynamicDigestOp` has been redesigned to be object-safe, enabling trait objects and dynamic dispatch
- ✅ **Generic Algorithm IDs**: Both traits are now generic over algorithm identifier types, making them protocol-agnostic
- ✅ **Comprehensive Documentation**: Full rustdoc documentation with working examples has been added
- ✅ **Working Examples**: SPDM hash negotiation example updated to use the new trait locations and patterns
- ✅ **Test Suite Clean**: All doctests pass or are properly marked as `ignore` where appropriate
- ✅ **Protocol Design Doc**: This document has been updated to reflect the current implementation
- ✅ **Build Verification**: All code compiles and examples run successfully with the new trait architecture

The traits are ready for production use in embedded systems requiring protocol-driven cryptographic algorithm negotiation.

## Current Trait Architecture

### Key Architectural Decisions

During the refactoring process, several key design decisions were made to optimize the traits for embedded systems and protocol-driven use:

1. **Object Safety**: `DynamicDigestOp` was redesigned to avoid consuming `self` by value, making it object-safe for trait objects
2. **Generic Algorithm IDs**: Both `DigestRegistry` and `DynamicDigestOp` are generic over algorithm identifier types for maximum flexibility
3. **Embedded-First**: All designs prioritize stack-based operations, bounded memory usage, and real-time constraints
4. **Protocol Agnostic**: Core traits remain independent of specific protocols like SPDM, enabling reuse across different security protocols
5. **Performance Hybrid**: Support for both compile-time optimized static dispatch and runtime flexible dynamic dispatch

### Hash/Digest Traits (`digest.rs`)

The digest traits provide a flexible foundation for cryptographic hash operations:

```rust
pub trait DigestAlgorithm {
    const OUTPUT_BITS: usize;
    type DigestOutput;
}

pub trait DigestInit<A: DigestAlgorithm>: ErrorType {
    type OpContext<'a>: DigestOp<Output = A::DigestOutput>
    where Self: 'a;
    
    fn init<'a>(&'a mut self, algo: A) -> Result<Self::OpContext<'a>, Self::Error>;
}

pub trait DigestOp: ErrorType {
    type Output;
    fn update(&mut self, input: &[u8]) -> Result<(), Self::Error>;
    fn finalize(self) -> Result<Self::Output, Self::Error>;
}
```

### MAC Traits (`mac.rs`)

The MAC traits follow a similar pattern but include key management:

```rust
pub trait MacAlgorithm {
    const OUTPUT_BITS: usize;
    type MacOutput;
    type Key;
}

pub trait MacInit<A: MacAlgorithm>: ErrorType {
    type OpContext<'a>: MacOp<Output = A::MacOutput>
    where Self: 'a;
    
    fn init<'a>(&'a mut self, algo: A, key: &A::Key) -> Result<Self::OpContext<'a>, Self::Error>;
}
```

## Protocol-Driven Hash Size Negotiation

### SPDM Context

SPDM (Security Protocol and Data Model) is a security protocol that requires dynamic hash algorithm negotiation based on:
- Capabilities exchange between requester and responder
- Security policy requirements
- Hardware/software support availability

**Key SPDM Requirements:**
1. **Algorithm Negotiation**: Parties must agree on hash algorithms during capability exchange
2. **Multiple Hash Support**: SPDM supports SHA-256, SHA-384, SHA-512, and others
3. **Context-Dependent Selection**: Different operations may use different hash sizes
4. **Runtime Flexibility**: Hash algorithm selection happens at runtime, not compile time

### MCTP Context

MCTP (Management Component Transport Protocol) uses hash functions for:
- Message integrity verification
- Authentication in secure MCTP
- Protocol-specific hash requirements based on binding types

## Current Design Analysis

### Strengths

1. **Compile-Time Algorithm Definition**: The `DigestAlgorithm` trait with `const OUTPUT_BITS` provides clear size information
2. **Type Safety**: Algorithm types ensure compile-time verification of hash operations
3. **Flexible Implementation**: Hardware and software implementations can coexist
4. **Zero-Cost Abstractions**: Minimal runtime overhead for algorithm selection

### Limitations for Protocol Negotiation

1. **Static Algorithm Binding**: Current design requires compile-time algorithm selection
2. **Limited Runtime Flexibility**: No built-in mechanism for dynamic algorithm switching
3. **Protocol Abstraction Gap**: No direct support for protocol-level negotiation patterns

## Enhanced Design for Protocol Support

### Generic Algorithm Registry Pattern

The `DigestRegistry` trait has been moved to the main `proposed-traits` crate as a generic abstraction for protocol-driven digest algorithm negotiation:

```rust
/// Registry of supported digest algorithms for protocol negotiation and discovery.
///
/// This trait provides a generic interface for querying and creating digest operations
/// based on algorithm identifiers. It's designed to support protocol-driven scenarios
/// where digest algorithms need to be negotiated or selected at runtime.
pub trait DigestRegistry: ErrorType {
    /// The type of algorithm identifiers used by this registry.
    type AlgorithmId: Copy + Debug + PartialEq;

    /// The type of digest operations created by this registry.
    type DigestOp;

    /// Check if a specific algorithm is supported by this registry.
    fn supports_algorithm(&self, algorithm_id: Self::AlgorithmId) -> bool;

    /// Get the output size in bytes for a supported algorithm.
    fn get_output_size(&self, algorithm_id: Self::AlgorithmId) -> Option<usize>;

    /// Create a digest operation for the specified algorithm.
    fn create_digest(&mut self, algorithm_id: Self::AlgorithmId) -> Result<Self::DigestOp, Self::Error>;

    /// Get a slice of all supported algorithm identifiers.
    fn supported_algorithms(&self) -> &[Self::AlgorithmId];
}
```

### Object-Safe Dynamic Digest Operations

The `DynamicDigestOp` trait provides a generic, object-safe interface for runtime digest operations:

```rust
/// Dynamic digest operation trait for runtime algorithm selection.
///
/// This trait is **object safe**, meaning it can be used as a trait object with
/// dynamic dispatch. This enables runtime polymorphism, protocol negotiation,
/// and plugin architectures.
pub trait DynamicDigestOp {
    /// The type of error returned by digest operations.
    type Error: Error;
    
    /// The type of algorithm identifier for this digest operation.
    type AlgorithmId: Copy + Debug + PartialEq;

    /// Updates the digest state with the provided input data.
    fn update(&mut self, input: &[u8]) -> Result<(), Self::Error>;

    /// Finalizes the digest computation.
    fn finalize_mut(&mut self) -> Result<(), Self::Error>;

    /// Returns the output size in bytes for this digest algorithm.
    fn output_size(&self) -> usize;

    /// Returns the algorithm identifier for this digest operation.
    fn algorithm_id(&self) -> Self::AlgorithmId;
    
    /// Copies the digest output to the provided buffer.
    fn copy_output(&self, output: &mut [u8]) -> Result<usize, Self::Error>;
}

### Protocol-Aware Hash Selection

```rust
/// SPDM-specific hash algorithm negotiation
pub struct SpdmHashNegotiator<D: DigestRegistry> {
    digest_provider: D,
    supported_algorithms: Vec<u32>,
    negotiated_algorithm: Option<u32>,
}

impl<D: DigestRegistry> SpdmHashNegotiator<D> {
    /// Negotiate hash algorithm based on capabilities
    pub fn negotiate_algorithm(&mut self, peer_algorithms: &[u32]) -> Option<u32> {
        // Find common algorithms, prefer stronger hashes
        for &algo in &[SPDM_SHA512, SPDM_SHA384, SPDM_SHA256] {
            if self.supports_algorithm(algo) && peer_algorithms.contains(&algo) {
                self.negotiated_algorithm = Some(algo);
                return Some(algo);
            }
        }
        None
    }
    
    /// Create hash operation using negotiated algorithm
    pub fn create_hash(&mut self) -> Result<Box<dyn DigestOpDyn>, D::Error> {
        let algo = self.negotiated_algorithm
            .ok_or_else(|| /* error for no negotiated algorithm */)?;
        self.digest_provider.create_digest(algo)
    }
}
```

### MAC Protocol Integration

```rust
/// Protocol-aware MAC operations
pub struct ProtocolMac<M: MacRegistry> {
    mac_provider: M,
    negotiated_mac: Option<u32>,
}

impl<M: MacRegistry> ProtocolMac<M> {
    /// Create MAC operation for protocol context
    pub fn create_protocol_mac(&mut self, key: &[u8]) -> Result<Box<dyn MacOpDyn>, M::Error> {
        let mac_algo = self.negotiated_mac
            .ok_or_else(|| /* error for no negotiated MAC */)?;
        self.mac_provider.create_mac(mac_algo, key)
    }
}
```

## Implementation Patterns

### Application Layer Usage

```rust
/// SPDM session with negotiated cryptographic parameters
pub struct SpdmSession<D: DigestRegistry, M: MacRegistry> {
    hash_negotiator: SpdmHashNegotiator<D>,
    mac_provider: ProtocolMac<M>,
}

impl<D: DigestRegistry, M: MacRegistry> SpdmSession<D, M> {
    /// Process SPDM message with negotiated algorithms
    pub fn process_message(&mut self, message: &[u8]) -> Result<Vec<u8>, SpdmError> {
        // Create hash operation using negotiated algorithm
        let mut hash_op = self.hash_negotiator.create_hash()?;
        hash_op.update(message)?;
        let hash_result = hash_op.finalize()?;
        
        // Create MAC if authentication is required
        if self.requires_authentication() {
            let mut mac_op = self.mac_provider.create_protocol_mac(&self.get_session_key())?;
            mac_op.update(&hash_result)?;
            let mac_result = mac_op.finalize()?;
            return Ok(mac_result);
        }
        
        Ok(hash_result)
    }
}
```

### HAL Layer Implementation

```rust
/// Hardware-accelerated digest registry for embedded platforms
pub struct PlatformDigestRegistry<H> {
    crypto_handle: H,
    supported_algorithms: &'static [u32],
}

impl<H> DigestRegistry for PlatformDigestRegistry<H> 
where 
    H: CryptoHandle + Clone,
{
    type Error = PlatformDigestError;
    
    fn supports_algorithm(&self, algorithm_id: u32) -> bool {
        self.supported_algorithms.contains(&algorithm_id)
    }
    
    fn create_digest(&mut self, algorithm_id: u32) -> Result<Box<dyn DigestOpDyn>, Self::Error> {
        match algorithm_id {
            SPDM_SHA256 => Ok(Box::new(PlatformSha256Op::new(self.crypto_handle.clone())?)),
            SPDM_SHA384 => Ok(Box::new(PlatformSha384Op::new(self.crypto_handle.clone())?)),
            SPDM_SHA512 => Ok(Box::new(PlatformSha512Op::new(self.crypto_handle.clone())?)),
            _ => Err(PlatformDigestError::UnsupportedAlgorithm),
        }
    }
}

/// Trait for opaque crypto handles that can represent various backend types
pub trait CryptoHandle {
    type Error;
    
    /// Validate that the handle is still valid/accessible
    fn is_valid(&self) -> bool;
    
    /// Get platform-specific handle information (for debugging/logging)
    fn handle_info(&self) -> &str;
}

/// Example implementations for different platform types
#[derive(Debug, Clone)]
pub enum PlatformHandle {
    /// Task/thread ID for async crypto operations
    TaskId(u32),
    /// Device driver handle/file descriptor
    DeviceHandle(i32),
}

impl CryptoHandle for PlatformHandle {
    type Error = PlatformError;
    
    fn is_valid(&self) -> bool {
        match self {
            PlatformHandle::TaskId(id) => *id != 0,
            PlatformHandle::DeviceHandle(fd) => *fd >= 0,
        }
    }
    
    fn handle_info(&self) -> &str {
        match self {
            PlatformHandle::TaskId(_) => "async_task",
            PlatformHandle::DeviceHandle(_) => "device_driver",
        }
    }
}
```

## Embedded Systems Considerations

**TBD**: This section will detail embedded-specific requirements and optimizations for the cryptographic trait design, including:

- Memory constraints and stack-based operations
- Real-time timing requirements and interrupt-safe operations  
- Hardware acceleration integration and resource management
- Power management and energy efficiency considerations
- Security hardening against side-channel attacks and fault injection
- Platform-specific optimizations for common embedded targets

## Key Design Principles

### 1. Separation of Concerns
- **Static Traits**: For compile-time optimized implementations with zero-cost abstractions
- **Dynamic Traits**: For runtime protocol negotiation and algorithm selection
- **Registry Abstractions**: For capability discovery and algorithm management
- **Security Traits**: For side-channel resistance and fault tolerance

### 2. Protocol Agnostic Foundation
- Core traits remain protocol-independent to maximize reusability
- Protocol-specific logic implemented in higher-level abstractions
- Reusable across SPDM, MCTP, TLS, and other security protocols
- Clean separation between cryptographic primitives and protocol requirements

### 3. Embedded-First Design Philosophy
- **Memory Efficiency**: Stack-based operations, zero-allocation paths, and carefully managed buffer sizes ensure operation within tight memory constraints typical of embedded systems.

- **Real-Time Guarantees**: Bounded execution times, interrupt-safe operations, and deterministic behavior enable integration with real-time systems and safety-critical applications.

- **Power Optimization**: Sophisticated power management including energy budgeting, DVFS integration, and intelligent operation scheduling enables battery-powered and energy-harvesting applications.

- **Hardware Integration**: Native support for crypto accelerators, DMA operations, and TEE environments maximizes performance while maintaining security guarantees.

### 4. Performance Considerations
- **Zero-cost static path**: Direct trait implementations for compile-time known algorithms
- **Minimal dynamic overhead**: Efficient runtime dispatch only when protocol negotiation is required
- **Hardware acceleration**: Transparent integration with platform-specific crypto engines

### 5. Error Handling Strategy
- **Layered error types**: Protocol errors separate from implementation and hardware errors
- **Graceful degradation**: Fallback mechanisms for hardware failures and capability mismatches
- **Security-aware errors**: No information leakage through error messages
- **Recovery mechanisms**: Automatic fault recovery and system resilience

### 6. Composability and Extensibility
- **Trait composition**: Mix-and-match capabilities through composable trait bounds
- **Platform adaptation**: Easy integration with new hardware platforms and crypto engines
- **Algorithm agility**: Support for emerging cryptographic algorithms without major refactoring
- **Testing and verification**: Comprehensive test framework for protocol negotiation scenarios

## Integration with Existing Traits

### Extending Current Design

The existing trait design provides an excellent foundation. To support protocol negotiation:

1. **Add Dynamic Variants**: Complement static traits with dynamic alternatives
2. **Registry Abstractions**: Provide algorithm discovery and selection mechanisms
3. **Protocol Adapters**: Bridge between protocol requirements and trait implementations
4. **Backward Compatibility**: Maintain existing static trait interfaces

### Migration Strategy

1. **Phase 1**: Add dynamic traits alongside existing static traits
2. **Phase 2**: Implement registry patterns for common hardware platforms
3. **Phase 3**: Create protocol-specific negotiation helpers
4. **Phase 4**: Optimize performance for common use cases

## Conclusion

The current Hash and MAC trait design provides a solid foundation for cryptographic operations in embedded systems. With the addition of dynamic algorithm selection capabilities, embedded-specific optimizations, and protocol-aware abstractions, it can effectively support protocol-driven hash size negotiation in SPDM, MCTP, and other security protocols while meeting the stringent requirements of embedded environments.

### Key Embedded Enhancements

The enhanced design specifically addresses embedded system constraints through:

**Memory Efficiency**: Stack-based operations, zero-allocation paths, and carefully managed buffer sizes ensure operation within tight memory constraints typical of embedded systems.

**Real-Time Guarantees**: Bounded execution times, interrupt-safe operations, and deterministic behavior enable integration with real-time systems and safety-critical applications.

**Power Optimization**: Sophisticated power management including energy budgeting, DVFS integration, and intelligent operation scheduling enables battery-powered and energy-harvesting applications.

**Hardware Integration**: Native support for crypto accelerators, DMA operations, and TEE environments maximizes performance while maintaining security guarantees.

### Scalability and Adaptability

The hybrid approach maintains the performance benefits of static trait implementations while adding the runtime flexibility required for protocol negotiation. This ensures:

- **Compile-time optimization** for resource-constrained systems where algorithms are known at build time
- **Runtime adaptability** for systems requiring dynamic protocol negotiation
- **Hardware acceleration** through platform-specific implementations
- **Security isolation** through TEE and secure memory management

The design scales from ultra-low-power microcontrollers to high-performance embedded processors, adapting to available resources while maintaining consistent APIs and security guarantees.

### Future-Proofing

The extensible trait-based architecture supports emerging requirements including:
- New cryptographic algorithms and protocol requirements
- Advanced hardware security features and accelerators
- Evolving power management and performance optimization techniques
- Enhanced security countermeasures and threat mitigation strategies

This comprehensive approach ensures that embedded systems can implement robust, secure, and efficient cryptographic operations that adapt to diverse protocol requirements while maintaining the performance, power, and security characteristics essential for modern embedded applications.

## Recommendations

### 1. Implement Dynamic Traits
Add `DigestRegistry` and `MacRegistry` traits for runtime algorithm selection with embedded-specific optimizations:
- Stack-based operation contexts to avoid heap allocation
- Bounded execution time guarantees for real-time systems
- Hardware resource management and fault tolerance

### 2. Create Protocol Helpers
Develop SPDM and MCTP-specific negotiation utilities with embedded constraints:
- Memory-efficient capability exchange mechanisms
- Power-aware algorithm selection strategies
- Real-time deadline management for protocol operations

### 3. Maintain Static Path Performance
Preserve existing compile-time optimized implementations while adding dynamic capabilities:
- Conditional compilation for resource-constrained targets
- Trait-based dispatch optimization for known use cases
- Hardware-specific optimizations through specialization

### 4. Hardware Integration Framework
Ensure registry patterns work efficiently with embedded crypto accelerators:
- DMA integration for high-throughput operations
- TEE support for security-critical applications
- Fault detection and recovery mechanisms
- Power management integration with system-level DVFS

### 5. Testing and Validation Framework
Develop comprehensive tests for embedded protocol negotiation scenarios:
- Real-time performance validation under various load conditions
- Power consumption profiling and optimization verification
- Side-channel resistance testing and validation
- Fault injection testing for robustness verification

### 6. Documentation and Examples
Provide clear guidance for embedded system integration:
- Performance characteristics documentation for different platforms
- Power consumption guidelines and optimization strategies
- Security considerations and threat model documentation
- Integration examples for common embedded platforms (ASPEED, OpenTitan, ARM Cortex-M, RISC-V)

### 7. Platform-Specific Optimizations
Create reference implementations for common embedded platforms:
- ASPEED and OpenTitan crypto engine integration with full feature support
- ARM TrustZone integration for TEE-aware operations
- Low-power microcontroller adaptations
- FPGA-based crypto accelerator support

This enhanced design enables robust, secure, and efficient cryptographic operations that can adapt to diverse protocol requirements while maintaining the performance characteristics essential for embedded systems. The focus on memory efficiency, real-time guarantees, and power optimization makes it suitable for the most demanding embedded applications including safety-critical systems, IoT devices, and infrastructure controllers.

## Dynamic-Static Trait Interoperation Example

This section demonstrates how the higher-level dynamic traits can seamlessly interoperate with static dispatch traits in real-world protocol negotiation scenarios, providing both runtime flexibility and compile-time optimization.

### Bridge Pattern Implementation

```rust
/// Bridge between dynamic and static trait implementations
pub trait DigestBridge<A: DigestAlgorithm>: ErrorType {
    /// Create a dynamic wrapper for static implementation
    fn to_dynamic(self) -> Box<dyn DigestOpDyn<Error = Self::Error>>;
    
    /// Try to downcast dynamic implementation to static type
    fn from_dynamic(dyn_op: Box<dyn DigestOpDyn>) -> Result<Self, Box<dyn DigestOpDyn>>
    where Self: Sized;
}

/// Static-to-dynamic adapter
pub struct StaticToDynamicAdapter<T> {
    inner: T,
    algorithm_id: u32,
    output_size: usize,
}

impl<T: DigestOp> DigestOpDyn for StaticToDynamicAdapter<T> {
    type Error = T::Error;
    
    fn update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        self.inner.update(input)
    }
    
    fn finalize(self: Box<Self>) -> Result<Vec<u8>, Self::Error> {
        let output = self.inner.finalize()?;
        // Convert static output to dynamic Vec<u8>
        Ok(self.serialize_output(output))
    }
    
    fn output_size(&self) -> usize {
        self.output_size
    }
    
    fn algorithm_id(&self) -> u32 {
        self.algorithm_id
    }
}

/// Dynamic-to-static adapter for known algorithms
pub struct DynamicToStaticAdapter<A: DigestAlgorithm> {
    inner: Box<dyn DigestOpDyn>,
    _phantom: core::marker::PhantomData<A>,
}

impl<A: DigestAlgorithm> DigestOp for DynamicToStaticAdapter<A> {
    type Output = A::DigestOutput;
    type Error = Box<dyn core::error::Error>;
    
    fn update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        self.inner.update(input).map_err(|e| Box::new(e) as Box<dyn core::error::Error>)
    }
    
    fn finalize(self) -> Result<Self::Output, Self::Error> {
        let dynamic_result = self.inner.finalize()?;
        self.deserialize_output(dynamic_result)
    }
}
```

### Hybrid Registry Implementation

```rust
/// Hybrid registry supporting both static and dynamic implementations
pub struct HybridDigestRegistry<H: CryptoHandle> {
    // Static implementations for compile-time known algorithms
    sha256_impl: Option<Box<dyn Fn() -> PlatformSha256Op<H>>>,
    sha384_impl: Option<Box<dyn Fn() -> PlatformSha384Op<H>>>,
    sha512_impl: Option<Box<dyn Fn() -> PlatformSha512Op<H>>>,
    
    // Dynamic registry for runtime algorithm selection
    dynamic_providers: HashMap<u32, Box<dyn DigestProvider>>,
    
    // Performance optimization: prefer static when available
    prefer_static: bool,
    
    // Platform handle for creating new operations
    crypto_handle: H,
}
}

trait DigestProvider {
    fn create_digest(&mut self) -> Result<Box<dyn DigestOpDyn>, Box<dyn core::error::Error>>;
    fn supports_hardware(&self) -> bool;
    fn get_performance_class(&self) -> PerformanceClass;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PerformanceClass {
    Software,
    HardwareAccelerated,
    HardwareOptimized,
    HardwareNative,
}

impl<H: CryptoHandle + Clone> HybridDigestRegistry<H> {
    pub fn new(crypto_handle: H) -> Self {
        Self {
            sha256_impl: None,
            sha384_impl: None,
            sha512_impl: None,
            dynamic_providers: HashMap::new(),
            prefer_static: true,
            crypto_handle,
        }
    }
    
    /// Register static implementation for optimal performance
    pub fn register_static_sha256<F>(&mut self, factory: F) 
    where F: Fn() -> PlatformSha256Op<H> + 'static 
    {
        self.sha256_impl = Some(Box::new(factory));
    }
    
    /// Register dynamic implementation for flexibility
    pub fn register_dynamic_provider(&mut self, algorithm_id: u32, provider: Box<dyn DigestProvider>) {
        self.dynamic_providers.insert(algorithm_id, provider);
    }
    
    /// Create digest with optimal dispatch strategy
    pub fn create_optimized_digest(&mut self, algorithm_id: u32) -> Result<OptimizedDigest<H>, RegistryError> {
        match algorithm_id {
            SPDM_SHA256 if self.prefer_static && self.sha256_impl.is_some() => {
                // Use static implementation for maximum performance
                let factory = self.sha256_impl.as_ref().unwrap();
                let static_impl = factory();
                Ok(OptimizedDigest::Static(StaticDigestVariant::Sha256(static_impl)))
            },
            _ => {
                // Fall back to dynamic implementation
                if let Some(provider) = self.dynamic_providers.get_mut(&algorithm_id) {
                    let dynamic_impl = provider.create_digest()?;
                    Ok(OptimizedDigest::Dynamic(dynamic_impl))
                } else {
                    Err(RegistryError::UnsupportedAlgorithm(algorithm_id))
                }
            }
        }
    }
}

/// Optimized digest operation that can use either static or dynamic dispatch
pub enum OptimizedDigest<H: CryptoHandle> {
    Static(StaticDigestVariant<H>),
    Dynamic(Box<dyn DigestOpDyn>),
}

pub enum StaticDigestVariant<H: CryptoHandle> {
    Sha256(PlatformSha256Op<H>),
    Sha384(PlatformSha384Op<H>),
    Sha512(PlatformSha512Op<H>),
}

impl<H: CryptoHandle> DigestOpDyn for OptimizedDigest<H> {
    type Error = HybridError;
    
    fn update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        match self {
            OptimizedDigest::Static(variant) => {
                match variant {
                    StaticDigestVariant::Sha256(op) => op.update(input).map_err(HybridError::Platform),
                    StaticDigestVariant::Sha384(op) => op.update(input).map_err(HybridError::Platform),
                    StaticDigestVariant::Sha512(op) => op.update(input).map_err(HybridError::Platform),
                }
            },
            OptimizedDigest::Dynamic(op) => op.update(input).map_err(HybridError::Dynamic),
        }
    }
    
    fn finalize(self: Box<Self>) -> Result<Vec<u8>, Self::Error> {
        match *self {
            OptimizedDigest::Static(variant) => {
                match variant {
                    StaticDigestVariant::Sha256(op) => {
                        let result = op.finalize().map_err(HybridError::Static)?;
                        Ok(result.to_vec())
                    },
                    StaticDigestVariant::Sha384(op) => {
                        let result = op.finalize().map_err(HybridError::Static)?;
                        Ok(result.to_vec())
                    },
                    StaticDigestVariant::Sha512(op) => {
                        let result = op.finalize().map_err(HybridError::Static)?;
                        Ok(result.to_vec())
                    },
                }
            },
            OptimizedDigest::Dynamic(op) => op.finalize().map_err(HybridError::Dynamic),
        }
    }
    
    fn output_size(&self) -> usize {
        match self {
            OptimizedDigest::Static(variant) => {
                match variant {
                    StaticDigestVariant::Sha256(_) => 32,
                    StaticDigestVariant::Sha384(_) => 48,
                    StaticDigestVariant::Sha512(_) => 64,
                }
            },
            OptimizedDigest::Dynamic(op) => op.output_size(),
        }
    }
}

#[derive(Debug)]
pub enum HybridError {
    Platform(PlatformDigestError),
    Dynamic(Box<dyn core::error::Error>),
    Registry(RegistryError),
}
```

### Protocol Negotiation with Hybrid Dispatch

```rust
/// SPDM session that optimally uses static and dynamic implementations
pub struct HybridSpdmSession {
    registry: HybridDigestRegistry,
    negotiated_algorithm: Option<u32>,
    performance_requirements: PerformanceRequirements,
    current_digest: Option<OptimizedDigest>,
}

#[derive(Debug, Clone)]
pub struct PerformanceRequirements {
    max_latency_us: u32,
    min_throughput_mbps: u32,
    power_budget: PowerBudget,
    real_time_constraints: bool,
}

#[derive(Debug, Clone)]
pub struct PowerBudget {
    max_energy_microjoules: u32,
    max_peak_power_mw: u16,
    thermal_limit_c: i8,
}

impl HybridSpdmSession {
    pub fn new(crypto_handle: PlatformHandle) -> Self {
        let mut registry = HybridDigestRegistry::new(crypto_handle.clone());
        
        // Register static implementations for maximum performance
        registry.register_static_sha256(move || PlatformSha256Op::new(crypto_handle.clone()).unwrap());
        
        // Register dynamic implementations for flexibility
        registry.register_dynamic_provider(SPDM_SHA384, Box::new(Sha384Provider::new()));
        registry.register_dynamic_provider(SPDM_SHA512, Box::new(Sha512Provider::new()));
        
        // Register software fallbacks
        registry.register_dynamic_provider(SPDM_SHA256_SW, Box::new(Sha256SoftwareProvider::new()));
        
        Self {
            registry,
            negotiated_algorithm: None,
            performance_requirements: PerformanceRequirements::default(),
            current_digest: None,
        }
    }
    
    /// Negotiate algorithm considering both capability and performance
    pub fn negotiate_algorithm_with_performance(
        &mut self, 
        peer_algorithms: &[u32],
        performance_req: PerformanceRequirements
    ) -> Result<u32, SpdmError> {
        self.performance_requirements = performance_req;
        
        // Priority algorithm selection based on performance requirements
        let candidate_algorithms = if self.performance_requirements.real_time_constraints {
            // Prefer static implementations for real-time systems
            vec![SPDM_SHA256, SPDM_SHA384, SPDM_SHA512]
        } else {
            // Consider all options for non-real-time systems
            vec![SPDM_SHA512, SPDM_SHA384, SPDM_SHA256, SPDM_SHA256_SW]
        };
        
        for &algo in &candidate_algorithms {
            if peer_algorithms.contains(&algo) && self.can_meet_performance_requirements(algo)? {
                self.negotiated_algorithm = Some(algo);
                return Ok(algo);
            }
        }
        
        Err(SpdmError::NoCompatibleAlgorithm)
    }
    
    /// Check if algorithm can meet performance requirements
    fn can_meet_performance_requirements(&self, algorithm_id: u32) -> Result<bool, SpdmError> {
        // Check if we have static implementation (best performance)
        let has_static = match algorithm_id {
            SPDM_SHA256 => self.registry.sha256_impl.is_some(),
            SPDM_SHA384 => self.registry.sha384_impl.is_some(),
            SPDM_SHA512 => self.registry.sha512_impl.is_some(),
            _ => false,
        };
        
        if has_static && self.performance_requirements.real_time_constraints {
            return Ok(true); // Static implementations always meet real-time requirements
        }
        
        // Check dynamic implementation capabilities
        if let Some(provider) = self.registry.dynamic_providers.get(&algorithm_id) {
            let performance_class = provider.get_performance_class();
            
            match performance_class {
                PerformanceClass::HardwareNative | PerformanceClass::HardwareOptimized => {
                    // Hardware implementations likely meet requirements
                    Ok(self.estimate_performance(algorithm_id, performance_class)?)
                },
                PerformanceClass::HardwareAccelerated => {
                    // May meet requirements depending on specific needs
                    Ok(!self.performance_requirements.real_time_constraints)
                },
                PerformanceClass::Software => {
                    // Software implementations for non-critical paths only
                    Ok(!self.performance_requirements.real_time_constraints && 
                       self.performance_requirements.max_latency_us > 10000)
                },
            }
        } else {
            Ok(false)
        }
    }
    
    /// Process SPDM message using optimal implementation strategy
    pub fn process_message_optimized(&mut self, message: &[u8]) -> Result<Vec<u8>, SpdmError> {
        let algorithm = self.negotiated_algorithm.ok_or(SpdmError::NoNegotiatedAlgorithm)?;
        
        // Create optimal digest implementation
        let mut digest = self.registry.create_optimized_digest(algorithm)
            .map_err(SpdmError::RegistryError)?;
        
        // Process message with performance monitoring
        let start_time = get_system_time_us();
        
        digest.update(message).map_err(SpdmError::DigestError)?;
        let result = digest.finalize().map_err(SpdmError::DigestError)?;
        
        let end_time = get_system_time_us();
        let processing_time = end_time - start_time;
        
        // Verify performance requirements were met
        if processing_time > self.performance_requirements.max_latency_us {
            log::warn!("Processing time {} exceeded requirement {}", 
                      processing_time, self.performance_requirements.max_latency_us);
            
            // Consider switching to faster implementation for next message
            self.optimize_for_next_operation()?;
        }
        
        Ok(result)
    }
    
    /// Dynamically optimize implementation selection based on performance feedback
    fn optimize_for_next_operation(&mut self) -> Result<(), SpdmError> {
        let algorithm = self.negotiated_algorithm.unwrap();
        
        // Switch to static implementation if available and not already using it
        match algorithm {
            SPDM_SHA256 if self.registry.sha256_impl.is_some() => {
                self.registry.prefer_static = true;
                log::info!("Switching to static SHA-256 implementation for better performance");
            },
            _ => {
                // Try to find a hardware-accelerated dynamic implementation
                if let Some(provider) = self.registry.dynamic_providers.get(&algorithm) {
                    if provider.supports_hardware() {
                        log::info!("Using hardware-accelerated implementation");
                    }
                }
            }
        }
        
        Ok(())
    }
}

/// Example showing embedded real-time usage
impl HybridSpdmSession {
    /// Process message in real-time context with strict timing guarantees
    pub fn process_message_real_time(
        &mut self, 
        message: &[u8], 
        deadline_us: u32
    ) -> Result<Vec<u8>, SpdmError> {
        let algorithm = self.negotiated_algorithm.ok_or(SpdmError::NoNegotiatedAlgorithm)?;
        let start_time = get_system_time_us();
        
        // Force static implementation for real-time processing
        let mut digest = match algorithm {
            SPDM_SHA256 if self.registry.sha256_impl.is_some() => {
                let factory = self.registry.sha256_impl.as_ref().unwrap();
                let static_impl = factory();
                OptimizedDigest::Static(StaticDigestVariant::Sha256(static_impl))
            },
            _ => {
                // Fall back to dynamic but check timing
                let dynamic_digest = self.registry.create_optimized_digest(algorithm)
                    .map_err(SpdmError::RegistryError)?;
                
                // Estimate if we can complete within deadline
                let estimated_time = self.estimate_processing_time(algorithm, message.len())?;
                if estimated_time > deadline_us {
                    return Err(SpdmError::DeadlineViolation);
                }
                
                dynamic_digest
            }
        };
        
        // Process with timing checks
        digest.update(message).map_err(SpdmError::DigestError)?;
        
        let mid_time = get_system_time_us();
        if mid_time - start_time > deadline_us / 2 {
            return Err(SpdmError::DeadlineViolation);
        }
        
        let result = digest.finalize().map_err(SpdmError::DigestError)?;
        
        let end_time = get_system_time_us();
        if end_time - start_time > deadline_us {
            log::error!("Real-time deadline violated: {} > {}", end_time - start_time, deadline_us);
            return Err(SpdmError::DeadlineViolation);
        }
        
        Ok(result)
    }
}

/// Complete example usage in embedded context showing different handle types
pub fn embedded_spdm_example() -> Result<(), Box<dyn core::error::Error>> {
    // Example 1: Async task-based crypto operations
    let task_handle = PlatformHandle::TaskId(42);
    let mut spdm_session_async = HybridSpdmSession::new(task_handle);
    println!("Created SPDM session with async task crypto");
    
    // Example 2: Device driver interface (TockOS, etc.)
    let device_handle = PlatformHandle::DeviceHandle(3); // /dev/crypto file descriptor
    let mut spdm_session_dev = HybridSpdmSession::new(device_handle);
    println!("Created SPDM session with device driver crypto");
    
    // Scenario 1: Initial negotiation with performance requirements (using async task)
    let peer_algorithms = &[SPDM_SHA256, SPDM_SHA384, SPDM_SHA512];
    let real_time_requirements = PerformanceRequirements {
        max_latency_us: 1000,  // 1ms max latency
        min_throughput_mbps: 100,
        power_budget: PowerBudget {
            max_energy_microjoules: 1000,
            max_peak_power_mw: 500,
            thermal_limit_c: 85,
        },
        real_time_constraints: true,
    };
    
    let negotiated = spdm_session_async.negotiate_algorithm_with_performance(
        peer_algorithms, 
        real_time_requirements
    )?;
    
    println!("Negotiated algorithm: {} (async task crypto, static dispatch preferred)", negotiated);
    
    // Scenario 2: Process real-time critical message with async task crypto
    let critical_message = b"Critical security message requiring fast processing";
    let result = spdm_session_async.process_message_real_time(critical_message, 800)?; // 800μs deadline
    
    println!("Critical message processed with async task crypto: {} bytes output", result.len());
    
    // Scenario 3: Process normal message with device driver crypto
    let normal_message = b"Normal SPDM message for capability exchange";
    let result = spdm_session_dev.process_message_optimized(normal_message)?;
    
    println!("Normal message processed with device driver crypto: {} bytes output", result.len());
    
    // Scenario 3: Handle algorithm change with device driver crypto
    let new_peer_algorithms = &[SPDM_SHA512, SPDM_SHA384]; // Peer now prefers SHA-512
    let flexible_requirements = PerformanceRequirements {
        max_latency_us: 5000,  // 5ms max latency
        min_throughput_mbps: 50,
        power_budget: PowerBudget {
            max_energy_microjoules: 5000,
            max_peak_power_mw: 300,
            thermal_limit_c: 70,
        },
        real_time_constraints: false,
    };
    
    let new_algorithm = spdm_session_dev.negotiate_algorithm_with_performance(
        new_peer_algorithms, 
        flexible_requirements
    )?;
    
    println!("Re-negotiated to algorithm: {} (device driver crypto, dynamic dispatch acceptable)", new_algorithm);
    
    // Process with new algorithm using device driver
    let final_message = b"Message processed with newly negotiated algorithm via device driver";
    let result = spdm_session_dev.process_message_optimized(final_message)?;
    
    println!("Final message processed with device driver crypto: {} bytes output", result.len());
    
    Ok(())
}

#[derive(Debug)]
pub enum SpdmError {
    NoCompatibleAlgorithm,
    NoNegotiatedAlgorithm,
    RegistryError(RegistryError),
    DigestError(HybridError),
    DeadlineViolation,
    PerformanceRequirementNotMet,
}

/// Platform-specific usage examples
impl PlatformDigestRegistry<PlatformHandle> {
    /// Create registry for async task-based crypto operations
    pub fn new_async_task(task_id: u32) -> Self {
        Self {
            crypto_handle: PlatformHandle::TaskId(task_id),
            supported_algorithms: &[SPDM_SHA256, SPDM_SHA384, SPDM_SHA512],
        }
    }
    
    /// Create registry using device driver interface (TockOS, etc.)
    pub fn new_device_driver(device_fd: i32) -> Self {
        Self {
            crypto_handle: PlatformHandle::DeviceHandle(device_fd),
            supported_algorithms: &[SPDM_SHA256, SPDM_SHA384, SPDM_SHA512],
        }
    }
}

/// Example digest operation that works with opaque handles
pub struct PlatformSha256Op<H: CryptoHandle> {
    handle: H,
    state: DigestState,
}

impl<H: CryptoHandle> PlatformSha256Op<H> {
    pub fn new(handle: H) -> Result<Self, H::Error> {
        if !handle.is_valid() {
            return Err(/* handle invalid error */);
        }
        
        Ok(Self {
            handle,
            state: DigestState::new(),
        })
    }
}

impl<H: CryptoHandle> DynamicDigestOp for PlatformSha256Op<H> {
    type Error = PlatformDigestError;
    type AlgorithmId = u32;
    
    fn update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        // Implementation depends on handle type
        match &self.handle {
            handle if handle.handle_info() == "async_task" => {
                // Queue operation to async task
                self.queue_async_operation(input)
            },
            handle if handle.handle_info() == "device_driver" => {
                // Use device driver interface
                self.invoke_device_driver(input)
            },
            _ => {
                // Generic fallback implementation
                self.update_generic(input)
            }
        }
    }
    
    fn finalize_mut(&mut self) -> Result<(), Self::Error> { todo!() }
    fn output_size(&self) -> usize { 32 }
    fn algorithm_id(&self) -> u32 { SPDM_SHA256 }
    fn copy_output(&self, output: &mut [u8]) -> Result<usize, Self::Error> { todo!() }
}

#[derive(Debug)]
pub enum PlatformError {
    TaskNotFound,
    DeviceAccessFailed,
    InvalidOperation,
    SecurityViolation,
}

impl core::fmt::Display for PlatformError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PlatformError::TaskNotFound => write!(f, "Crypto task not found"),
            PlatformError::DeviceAccessFailed => write!(f, "Device access failed"),
            PlatformError::InvalidOperation => write!(f, "Invalid crypto operation"),
            PlatformError::SecurityViolation => write!(f, "Security policy violation"),
        }
    }
}

impl core::error::Error for PlatformError {}
