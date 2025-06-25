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
```
```

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
/// Hardware-accelerated digest registry for ASPEED chips
pub struct AspeedDigestRegistry {
    hw_base: *mut u8,
    supported_algorithms: &'static [u32],
}

impl DigestRegistry for AspeedDigestRegistry {
    type Error = AspeedDigestError;
    
    fn supports_algorithm(&self, algorithm_id: u32) -> bool {
        self.supported_algorithms.contains(&algorithm_id)
    }
    
    fn create_digest(&mut self, algorithm_id: u32) -> Result<Box<dyn DigestOpDyn>, Self::Error> {
        match algorithm_id {
            SPDM_SHA256 => Ok(Box::new(AspeedSha256Op::new(self.hw_base)?)),
            SPDM_SHA384 => Ok(Box::new(AspeedSha384Op::new(self.hw_base)?)),
            SPDM_SHA512 => Ok(Box::new(AspeedSha512Op::new(self.hw_base)?)),
            _ => Err(AspeedDigestError::UnsupportedAlgorithm),
        }
    }
}
```

## Embedded Systems Considerations

### Memory Constraints

In embedded contexts, memory usage is critical. Traditional heap allocation patterns are often unacceptable due to limited RAM and heap fragmentation concerns.

#### Stack-Based Operations

```rust
/// Stack-allocated digest operations for memory-constrained environments
pub trait DigestOpStack: ErrorType {
    type Output;
    const MAX_BLOCK_SIZE: usize = 64; // SHA-256/384/512 block size
    const STATE_SIZE: usize; // Algorithm-specific state size
    
    fn update_stack(&mut self, input: &[u8]) -> Result<(), Self::Error>;
    fn finalize_stack(self) -> Result<Self::Output, Self::Error>;
    
    /// Get memory footprint for this operation
    fn memory_footprint() -> MemoryFootprint;
}

/// No-alloc registry for embedded systems
pub trait DigestRegistryNoAlloc: ErrorType {
    type DigestContext: DigestOpStack;
    
    /// Create digest context on the stack
    fn create_digest_stack(&mut self, algorithm_id: u32) -> Result<Self::DigestContext, Self::Error>;
    
    /// Get algorithm info without allocation
    fn get_algorithm_info(&self, algorithm_id: u32) -> Option<AlgorithmInfo>;
    
    /// Pre-check memory requirements before operation
    fn check_memory_requirements(&self, algorithm_id: u32, available_stack: usize) -> bool;
}

#[derive(Clone, Copy, Debug)]
pub struct AlgorithmInfo {
    pub output_size: usize,
    pub block_size: usize,
    pub state_size: usize,
    pub min_stack_bytes: usize,
    pub alignment_requirement: usize,
}

#[derive(Clone, Copy, Debug)]
pub struct MemoryFootprint {
    pub stack_bytes: usize,
    pub static_bytes: usize,
    pub alignment: usize,
    pub volatile_registers: usize, // For hardware implementations
}
```

#### Buffer Management Patterns

```rust
/// Fixed-size buffer management for embedded digest operations
pub struct DigestBuffer<const SIZE: usize> {
    buffer: [u8; SIZE],
    position: usize,
}

impl<const SIZE: usize> DigestBuffer<SIZE> {
    const fn new() -> Self {
        Self {
            buffer: [0; SIZE],
            position: 0,
        }
    }
    
    /// Add data to buffer, processing full blocks
    fn update<D: DigestOpStack>(&mut self, digest: &mut D, data: &[u8]) -> Result<(), D::Error> {
        let mut remaining = data;
        
        while !remaining.is_empty() {
            let space = SIZE - self.position;
            let to_copy = remaining.len().min(space);
            
            self.buffer[self.position..self.position + to_copy]
                .copy_from_slice(&remaining[..to_copy]);
            self.position += to_copy;
            remaining = &remaining[to_copy..];
            
            if self.position == SIZE {
                digest.update_stack(&self.buffer)?;
                self.position = 0;
            }
        }
        Ok(())
    }
    
    /// Finalize with remaining buffer content
    fn finalize<D: DigestOpStack>(mut self, mut digest: D) -> Result<D::Output, D::Error> {
        if self.position > 0 {
            digest.update_stack(&self.buffer[..self.position])?;
        }
        digest.finalize_stack()
    }
}

/// Embedded-specific SPDM session with static buffers
pub struct EmbeddedSpdmSession<const BUFFER_SIZE: usize> {
    digest_buffer: DigestBuffer<BUFFER_SIZE>,
    mac_buffer: DigestBuffer<BUFFER_SIZE>,
    negotiated_hash: Option<u32>,
    negotiated_mac: Option<u32>,
}
```

### Real-Time Constraints

Protocol negotiation and cryptographic operations in embedded systems must respect strict timing requirements. This is especially critical in safety-critical systems and high-frequency control loops.

#### Time-Bounded Operations

```rust
/// Time-bounded hash operations for real-time systems
pub trait DigestOpRealTime: DigestOpStack {
    /// Maximum processing time per update call (in microseconds)
    const MAX_UPDATE_TIME_US: u32;
    
    /// Maximum total operation time (in microseconds)
    const MAX_TOTAL_TIME_US: u32;
    
    /// Non-blocking update for interrupt contexts
    fn update_nonblocking(&mut self, input: &[u8]) -> Result<ProcessResult, Self::Error>;
    
    /// Check if operation can complete within deadline
    fn can_complete_by(&self, deadline_us: u32) -> bool;
    
    /// Get current operation progress
    fn get_progress(&self) -> OperationProgress;
    
    /// Suspend operation for higher priority tasks
    fn suspend(&mut self) -> Result<SuspendToken, Self::Error>;
    
    /// Resume suspended operation
    fn resume(&mut self, token: SuspendToken) -> Result<(), Self::Error>;
}

#[derive(Debug, Clone, Copy)]
pub enum ProcessResult {
    /// Operation completed successfully
    Completed(usize), // bytes processed
    /// Operation needs more time, call again
    Partial(usize),   // bytes processed so far
    /// Operation would exceed deadline
    WouldBlock,
}

#[derive(Debug, Clone, Copy)]
pub struct OperationProgress {
    pub bytes_processed: usize,
    pub estimated_remaining_us: u32,
    pub can_yield: bool,
}

/// Token for resuming suspended operations
pub struct SuspendToken {
    context: [u32; 8], // Platform-specific context
    timestamp: u64,
}
```

#### Interrupt-Safe Operations

```rust
/// Interrupt-safe digest operations
pub trait DigestOpInterruptSafe: DigestOpRealTime {
    /// Update from interrupt context (minimal processing)
    fn update_from_interrupt(&mut self, input: &[u8]) -> Result<(), Self::Error>;
    
    /// Check if safe to call from current interrupt level
    fn interrupt_safe(&self, irq_level: u8) -> bool;
    
    /// Atomic finalize operation
    fn finalize_atomic(self) -> Result<Self::Output, Self::Error>;
}

/// Real-time SPDM message processor
pub struct RealTimeSpdmProcessor<D: DigestOpRealTime> {
    digest_op: Option<D>,
    message_buffer: [u8; 1024],
    buffer_pos: usize,
    deadline_us: u32,
}

impl<D: DigestOpRealTime> RealTimeSpdmProcessor<D> {
    /// Process message chunk within time budget
    pub fn process_chunk(&mut self, chunk: &[u8], time_budget_us: u32) -> Result<ProcessResult, D::Error> {
        let start_time = get_system_time_us();
        
        if let Some(ref mut digest) = self.digest_op {
            let remaining_time = time_budget_us.saturating_sub(get_system_time_us() - start_time);
            
            if !digest.can_complete_by(remaining_time) {
                return Ok(ProcessResult::WouldBlock);
            }
            
            match digest.update_nonblocking(chunk)? {
                ProcessResult::Completed(bytes) => {
                    self.buffer_pos += bytes;
                    Ok(ProcessResult::Completed(bytes))
                },
                ProcessResult::Partial(bytes) => {
                    self.buffer_pos += bytes;
                    Ok(ProcessResult::Partial(bytes))
                },
                ProcessResult::WouldBlock => Ok(ProcessResult::WouldBlock),
            }
        } else {
            Err(/* no active digest operation */)
        }
    }
}
```

#### Deterministic Timing

```rust
/// Constant-time digest operations for security-critical applications
pub trait DigestOpConstantTime: DigestOpStack {
    /// Process exactly one block in constant time
    fn process_block_constant_time(&mut self, block: &[u8; Self::BLOCK_SIZE]) -> Result<(), Self::Error>;
    
    /// Constant-time conditional operation
    fn conditional_update(&mut self, condition: bool, input: &[u8]) -> Result<(), Self::Error>;
    
    /// Timing-safe comparison
    fn constant_time_eq(a: &[u8], b: &[u8]) -> bool;
}

/// Timing analysis utilities for embedded systems
pub struct TimingAnalyzer {
    measurements: [u32; 1000],
    count: usize,
}

impl TimingAnalyzer {
    pub fn measure_operation<F, R>(&mut self, operation: F) -> R 
    where F: FnOnce() -> R 
    {
        let start = get_cycle_count();
        let result = operation();
        let end = get_cycle_count();
        
        if self.count < self.measurements.len() {
            self.measurements[self.count] = end - start;
            self.count += 1;
        }
        
        result
    }
    
    pub fn get_statistics(&self) -> TimingStatistics {
        if self.count == 0 {
            return TimingStatistics::default();
        }
        
        let mut sorted = [0u32; 1000];
        sorted[..self.count].copy_from_slice(&self.measurements[..self.count]);
        sorted[..self.count].sort_unstable();
        
        TimingStatistics {
            min: sorted[0],
            max: sorted[self.count - 1],
            median: sorted[self.count / 2],
            p95: sorted[(self.count * 95) / 100],
            p99: sorted[(self.count * 99) / 100],
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct TimingStatistics {
    pub min: u32,
    pub max: u32,
    pub median: u32,
    pub p95: u32,
    pub p99: u32,
}
```

### Hardware Acceleration Integration

Embedded systems often have dedicated cryptographic hardware that must be carefully managed to ensure optimal performance and resource utilization.

#### Hardware Resource Management

```rust
/// Hardware-specific digest operations with resource management
pub trait HardwareDigest: ErrorType {
    /// Check if hardware is available and ready
    fn hw_available(&self) -> bool;
    
    /// Check hardware capabilities
    fn hw_capabilities(&self) -> HardwareCapabilities;
    
    /// Reserve hardware for exclusive use
    fn reserve_hw(&mut self, timeout_us: u32) -> Result<HardwareReservation, Self::Error>;
    
    /// Fallback to software implementation
    fn fallback_to_software(&mut self) -> Result<(), Self::Error>;
    
    /// Hardware context preservation for task switching
    fn save_hw_context(&mut self) -> Result<HwContext, Self::Error>;
    fn restore_hw_context(&mut self, context: HwContext) -> Result<(), Self::Error>;
    
    /// Check for hardware errors/faults
    fn check_hw_status(&self) -> HardwareStatus;
    
    /// Reset hardware to known state
    fn reset_hw(&mut self) -> Result<(), Self::Error>;
}

#[derive(Debug, Clone, Copy)]
pub struct HardwareCapabilities {
    pub supported_algorithms: &'static [u32],
    pub max_message_size: usize,
    pub dma_capable: bool,
    pub concurrent_operations: u8,
    pub power_states: &'static [PowerState],
}

#[repr(C)]
pub struct HwContext {
    registers: [u32; 16], // Platform-specific register state
    dma_state: Option<DmaState>,
    algorithm_state: AlgorithmState,
    interrupt_mask: u32,
}

#[derive(Debug)]
pub struct HardwareReservation {
    token: u64,
    reserved_until: u64,
    exclusive: bool,
}

#[derive(Debug, Clone, Copy)]
pub enum HardwareStatus {
    Ready,
    Busy,
    Error(HwErrorCode),
    Maintenance,
    PowerDown,
}

#[derive(Debug, Clone, Copy)]
pub enum HwErrorCode {
    BusError,
    ConfigError,
    TimeoutError,
    IntegrityError,
    OverheatError,
}
```

#### DMA Integration

```rust
/// DMA-capable digest operations for high throughput
pub trait DigestOpDma: HardwareDigest {
    /// Start DMA transfer for large data blocks
    fn start_dma_transfer(&mut self, source: &[u8], completion: DmaCompletion) -> Result<DmaTransfer, Self::Error>;
    
    /// Check DMA transfer status
    fn check_dma_status(&self, transfer: &DmaTransfer) -> DmaStatus;
    
    /// Wait for DMA completion with timeout
    fn wait_dma_completion(&self, transfer: DmaTransfer, timeout_us: u32) -> Result<DmaResult, Self::Error>;
    
    /// Cancel ongoing DMA transfer
    fn cancel_dma(&mut self, transfer: DmaTransfer) -> Result<(), Self::Error>;
}

pub struct DmaTransfer {
    channel: u8,
    transaction_id: u32,
    start_time: u64,
}

#[derive(Debug)]
pub enum DmaStatus {
    InProgress { bytes_transferred: usize },
    Completed { total_bytes: usize },
    Error(DmaError),
}

#[derive(Debug)]
pub enum DmaError {
    BusError,
    AddressError,
    PermissionError,
    Timeout,
}

pub enum DmaCompletion {
    Blocking,
    Interrupt(fn(DmaResult)),
    Callback(Box<dyn FnOnce(DmaResult)>),
}

/// ASPEED crypto engine with DMA support
pub struct AspeedCryptoEngine {
    base_addr: *mut u8,
    dma_controller: *mut u8,
    reserved: Option<HardwareReservation>,
    active_transfers: heapless::Vec<DmaTransfer, 4>,
}

impl AspeedCryptoEngine {
    /// Process large SPDM message using DMA
    pub fn process_spdm_message_dma(&mut self, message: &[u8]) -> Result<[u8; 32], AspeedError> {
        // Reserve hardware
        let _reservation = self.reserve_hw(1000)?; // 1ms timeout
        
        // Configure for SHA-256
        self.configure_sha256()?;
        
        // Start DMA transfer for large message
        if message.len() > 1024 {
            let transfer = self.start_dma_transfer(message, DmaCompletion::Blocking)?;
            let result = self.wait_dma_completion(transfer, 10000)?; // 10ms timeout
            
            match result {
                DmaResult::Success(hash) => Ok(hash),
                DmaResult::Error(e) => Err(AspeedError::DmaError(e)),
            }
        } else {
            // Use programmed I/O for small messages
            self.process_message_pio(message)
        }
    }
}
```

#### Hardware Abstraction Layer

```rust
/// Platform-agnostic hardware abstraction for crypto operations
pub trait CryptoHal {
    type Error;
    type DigestOp: HardwareDigest<Error = Self::Error>;
    type MacOp: HardwareDigest<Error = Self::Error>;
    
    /// Detect available crypto hardware
    fn detect_hardware(&mut self) -> Result<HardwareInfo, Self::Error>;
    
    /// Initialize crypto subsystem
    fn init_crypto(&mut self) -> Result<(), Self::Error>;
    
    /// Create hardware-accelerated digest operation
    fn create_hw_digest(&mut self, algorithm: u32) -> Result<Self::DigestOp, Self::Error>;
    
    /// Create hardware-accelerated MAC operation
    fn create_hw_mac(&mut self, algorithm: u32, key: &[u8]) -> Result<Self::MacOp, Self::Error>;
    
    /// Get hardware performance characteristics
    fn get_performance_info(&self) -> PerformanceInfo;
}

#[derive(Debug)]
pub struct HardwareInfo {
    pub vendor_id: u32,
    pub device_id: u32,
    pub revision: u8,
    pub capabilities: HardwareCapabilities,
    pub firmware_version: Option<[u8; 16]>,
}

#[derive(Debug)]
pub struct PerformanceInfo {
    pub throughput_mbps: u32,
    pub latency_us: u32,
    pub power_mw: u16,
    pub concurrent_ops: u8,
}

/// Platform-specific implementations
impl CryptoHal for AspeedCryptoHal {
    type Error = AspeedError;
    type DigestOp = AspeedDigestOp;
    type MacOp = AspeedMacOp;
    
    fn detect_hardware(&mut self) -> Result<HardwareInfo, Self::Error> {
        let vendor_id = self.read_register(VENDOR_ID_REG)?;
        let device_id = self.read_register(DEVICE_ID_REG)?;
        
        if vendor_id != ASPEED_VENDOR_ID {
            return Err(AspeedError::UnsupportedHardware);
        }
        
        Ok(HardwareInfo {
            vendor_id,
            device_id,
            revision: self.read_register(REVISION_REG)? as u8,
            capabilities: self.detect_capabilities()?,
            firmware_version: self.read_firmware_version()?,
        })
    }
}
```

### Power Management

Embedded systems require sophisticated power management to balance performance with energy efficiency, especially in battery-powered or energy-harvesting applications.

#### Power-Aware Cryptographic Operations

```rust
/// Power-aware cryptographic operations with detailed energy modeling
pub trait PowerAwareDigest: ErrorType {
    /// Estimate power consumption for operation
    fn estimate_power_usage(&self, data_size: usize) -> PowerEstimate;
    
    /// Request specific power mode for operations
    fn set_power_mode(&mut self, mode: PowerMode) -> Result<(), Self::Error>;
    
    /// Get current power consumption
    fn get_current_power(&self) -> Result<PowerMeasurement, Self::Error>;
    
    /// Prepare for system suspend
    fn prepare_suspend(&mut self) -> Result<SuspendState, Self::Error>;
    fn resume_from_suspend(&mut self, state: SuspendState) -> Result<(), Self::Error>;
    
    /// Schedule operation for optimal power efficiency
    fn schedule_for_efficiency(&mut self, deadline: u64, priority: PowerPriority) -> Result<ScheduleToken, Self::Error>;
    
    /// Energy budget management
    fn set_energy_budget(&mut self, budget: EnergyBudget) -> Result<(), Self::Error>;
    fn get_remaining_budget(&self) -> EnergyBudget;
}

#[derive(Debug, Clone, Copy)]
pub struct PowerEstimate {
    pub energy_microjoules: u32,
    pub peak_current_ma: u16,
    pub average_current_ma: u16,
    pub duration_us: u32,
    pub thermal_impact: ThermalImpact,
}

#[derive(Debug, Clone, Copy)]
pub enum PowerMode {
    HighPerformance,  // Maximum speed, highest power
    Balanced,         // Good balance of speed and power
    LowPower,        // Minimum power, slower processing
    UltraLowPower,   // Minimal power, very slow
    Adaptive,        // Automatically adjust based on conditions
}

#[derive(Debug, Clone, Copy)]
pub struct PowerMeasurement {
    pub voltage_mv: u16,
    pub current_ma: u16,
    pub power_mw: u16,
    pub temperature_c: i8,
    pub efficiency_percent: u8,
}

#[derive(Debug, Clone, Copy)]
pub enum PowerPriority {
    Critical,    // Must complete regardless of power cost
    High,        // Important but consider power
    Normal,      // Standard priority
    Background,  // Can be deferred for power savings
}

#[derive(Debug, Clone)]
pub struct EnergyBudget {
    pub total_microjoules: u32,
    pub consumed_microjoules: u32,
    pub window_duration_ms: u32,
    pub hard_limit: bool,
}

#[derive(Debug, Clone, Copy)]
pub enum ThermalImpact {
    Negligible,
    Low,
    Moderate,
    High,
    Critical,
}
```

#### Dynamic Voltage and Frequency Scaling (DVFS)

```rust
/// DVFS-aware digest operations
pub trait DigestOpDvfs: PowerAwareDigest {
    /// Get supported voltage/frequency combinations
    fn get_supported_dvfs_states(&self) -> &[DvfsState];
    
    /// Request optimal DVFS state for current workload
    fn request_optimal_dvfs(&mut self, workload: WorkloadCharacteristics) -> Result<DvfsState, Self::Error>;
    
    /// Adapt to DVFS transition
    fn handle_dvfs_transition(&mut self, old_state: DvfsState, new_state: DvfsState) -> Result<(), Self::Error>;
}

#[derive(Debug, Clone, Copy)]
pub struct DvfsState {
    pub voltage_mv: u16,
    pub frequency_mhz: u16,
    pub power_mw: u16,
    pub performance_factor: f32, // Relative to maximum performance
}

#[derive(Debug, Clone, Copy)]
pub struct WorkloadCharacteristics {
    pub data_size: usize,
    pub deadline_us: u32,
    pub computational_intensity: ComputationalIntensity,
    pub memory_access_pattern: MemoryAccessPattern,
}

#[derive(Debug, Clone, Copy)]
pub enum ComputationalIntensity {
    Light,    // Simple hash operations
    Moderate, // Standard crypto operations
    Heavy,    // Complex multi-stage operations
}

#[derive(Debug, Clone, Copy)]
pub enum MemoryAccessPattern {
    Sequential,  // Linear memory access
    Random,      // Random memory access
    Streaming,   // Continuous streaming
    Burst,       // Bursty access patterns
}
```

#### Sleep State Management

```rust
/// Sleep state management for crypto operations
pub trait CryptoSleepManager {
    type Error;
    
    /// Enter sleep state when idle
    fn enter_sleep(&mut self, max_sleep_us: u32) -> Result<SleepResult, Self::Error>;
    
    /// Wake from sleep state
    fn wake_from_sleep(&mut self) -> Result<(), Self::Error>;
    
    /// Set wake conditions
    fn configure_wake_sources(&mut self, sources: &[WakeSource]) -> Result<(), Self::Error>;
    
    /// Get time until next required wake
    fn time_until_next_wake(&self) -> Option<u32>;
}

#[derive(Debug)]
pub enum SleepResult {
    SleptFor(u32),           // Microseconds actually slept
    WokeEarly(WakeReason),   // Woke before timeout
    CouldNotSleep,           // Sleep not possible
}

#[derive(Debug)]
pub enum WakeReason {
    Timeout,
    Interrupt,
    ExternalEvent,
    ProtocolMessage,
    ScheduledOperation,
}

#[derive(Debug, Clone, Copy)]
pub enum WakeSource {
    Timer(u32),              // Wake after specified microseconds
    Interrupt(u8),           // Wake on specific interrupt
    NetworkActivity,         // Wake on network traffic
    ProtocolEvent,          // Wake on protocol-specific events
}

/// Power-efficient SPDM session manager
pub struct PowerEfficientSpdmSession<D: PowerAwareDigest> {
    digest_provider: D,
    power_budget: EnergyBudget,
    sleep_manager: Box<dyn CryptoSleepManager<Error = D::Error>>,
    scheduled_operations: heapless::Vec<ScheduledOperation, 8>,
}

impl<D: PowerAwareDigest> PowerEfficientSpdmSession<D> {
    /// Process SPDM message with power optimization
    pub fn process_message_power_optimized(
        &mut self, 
        message: &[u8], 
        deadline: u64, 
        priority: PowerPriority
    ) -> Result<Vec<u8>, D::Error> {
        // Check energy budget
        let estimate = self.digest_provider.estimate_power_usage(message.len());
        if estimate.energy_microjoules > self.power_budget.total_microjoules - self.power_budget.consumed_microjoules {
            if !self.power_budget.hard_limit {
                // Try to defer or optimize
                return self.defer_or_optimize(message, deadline, priority);
            } else {
                return Err(/* energy budget exceeded */);
            }
        }
        
        // Set optimal power mode based on deadline and priority
        let power_mode = self.calculate_optimal_power_mode(deadline, priority);
        self.digest_provider.set_power_mode(power_mode)?;
        
        // Schedule operation if not urgent
        if priority == PowerPriority::Background {
            let token = self.digest_provider.schedule_for_efficiency(deadline, priority)?;
            self.scheduled_operations.push(ScheduledOperation {
                token,
                message_hash: self.hash_message(message),
                deadline,
            })?;
            return Ok(vec![]); // Will process later
        }
        
        // Process immediately
        self.process_message_immediate(message)
    }
    
    /// Enter power-saving mode during idle periods
    pub fn enter_idle_mode(&mut self) -> Result<(), D::Error> {
        // Save current state
        let suspend_state = self.digest_provider.prepare_suspend()?;
        
        // Calculate maximum sleep time
        let next_operation = self.scheduled_operations.iter()
            .map(|op| op.deadline)
            .min()
            .unwrap_or(u64::MAX);
        
        let current_time = get_system_time_us();
        let max_sleep = if next_operation > current_time {
            (next_operation - current_time) as u32
        } else {
            0
        };
        
        if max_sleep > 1000 { // Only sleep if worthwhile (>1ms)
            self.sleep_manager.configure_wake_sources(&[
                WakeSource::Timer(max_sleep),
                WakeSource::NetworkActivity,
                WakeSource::ProtocolEvent,
            ])?;
            
            match self.sleep_manager.enter_sleep(max_sleep)? {
                SleepResult::SleptFor(duration) => {
                    // Update power savings
                    self.update_power_savings(duration);
                },
                SleepResult::WokeEarly(reason) => {
                    // Handle early wake
                    self.handle_early_wake(reason)?;
                },
                SleepResult::CouldNotSleep => {
                    // Continue normal operation
                },
            }
        }
        
        // Resume crypto operations
        self.digest_provider.resume_from_suspend(suspend_state)?;
        Ok(())
    }
}

#[derive(Debug)]
struct ScheduledOperation {
    token: ScheduleToken,
    message_hash: u32,
    deadline: u64,
}
```

### Embedded Security Considerations

Embedded systems face unique security challenges that must be addressed in the cryptographic trait design.

#### Side-Channel Attack Resistance

```rust
/// Side-channel resistant operations for security-critical embedded systems
pub trait SideChannelResistant: ErrorType {
    /// Constant-time implementation guarantee
    fn is_constant_time(&self) -> bool;
    
    /// Memory access pattern randomization
    fn enable_access_randomization(&mut self, enabled: bool) -> Result<(), Self::Error>;
    
    /// Power analysis countermeasures
    fn enable_power_countermeasures(&mut self, level: CountermeasureLevel) -> Result<(), Self::Error>;
    
    /// Timing randomization for operation completion
    fn add_timing_jitter(&mut self, max_jitter_us: u32) -> Result<(), Self::Error>;
    
    /// Clear sensitive data from memory
    fn secure_clear(&mut self) -> Result<(), Self::Error>;
}

#[derive(Debug, Clone, Copy)]
pub enum CountermeasureLevel {
    None,
    Basic,      // Basic power line filtering
    Enhanced,   // Active power randomization
    Military,   // Full spectrum countermeasures
}

/// Secure memory management for embedded crypto operations
pub trait SecureMemory {
    /// Allocate secure memory region
    fn allocate_secure(&mut self, size: usize) -> Result<SecureBuffer, Self::Error>;
    
    /// Lock memory pages to prevent swapping
    fn lock_memory(&mut self, buffer: &mut [u8]) -> Result<(), Self::Error>;
    
    /// Securely zero memory
    fn secure_zero(&mut self, buffer: &mut [u8]);
    
    /// Check for memory tampering
    fn verify_integrity(&self, buffer: &[u8]) -> Result<bool, Self::Error>;
}

/// Secure buffer with automatic cleanup
pub struct SecureBuffer {
    ptr: *mut u8,
    size: usize,
    canary: u64,
}

impl SecureBuffer {
    /// Access buffer data safely
    pub fn as_slice(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.ptr, self.size) }
    }
    
    /// Access buffer data mutably
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.ptr, self.size) }
    }
    
    /// Check for buffer overflow attacks
    pub fn check_canary(&self) -> bool {
        // Implementation would check canary values
        true
    }
}

impl Drop for SecureBuffer {
    fn drop(&mut self) {
        // Securely clear memory before deallocation
        if !self.ptr.is_null() {
            unsafe {
                core::ptr::write_bytes(self.ptr, 0, self.size);
                // Additional randomization passes could be added here
            }
        }
    }
}
```

#### Trusted Execution Environment (TEE) Integration

```rust
/// TEE-aware cryptographic operations
pub trait TeeAwareDigest: ErrorType {
    /// Execute operation in trusted environment
    fn execute_in_tee(&mut self, operation: TeeOperation) -> Result<TeeResult, Self::Error>;
    
    /// Verify execution environment trust level
    fn verify_trust_level(&self) -> TrustLevel;
    
    /// Attest operation integrity
    fn create_attestation(&self) -> Result<AttestationToken, Self::Error>;
    
    /// Seal data to current environment
    fn seal_data(&mut self, data: &[u8]) -> Result<SealedData, Self::Error>;
    
    /// Unseal previously sealed data
    fn unseal_data(&mut self, sealed: &SealedData) -> Result<Vec<u8>, Self::Error>;
}

#[derive(Debug, Clone, Copy)]
pub enum TrustLevel {
    Untrusted,          // Normal world execution
    Secure,             // Secure world execution
    TrustedApplication, // Trusted application context
    Hardware,           // Hardware-backed security
}

pub struct TeeOperation {
    pub operation_type: TeeOpType,
    pub input_data: &'static [u8],
    pub expected_output_size: usize,
}

#[derive(Debug)]
pub enum TeeOpType {
    Digest(u32),          // Algorithm ID
    Mac(u32, &'static [u8]), // Algorithm ID + key
    KeyDerivation,
    RandomGeneration,
}

/// ARM TrustZone integration for ASPEED systems
pub struct AspeedTrustZoneDigest {
    secure_world_interface: *mut u8,
    trust_level: TrustLevel,
    attestation_key: Option<[u8; 32]>,
}

impl TeeAwareDigest for AspeedTrustZoneDigest {
    type Error = AspeedTeeError;
    
    fn execute_in_tee(&mut self, operation: TeeOperation) -> Result<TeeResult, Self::Error> {
        // Transition to secure world
        let smc_result = self.secure_monitor_call(
            SMC_CRYPTO_OPERATION,
            operation.operation_type as u64,
            operation.input_data.as_ptr() as u64,
            operation.input_data.len() as u64,
        )?;
        
        // Verify result integrity
        if !self.verify_result_integrity(&smc_result) {
            return Err(AspeedTeeError::IntegrityFailure);
        }
        
        Ok(TeeResult {
            data: smc_result.output,
            attestation: smc_result.attestation,
            trust_level: TrustLevel::Secure,
        })
    }
    
    fn verify_trust_level(&self) -> TrustLevel {
        if self.is_in_secure_world() {
            TrustLevel::Secure
        } else {
            TrustLevel::Untrusted
        }
    }
}
```

#### Fault Injection Resistance

```rust
/// Fault injection resistant operations
pub trait FaultResistant: ErrorType {
    /// Execute operation with redundancy checks
    fn execute_with_redundancy(&mut self, operation: FaultResistantOp) -> Result<VerifiedResult, Self::Error>;
    
    /// Detect and handle fault injection attempts
    fn detect_fault_injection(&self) -> Result<FaultDetectionResult, Self::Error>;
    
    /// Configure fault detection sensitivity
    fn set_fault_detection_level(&mut self, level: FaultDetectionLevel) -> Result<(), Self::Error>;
    
    /// Reset after detected fault
    fn fault_recovery(&mut self) -> Result<(), Self::Error>;
}

#[derive(Debug)]
pub struct FaultResistantOp {
    pub primary_operation: Box<dyn FnOnce() -> Result<Vec<u8>, ()>>,
    pub verification_operation: Box<dyn FnOnce(&[u8]) -> bool>,
    pub redundancy_level: RedundancyLevel,
}

#[derive(Debug, Clone, Copy)]
pub enum RedundancyLevel {
    None,
    Dual,      // Execute twice, compare results
    Triple,    // Execute three times, majority vote
    Adaptive,  // Adjust based on environmental conditions
}

#[derive(Debug)]
pub struct FaultDetectionResult {
    pub fault_detected: bool,
    pub fault_type: Option<FaultType>,
    pub confidence: u8, // 0-100
    pub recommended_action: FaultAction,
}

#[derive(Debug, Clone, Copy)]
pub enum FaultType {
    VoltageGlitch,
    ClockGlitch,
    LaserFault,
    EMIFault,
    TemperatureFault,
}

#[derive(Debug, Clone, Copy)]
pub enum FaultAction {
    Continue,
    Retry,
    Reset,
    Shutdown,
    Alert,
}

#[derive(Debug, Clone, Copy)]
pub enum FaultDetectionLevel {
    Minimal,   // Basic checks
    Standard,  // Standard fault detection
    Paranoid,  // Maximum sensitivity
}

/// Fault-resistant SPDM implementation
pub struct FaultResistantSpdm<D: FaultResistant> {
    digest_provider: D,
    fault_counter: u32,
    max_faults: u32,
}

impl<D: FaultResistant> FaultResistantSpdm<D> {
    pub fn process_critical_message(&mut self, message: &[u8]) -> Result<Vec<u8>, D::Error> {
        // Check for environmental fault conditions
        let fault_result = self.digest_provider.detect_fault_injection()?;
        if fault_result.fault_detected {
            self.fault_counter += 1;
            
            match fault_result.recommended_action {
                FaultAction::Retry => {
                    if self.fault_counter < self.max_faults {
                        return self.process_critical_message(message); // Recursive retry
                    } else {
                        return Err(/* too many faults */);
                    }
                },
                FaultAction::Reset => {
                    self.digest_provider.fault_recovery()?;
                    self.fault_counter = 0;
                },
                FaultAction::Shutdown => {
                    return Err(/* system shutdown required */);
                },
                _ => {},
            }
        }
        
        // Execute with fault resistance
        let operation = FaultResistantOp {
            primary_operation: Box::new(|| {
                // Primary hash computation
                self.compute_hash_primary(message)
            }),
            verification_operation: Box::new(|result| {
                // Verify result consistency
                self.verify_hash_result(result, message)
            }),
            redundancy_level: RedundancyLevel::Triple,
        };
        
        let verified_result = self.digest_provider.execute_with_redundancy(operation)?;
        
        if verified_result.confidence < 95 {
            return Err(/* low confidence result */);
        }
        
        Ok(verified_result.data)
    }
}
```

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

- **Security-by-Design**: Built-in protection against side-channel attacks, fault injection, and other embedded-specific threats ensures robust security even in hostile environments.

### 4. Performance Considerations
- **Zero-cost static path**: Direct trait implementations for compile-time known algorithms
- **Minimal dynamic overhead**: Efficient runtime dispatch only when protocol negotiation is required
- **Hardware acceleration**: Transparent integration with platform-specific crypto engines
- **Memory locality**: Cache-friendly data structures and access patterns

### 5. Security-by-Design
- **Side-channel resistance**: Constant-time operations and power analysis countermeasures
- **Fault tolerance**: Redundant execution and integrity verification
- **TEE integration**: Support for trusted execution environments and secure world operations
- **Memory protection**: Secure buffer management and automatic cleanup

### 6. Error Handling Strategy
- **Layered error types**: Protocol errors separate from implementation and hardware errors
- **Graceful degradation**: Fallback mechanisms for hardware failures and capability mismatches
- **Security-aware errors**: No information leakage through error messages
- **Recovery mechanisms**: Automatic fault recovery and system resilience

### 7. Composability and Extensibility
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

**Security-by-Design**: Built-in protection against side-channel attacks, fault injection, and other embedded-specific threats ensures robust security even in hostile environments.

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
- Integration examples for common embedded platforms (ASPEED, ARM Cortex-M, RISC-V)

### 7. Platform-Specific Optimizations
Create reference implementations for common embedded platforms:
- ASPEED crypto engine integration with full feature support
- ARM TrustZone integration for TEE-aware operations
- Low-power microcontroller adaptations
- FPGA-based crypto accelerator support

This enhanced design enables robust, secure, and efficient cryptographic operations that can adapt to diverse protocol requirements while maintaining the performance characteristics essential for embedded systems. The focus on memory efficiency, real-time guarantees, power optimization, and security-by-design makes it suitable for the most demanding embedded applications including safety-critical systems, IoT devices, and infrastructure controllers.

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
pub struct HybridDigestRegistry {
    // Static implementations for compile-time known algorithms
    sha256_impl: Option<Box<dyn Fn() -> AspeedSha256Op>>,
    sha384_impl: Option<Box<dyn Fn() -> AspeedSha384Op>>,
    sha512_impl: Option<Box<dyn Fn() -> AspeedSha512Op>>,
    
    // Dynamic registry for runtime algorithm selection
    dynamic_providers: HashMap<u32, Box<dyn DigestProvider>>,
    
    // Performance optimization: prefer static when available
    prefer_static: bool,
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

impl HybridDigestRegistry {
    pub fn new() -> Self {
        Self {
            sha256_impl: None,
            sha384_impl: None,
            sha512_impl: None,
            dynamic_providers: HashMap::new(),
            prefer_static: true,
        }
    }
    
    /// Register static implementation for optimal performance
    pub fn register_static_sha256<F>(&mut self, factory: F) 
    where F: Fn() -> AspeedSha256Op + 'static 
    {
        self.sha256_impl = Some(Box::new(factory));
    }
    
    /// Register dynamic implementation for flexibility
    pub fn register_dynamic_provider(&mut self, algorithm_id: u32, provider: Box<dyn DigestProvider>) {
        self.dynamic_providers.insert(algorithm_id, provider);
    }
    
    /// Create digest with optimal dispatch strategy
    pub fn create_optimized_digest(&mut self, algorithm_id: u32) -> Result<OptimizedDigest, RegistryError> {
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
pub enum OptimizedDigest {
    Static(StaticDigestVariant),
    Dynamic(Box<dyn DigestOpDyn>),
}

pub enum StaticDigestVariant {
    Sha256(AspeedSha256Op),
    Sha384(AspeedSha384Op),
    Sha512(AspeedSha512Op),
}

impl DigestOpDyn for OptimizedDigest {
    type Error = HybridError;
    
    fn update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        match self {
            OptimizedDigest::Static(variant) => {
                match variant {
                    StaticDigestVariant::Sha256(op) => op.update(input).map_err(HybridError::Static),
                    StaticDigestVariant::Sha384(op) => op.update(input).map_err(HybridError::Static),
                    StaticDigestVariant::Sha512(op) => op.update(input).map_err(HybridError::Static),
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
    Static(AspeedDigestError),
    Dynamic(Box<dyn core::error::Error>),
    Registry(RegistryError),
}
```

### Protocol Negotiation with Hybrid Dispatch

```rust
/// SPDM session that optimally uses both static and dynamic implementations
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
    pub fn new() -> Self {
        let mut registry = HybridDigestRegistry::new();
        
        // Register static implementations for maximum performance
        registry.register_static_sha256(|| AspeedSha256Op::new_hardware());
        
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

/// Complete example usage in embedded context
pub fn embedded_spdm_example() -> Result<(), Box<dyn core::error::Error>> {
    let mut spdm_session = HybridSpdmSession::new();
    
    // Scenario 1: Initial negotiation with performance requirements
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
    
    let negotiated = spdm_session.negotiate_algorithm_with_performance(
        peer_algorithms, 
        real_time_requirements
    )?;
    
    println!("Negotiated algorithm: {} (static dispatch preferred)", negotiated);
    
    // Scenario 2: Process real-time critical message
    let critical_message = b"Critical security message requiring fast processing";
    let result = spdm_session.process_message_real_time(critical_message, 800)?; // 800μs deadline
    
    println!("Critical message processed: {} bytes output", result.len());
    
    // Scenario 3: Process normal message with optimization
    let normal_message = b"Normal SPDM message for capability exchange";
    let result = spdm_session.process_message_optimized(normal_message)?;
    
    println!("Normal message processed: {} bytes output", result.len());
    
    // Scenario 4: Handle algorithm change during session
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
    
    let new_algorithm = spdm_session.negotiate_algorithm_with_performance(
        new_peer_algorithms, 
        flexible_requirements
    )?;
    
    println!("Re-negotiated to algorithm: {} (dynamic dispatch acceptable)", new_algorithm);
    
    // Process with new algorithm
    let final_message = b"Message processed with newly negotiated algorithm";
    let result = spdm_session.process_message_optimized(final_message)?;
    
    println!("Final message processed: {} bytes output", result.len());
    
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
```

### Key Benefits of This Approach

1. **Performance Optimization**: Static dispatch for critical paths, dynamic dispatch for flexibility
2. **Runtime Adaptability**: Can switch between implementations based on performance feedback
3. **Resource Efficiency**: Uses optimal implementation for current constraints
4. **Backwards Compatibility**: Supports both static and dynamic trait patterns
5. **Real-Time Support**: Guarantees timing requirements through static dispatch when needed
6. **Protocol Compliance**: Maintains full SPDM protocol compatibility while optimizing performance

This hybrid approach demonstrates how embedded systems can benefit from both compile-time optimization and runtime flexibility, adapting to changing performance requirements and protocol negotiations while maintaining strict timing and resource constraints.
