use crate::error::*;

pub trait TaskSyscalls:
    TaskCreation + TaskTermination + TaskScheduling + TaskInspection
{}

/// Trait for inspecting the state and metadata of tasks in a microkernel.
///
/// This trait is intended for non-static microkernels that support runtime
/// introspection of task state. It allows querying information about a task
/// using its task ID.
///
/// The associated type `Info` defines the structure returned by the inspection,
/// which may include fields such as task state, priority, runtime statistics, etc.
pub trait TaskInspection: Send + Sync + ErrorType{
    /// Type representing the information returned about a task.
    type Info;

    /// Retrieves information about a task by its task ID.
    ///
    /// # Parameters
    /// - `tid`: The task ID of the task to inspect.
    ///
    /// # Returns
    /// - `Ok(Self::Info)`: Structured information about the task.
    /// - `Err(SyscallError)`: If the task does not exist or cannot be inspected.
    fn inspect_task(&self, tid: u64) -> Result<Self::Info, Self::Error>;
}


/// Trait for creating tasks in non-static kernels.
///
/// This trait is intended for kernels that support dynamic task creation at runtime.
/// Static kernels, where all tasks are defined at compile time, should not implement this trait.
///
/// The associated type `Param` allows each implementation to define its own
/// task configuration structure, enabling flexibility in how tasks are created.
pub trait TaskCreation: Send + Sync + ErrorType{
    /// Type representing the parameters required to create a task.
    type Param;

    /// Creates a new task using the provided parameters.
    ///
    /// # Parameters
    /// - `params`: Task creation parameters defined by the implementation.
    ///
    /// # Returns
    /// - `Ok(tid)`: Task ID of the newly created task.
    /// - `Err(SyscallError)`: If creation fails.
    fn create_task(&self, params: Self::Param) -> Result<u64, Self::Error>;
}

pub trait TaskScheduling: Send + Sync + ErrorType {
    /// Yields the processor, allowing other tasks to run.
    fn task_yield(&self) -> Result<(), Self::Error>;

    /// Sets the priority of the current task.
    ///
    /// # Parameters
    /// - `priority`: New priority level for the task.
    ///
    /// # Returns
    /// - `Ok(())`: If the priority was successfully changed.
    /// - `Err(SyscallError)`: If the operation failed.
    fn task_set_priority(&self, priority: u32) -> Result<(), Self::Error>;
}

/// Trait for terminating tasks in the system.
///
/// This is used to signal that a task has completed or should be forcefully exited.
pub trait TaskTermination: Send + Sync + ErrorType {
    /// Terminates the task with the given task ID and exit code.
    ///
    /// # Parameters
    /// - `tid`: Task ID of the task to terminate.
    /// - `exit_code`: Exit code to report for the task.
    ///
    /// # Returns
    /// - `Ok(())`: If the task was successfully terminated.
    /// - `Err(SyscallError)`: If the termination failed.
    fn task_exit(&self, tid: u64, exit_code: i32) -> Result<(), Self::Error>;
}
