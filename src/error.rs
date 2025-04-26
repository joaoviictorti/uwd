use core::fmt;

/// Represents all possible errors that can occur during spoofing operations.
#[derive(Debug, Clone, Copy)]
pub enum SpoofError {
    /// More than the allowed number of arguments were passed (max 11).
    TooManyArguments,

    /// Null address provided for a function call when one was expected.
    NullFunctionAddress,

    /// Failed to get a handle to `kernelbase.dll`.
    KernelbaseNotFound,

    /// Failed to locate the exception directory within `kernelbase.dll`.
    RuntimeAddressNotFound,

    /// Failed to find the return address from `BaseThreadInitThunk` on the stack.
    ReturnAddressNotFound,

    /// Failed to locate a valid first function prologue.
    FirstPrologNotFound,

    /// Failed to locate a valid second prologue with `push rbp`.
    SecondPrologNotFound,

    /// Failed to find the `add rsp, 0x58; ret` gadget.
    AddRspGadgetNotFound,

    /// Failed to find the `jmp rbx` gadget.
    JmpRbxGadgetNotFound,

    /// Failed to get a handle to `ntdll.dll`.
    NtdllNotFound,

    /// Failed to get a handle to `kernel32.dll`.
    Kernel32NotFound,

    /// Failed to locate `RtlUserThreadStart` within `ntdll.dll`.
    RtlUserThreadStartNotFound,

    /// Failed to locate `BaseThreadInitThunk` within `kernel32.dll`.
    BaseThreadInitThunkNotFound,

    /// Failed to find the runtime function structure for `RtlUserThreadStart`.
    RtlUserRuntimeNotFound,

    /// Failed to find the runtime function structure for `BaseThreadInitThunk`.
    BaseThreadRuntimeNotFound,

    /// Failed to recover the stack frame size for `RtlUserThreadStart`.
    RtlUserStackSizeNotFound,

    /// Failed to recover the stack frame size for `BaseThreadInitThunk`.
    BaseThreadStackSizeNotFound,

    /// Failed to resolve the address of the target function.
    ProcAddressNotFound,

    /// Failed to retrieve the syscall number (SSN) for the function.
    SsnNotFound,

    /// Failed to locate the system call trampoline address.
    SyscallAddressNotFound,
}

impl fmt::Display for SpoofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}