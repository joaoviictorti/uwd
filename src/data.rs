#![allow(non_snake_case, non_camel_case_types)]

use core::ffi::c_void;

/// Indicates the presence of an exception handler in the function.
pub const UNW_FLAG_EHANDLER: u8 = 0x1;

/// Indicates chained unwind information is present.
pub const UNW_FLAG_CHAININFO: u8 = 0x4;

/// Configuration structure passed to the spoof ASM routine.
#[repr(C)]
#[derive(Debug)]
pub struct Config {
    /// Address RtlUserThreadStart
    pub rtl_user_addr: *const c_void,

    /// Stack Size RtlUserThreadStart
    pub rtl_user_thread_size: u64,

    /// Address BaseThreadInitThunk
    pub base_thread_addr: *const c_void,

    /// Stack Size BaseThreadInitThunk
    pub base_thread_size: u64,

    /// First (fake) return address frame
    pub first_frame_fp: *const c_void,

    /// Second (ROP) return address frame
    pub second_frame_fp: *const c_void,

    /// Gadget: `jmp [rbx]`
    pub jmp_rbx_gadget: *const c_void,

    /// Gadget: `add rsp, X; ret`
    pub add_rsp_gadget: *const c_void,

    /// Stack size of first spoofed frame
    pub first_frame_size: u64,

    /// Stack size of second spoofed frame
    pub second_frame_size: u64,

    /// Stack frame size where the `jmp [rbx]` gadget resides
    pub jmp_rbx_frame_size: u64,

    /// Stack frame size where the `add rsp, X` gadget resides
    pub add_rsp_frame_size: u64,

    /// Offset on the stack where `rbp` is pushed
    pub rbp_stack_offset: u64,

    /// The function to be spoofed / called
    pub spoof_function: *const c_void,

    /// Return address (used as stack-resume point after call)
    pub return_address: *const c_void,

    /// Checks if the target is a syscall
    pub is_syscall: u32,

    /// System Service Number (SSN)
    pub ssn: u16,

    /// Arguments that will be passed to the function that will be spoofed
    pub number_args: u32,
    pub arg01: *const c_void,
    pub arg02: *const c_void,
    pub arg03: *const c_void,
    pub arg04: *const c_void,
    pub arg05: *const c_void,
    pub arg06: *const c_void,
    pub arg07: *const c_void,
    pub arg08: *const c_void,
    pub arg09: *const c_void,
    pub arg10: *const c_void,
    pub arg11: *const c_void,
}

impl Default for Config {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}

/// Enumeration of x86_64 general-purpose registers.
///
/// Used in unwind parsing or register mapping logic.
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
#[allow(dead_code)]
pub enum Registers {
    Rax = 0,
    Rcx,
    Rdx,
    Rbx,
    Rsp,
    Rbp,
    Rsi,
    Rdi,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
}

impl PartialEq<usize> for Registers {
    fn eq(&self, other: &usize) -> bool {
        *self as usize == *other
    }
}

/// Union representing a single unwind operation code.
#[repr(C)]
pub union UNWIND_CODE {
    /// Offset into the stack frame for the operation.
    pub FrameOffset: u16,

    /// Structured fields of the unwind code.
    pub Anonymous: UNWIND_CODE_0,
}

bitfield::bitfield! {
    /// Bitfield representation of an unwind code entry.
    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct UNWIND_CODE_0(u16);

    /// Byte offset from the start of the prologue where this operation is applied.
    pub u8, CodeOffset, SetCodeOffset: 7, 0;

    /// The unwind operation code.
    pub u8, UnwindOp, SetUnwindOp: 11, 8;

    /// Additional operation-specific information.
    pub u8, OpInfo, SetOpInfo: 15, 12;
}

/// Union representing optional exception handler or chained function entry.
#[repr(C)]
pub union UNWIND_INFO_0 {
    /// Address of the exception handler (RVA).
    pub ExceptionHandler: u32,

    /// Address of a chained function entry.
    pub FunctionEntry: u32,
}

bitfield::bitfield! {
    /// Combines the `Version` and `Flags` fields in a compact format.
    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct UNWIND_VERSION_FLAGS(u8);

    /// Unwind info format version.
    pub u8, Version, SetVersion: 2, 0;

    /// Unwind flags.
    pub u8, Flags, SetFlags: 7, 3;
}

bitfield::bitfield! {
    /// Compact representation of frame register and offset fields.
    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct UNWIND_FRAME_INFO(u8);

    /// The register used as the frame pointer.
    pub u8, FrameRegister, SetFrameRegister: 3, 0;

    /// Offset from the stack pointer to the frame pointer.
    pub u8, FrameOffset, SetFrameOffset: 7, 4;
}

/// Structure containing the unwind information of a function.
#[repr(C)]
pub struct UNWIND_INFO {
    /// Separate structure containing `Version` and `Flags`.
    pub VersionFlags: UNWIND_VERSION_FLAGS,

    /// Size of the function prologue in bytes.
    pub SizeOfProlog: u8,

    /// Number of non-array `UnwindCode` entries.
    pub CountOfCodes: u8,

    /// Separate structure containing `FrameRegister` and `FrameOffset`.
    pub FrameInfo: UNWIND_FRAME_INFO,

    /// Array of unwind codes describing specific operations.
    pub UnwindCode: UNWIND_CODE,

    /// Union containing `ExceptionHandler` or `FunctionEntry`.
    pub Anonymous: UNWIND_INFO_0,

    /// Optional exception data.
    pub ExceptionData: u32,
}

/// Unwind operation codes used by the Windows x64 exception handling model.
///
/// For full details, refer to Microsoft documentation:
/// https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64
#[repr(u8)]
#[allow(dead_code)]
pub enum UNWIND_OP_CODES {
    UWOP_PUSH_NONVOL = 0,
    UWOP_ALLOC_LARGE = 1,
    UWOP_ALLOC_SMALL = 2,
    UWOP_SET_FPREG = 3,
    UWOP_SAVE_NONVOL = 4,
    UWOP_SAVE_NONVOL_BIG = 5,
    UWOP_EPILOG = 6,
    UWOP_SPARE_CODE = 7,
    UWOP_SAVE_XMM128 = 8,
    UWOP_SAVE_XMM128BIG = 9,
    UWOP_PUSH_MACH_FRAME = 10,
}

impl TryFrom<u8> for UNWIND_OP_CODES {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0..=10 => Ok(unsafe { core::mem::transmute::<u8, UNWIND_OP_CODES>(value) }),
            _ => Err(()),
        }
    }
}