use alloc::{string::String, vec::Vec};
use core::{ffi::c_void, slice::from_raw_parts};
use anyhow::{Context, Result, bail};
use obfstr::{obfbytes as b, obfstring as s};
use dinvk::{
    GetModuleHandle, GetProcAddress, NtCurrentTeb,
    data::IMAGE_RUNTIME_FUNCTION,
    hash::{jenkins3, murmur3},
    parse::PE,
    shuffle,
};

use crate::data::{
    Config, Registers,
    UNWIND_OP_CODES::{self, *},
};
use crate::data::{
    UNW_FLAG_CHAININFO,
    UNW_FLAG_EHANDLER,
    UNWIND_CODE,
    UNWIND_INFO,
};

unsafe extern "C" {
    /// Function responsible for Call Stack Spoofing (Desync)
    fn Spoof(config: &mut Config) -> *mut c_void;

    /// Function responsible for Call Stack Spoofing (Synthetic)
    fn SpoofSynthetic(config: &mut Config) -> *mut c_void;
}

/// Invokes the [`Uwd::spoof`] function with the target function address, using a desynchronized call stack.
///
/// # Arguments
///
/// - `$addr`: A pointer to the function to spoof-call (typically a Windows API)
/// - `$arg`: A list of arguments to be passed to the spoofed function (up to 11 maximum)
#[macro_export]
macro_rules! spoof {
    ($addr:expr, $($arg:expr),+ $(,)?) => {
        unsafe {
            $crate::internal::uwd_entry(
                $addr,
                $crate::SpoofKind::Function,
                &[$(::core::mem::transmute($arg as usize)),*],
                false,
            )
        }
    };
}

/// Wraps a native Windows syscall using [`Uwd::spoof`] with desynchronized stack spoofing.
///
/// # Arguments
///
/// - `$name`: The name of the syscall as a string literal (e.g. `"NtWriteVirtualMemory"`).
/// - `$arg`: A list of arguments to be passed to the spoofed function (up to 11 maximum)
#[macro_export]
macro_rules! syscall {
    ($name:expr, $($arg:expr),* $(,)?) => {
        unsafe {
            $crate::internal::uwd_entry(
                core::ptr::null_mut(),
                $crate::SpoofKind::Syscall($name),
                &[$(::core::mem::transmute($arg as usize)),*],
                false,
            )
        }
    };
}

/// Invokes the [`Uwd::spoof_synthetic`] function using a synthetic stack layout.
///
/// # Arguments
///
/// - `$addr`: A pointer to the function to spoof-call (typically a Windows API)
/// - `$arg`: A list of arguments to be passed to the spoofed function (up to 11 maximum)
#[macro_export]
macro_rules! spoof_synthetic {
    ($addr:expr, $($arg:expr),+ $(,)?) => {
        unsafe {
            $crate::internal::uwd_entry(
                $addr,
                $crate::SpoofKind::Function,
                &[$(::core::mem::transmute($arg as usize)),*],
                true,
            )
        }
    };
}

/// Wraps a native Windows syscall using [`Uwd::spoof_synthetic`] with a simulated stack layout.
///
/// # Arguments
///
/// - `$name`: The name of the syscall as a string literal (e.g. `"NtWriteVirtualMemory"`).
/// - `$arg`: A list of arguments to be passed to the spoofed function (up to 11 maximum)
#[macro_export]
macro_rules! syscall_synthetic {
    ($name:expr, $($arg:expr),* $(,)?) => {
        unsafe {
            $crate::internal::uwd_entry(
                core::ptr::null_mut(),
                $crate::SpoofKind::Syscall($name),
                &[$(::core::mem::transmute($arg as usize)),*],
                true,
            )
        }
    };
}

/// Represents metadata extracted from a function's prologue used for call stack spoofing.
#[derive(Copy, Clone)]
struct Prolog {
    /// Address of the function's entry point or relevant instruction
    frame: u64,

    /// Total stack space reserved by the function (in bytes)
    stack_size: u32,

    /// Offset inside the function where a specific instruction pattern is found
    offset: u32,

    /// Offset in the stack where `rbp` is pushed
    rbp_offset: u32,
}

/// Root structure responsible for setting up and orchestrating the call stack spoofing process.
pub struct Uwd;

impl Uwd {
    /// Performs call stack spoofing in `desync` mode, reusing the thread's real stack.
    ///
    /// # Arguments
    ///
    /// * `addr` - Target function pointer. Can be `null` if `kind` is `SpoofKind::Syscall`.
    /// * `args` - Up to 11 arguments that will be passed to the target, cast as `*const c_void`.
    /// * `kind` - The spoofing mode:
    ///     - [`SpoofKind::Function`]: Directly call a function using the spoofed call stack.
    ///     - [`SpoofKind::Syscall`]: Resolve and invoke a Windows syscall via its shadow stub.
    ///
    /// # Returns
    ///
    /// * `Ok(*mut c_void)` — On success, returns the result of the spoofed function or syscall.
    /// * `Err(anyhow::Error)` — If any required setup step fails (e.g., gadgets missing, invalid arguments).
    fn spoof(addr: *mut c_void, args: &[*const c_void], kind: SpoofKind) -> Result<*mut c_void> {
        // Max 11 arguments allowed
        if args.len() > 11 {
            bail!(s!("Too many arguments"));
        }

        // Prevent calling a null function unless it's a syscall
        if let SpoofKind::Function = kind {
            if addr.is_null() {
                bail!(s!("Null function address"));
            }
        }

        // Preparing the `Config` structure for spoofing
        let mut config = Config::default();

        // Get the base address of kernelbase.dll
        let kernelbase = GetModuleHandle(2737729883u32, Some(murmur3));

        // Parse the IMAGE_RUNTIME_FUNCTION table into usable Rust slices.
        let pe = PE::parse(kernelbase);
        let tables = pe
            .unwind()
            .entries()
            .context(s!("Failed to read IMAGE_RUNTIME_FUNCTION entries from .pdata section"))?;

        // Locate a return address from BaseThreadInitThunk on the current stack.
        config.return_address = Self::find_base_thread_return_address().context(s!("Return address not found"))? as *const c_void;

        // First frame: a normal function with a clean prologue
        let first_prolog = Self::find_prolog(kernelbase, tables).context(s!("First prolog not found"))?;
        config.first_frame_fp = (first_prolog.frame + first_prolog.offset as u64) as *const c_void;
        config.first_frame_size = first_prolog.stack_size as u64;

        // Second frame: looks specifically for a prologue with `push rbp`.
        let second_prolog = Self::find_push_rbp(kernelbase, tables).context(s!("Second prolog not found"))?;
        config.second_frame_fp = (second_prolog.frame + second_prolog.offset as u64) as *const c_void;
        config.second_frame_size = second_prolog.stack_size as u64;
        config.rbp_stack_offset = second_prolog.rbp_offset as u64;

        // Find a gadget `add rsp, 0x58; ret`.
        let (add_rsp_addr, size) = Self::find_gadget(kernelbase, b!(&[0x48, 0x83, 0xC4, 0x58, 0xC3]), tables)
            .context(s!("Add RSP gadget not found"))?;
        config.add_rsp_gadget = add_rsp_addr as *const c_void;
        config.add_rsp_frame_size = size as u64;

        // Find a gadget that performs `jmp rbx` - to restore the original call.
        let (jmp_rbx_addr, size) = Self::find_gadget(kernelbase, b!(&[0xFF, 0x23]), tables)
            .context(s!("JMP RBX gadget not found"))?;
        config.jmp_rbx_gadget = jmp_rbx_addr as *const c_void;
        config.jmp_rbx_frame_size = size as u64;

        // Preparing arguments
        let len = args.len().min(11);
        config.number_args = len as u32;
        for (i, &arg) in args.iter().take(len).enumerate() {
            match i {
                0 => config.arg01 = arg,
                1 => config.arg02 = arg,
                2 => config.arg03 = arg,
                3 => config.arg04 = arg,
                4 => config.arg05 = arg,
                5 => config.arg06 = arg,
                6 => config.arg07 = arg,
                7 => config.arg08 = arg,
                8 => config.arg09 = arg,
                9 => config.arg10 = arg,
                10 => config.arg11 = arg,
                _ => break,
            }
        }

        // Spoof kind handling
        match kind {
            // Executes a function that is not syscall
            SpoofKind::Function => {
                config.spoof_function = addr;
            }

            // Executes a syscall indirectly
            SpoofKind::Syscall(name) => {
                // Retrieves the ntdll address
                let ntdll = GetModuleHandle(2788516083u32, Some(murmur3));
                if ntdll.is_null() {
                    bail!(s!("ntdll.dll not found"));
                }

                // Retrieves the address of the function
                let addr = GetProcAddress(ntdll, name, None);
                if addr.is_null() {
                    bail!(s!("GetProcAddress returned null"));
                }

                // Configures the parameters to be sent to execute the syscall indirectly
                config.is_syscall = true as u32;
                config.ssn = dinvk::ssn(name, ntdll).context(s!("SSN not found"))?;
                config.spoof_function = dinvk::get_syscall_address(addr)
                    .context(s!("Syscall address not found"))? as *const c_void;
            }
        }

        // Call the external spoofing routine with the full config.
        Ok(unsafe { Spoof(&mut config) })
    }

    /// Performs call stack spoofing in `synthetic` mode, simulating a fake stack from scratch.
    ///
    /// # Arguments
    ///
    /// * `addr` - Target function pointer. Can be `null` if `kind` is `SpoofKind::Syscall`.
    /// * `args` - Up to 11 arguments that will be passed to the target, cast as `*const c_void`.
    /// * `kind` - The spoofing mode:
    ///     - [`SpoofKind::Function`]: Directly call a function using the spoofed call stack.
    ///     - [`SpoofKind::Syscall`]: Resolve and invoke a Windows syscall via its shadow stub.
    ///
    /// # Returns
    ///
    /// * `Ok(*mut c_void)` — On success, returns the result of the spoofed function or syscall.
    /// * `Err(anyhow::Error)` — If any required setup step fails (e.g., gadgets missing, invalid arguments).
    fn spoof_synthetic(addr: *mut c_void, args: &[*const c_void], kind: SpoofKind) -> Result<*mut c_void> {
        // Max 11 arguments allowed
        if args.len() > 11 {
            bail!(s!("Too many arguments"));
        }

        // Prevent calling a null function unless it's a syscall
        if let SpoofKind::Function = kind {
            if addr.is_null() {
                bail!(s!("Null function address"));
            }
        }

        // Preparing the `Config` structure for spoofing
        let mut config = Config::default();

        // Get the base address of kernelbase.dll
        let kernelbase = GetModuleHandle(2737729883u32, Some(murmur3));

        // Parse the IMAGE_RUNTIME_FUNCTION table into usable Rust slices.
        let pe_kernelbase = PE::parse(kernelbase);
        let tables = pe_kernelbase.unwind().entries().context(s!(
            "Failed to read IMAGE_RUNTIME_FUNCTION entries from .pdata section"
        ))?;

        // Preparing addresses to use as artificial frames to emulate thread stack initialization
        let ntdll = GetModuleHandle(2788516083u32, Some(murmur3));
        if ntdll.is_null() {
            bail!(s!("ntdll.dll not found"));
        }

        let kernel32 = GetModuleHandle(2808682670u32, Some(murmur3));
        let rlt_user_addr = GetProcAddress(ntdll, 3761471966u32, Some(jenkins3));
        let base_thread_addr = GetProcAddress(kernel32, 4073232152u32, Some(jenkins3));
        config.rtl_user_addr = rlt_user_addr;
        config.base_thread_addr = base_thread_addr;

        // Recovering the IMAGE_RUNTIME_FUNCTION structure of target apis
        let pe_ntdll = PE::parse(ntdll);
        let rtl_user_runtime = pe_ntdll
            .unwind()
            .function_by_offset(rlt_user_addr as u32 - ntdll as u32)
            .context(s!("RtlUserThreadStart unwind info not found"))?;

        let pe_kernel32 = PE::parse(kernel32);
        let base_thread_runtime = pe_kernel32
            .unwind()
            .function_by_offset(base_thread_addr as u32 - kernel32 as u32)
            .context(s!("BaseThreadInitThunk unwind info not found"))?;

        // Recovering the stack size of target apis
        let rtl_user_size = StackFrame::ignoring_set_fpreg(ntdll, rtl_user_runtime).context(s!("RtlUserThreadStart stack size not found"))?;
        let base_thread_size = StackFrame::ignoring_set_fpreg(kernel32, base_thread_runtime).context(s!("BaseThreadInitThunk stack size not found"))?;

        config.rtl_user_thread_size = rtl_user_size as u64;
        config.base_thread_size = base_thread_size as u64;

        // First frame: a normal function with a clean prologue
        let first_prolog = Self::find_prolog(kernelbase, tables).context(s!("First prolog not found"))?;
        config.first_frame_fp = (first_prolog.frame + first_prolog.offset as u64) as *const c_void;
        config.first_frame_size = first_prolog.stack_size as u64;

        // Second frame: looks specifically for a prologue with `push rbp`.
        let second_prolog = Self::find_push_rbp(kernelbase, tables).context(s!("Second prolog not found"))?;
        config.second_frame_fp = (second_prolog.frame + second_prolog.offset as u64) as *const c_void;
        config.second_frame_size = second_prolog.stack_size as u64;
        config.rbp_stack_offset = second_prolog.rbp_offset as u64;

        // Find a gadget `add rsp, 0x58; ret`.
        let (add_rsp_addr, size) = Self::find_gadget(kernelbase, b!(&[0x48, 0x83, 0xC4, 0x58, 0xC3]), tables)
            .context(s!("Add RSP gadget not found"))?;
        config.add_rsp_gadget = add_rsp_addr as *const c_void;
        config.add_rsp_frame_size = size as u64;

        // Find a gadget that performs `jmp rbx` - to restore the original call.
        let (jmp_rbx_addr, size) = Self::find_gadget(kernelbase, b!(&[0xFF, 0x23]), tables)
            .context(s!("JMP RBX gadget not found"))?;
        config.jmp_rbx_gadget = jmp_rbx_addr as *const c_void;
        config.jmp_rbx_frame_size = size as u64;

        // Preparing arguments
        let len = args.len().min(11);
        config.number_args = len as u32;
        for (i, &arg) in args.iter().take(len).enumerate() {
            match i {
                0 => config.arg01 = arg,
                1 => config.arg02 = arg,
                2 => config.arg03 = arg,
                3 => config.arg04 = arg,
                4 => config.arg05 = arg,
                5 => config.arg06 = arg,
                6 => config.arg07 = arg,
                7 => config.arg08 = arg,
                8 => config.arg09 = arg,
                9 => config.arg10 = arg,
                10 => config.arg11 = arg,
                _ => break,
            }
        }

        // Spoof kind handling
        match kind {
            // Executes a function that is not syscall
            SpoofKind::Function => {
                config.spoof_function = addr;
            }

            // Executes a syscall indirectly
            SpoofKind::Syscall(name) => {
                // Retrieves the address of the function
                let addr = GetProcAddress(ntdll, name, None);
                if addr.is_null() {
                    bail!(s!("GetProcAddress returned null"));
                }

                // Configures the parameters to be sent to execute the syscall indirectly
                config.is_syscall = true as u32;
                config.ssn = dinvk::ssn(name, ntdll).context(s!("SSN not found"))?;
                config.spoof_function = dinvk::get_syscall_address(addr)
                    .context(s!("Syscall address not found"))? as *const c_void;
            }
        }

        // Call the external spoofing routine with the full config.
        Ok(unsafe { SpoofSynthetic(&mut config) })
    }

    /// Searches for a specific instruction pattern inside a function’s code region,
    /// returning the relative offset from the function's start if found.
    ///
    /// # Arguments
    ///
    /// * `module` - Base address of the module containing the target function.
    /// * `runtime` - A reference to the IMAGE_RUNTIME_FUNCTION describing the function.
    ///
    /// # Returns
    ///
    /// * `Some(offset)` — The relative offset inside the function where the gadget was found.
    /// * `None` — If the gadget pattern wasn't found.
    ///
    /// # Notes
    ///
    /// The pattern being searched is a `call qword ptr [rip+0]`, encoded as `48 FF 15 00 00 00 00`,
    /// and the function returns the offset *after* the full instruction (+7).
    fn find_valid_instruction_offset(module: *mut c_void, runtime: &IMAGE_RUNTIME_FUNCTION) -> Option<u32> {
        let start = module as u64 + runtime.BeginAddress as u64;
        let end = module as u64 + runtime.EndAddress as u64;
        let size = end - start;

        // Find a gadget `call qword ptr [rip+0]`
        let pattern = b!(&[0x48, 0xFF, 0x15]);
        unsafe {
            let bytes = from_raw_parts(start as *const u8, size as usize);
            if let Some(pos) = memchr::memmem::find(bytes, pattern) {
                // Returns valid RVA: offset of the gadget inside the function
                return Some((pos + 7) as u32);
            }
        }

        None
    }

    /// Scans the memory of a module for a specific byte pattern, constrained to
    /// valid runtime functions with corresponding unwind info.
    ///
    /// # Arguments
    ///
    /// * `module` — Base address of the loaded module to scan (e.g., `kernelbase.dll`).
    /// * `pattern` — Byte sequence representing the target gadget (e.g., `[0xFF, 0x23]` for `jmp rbx`).
    /// * `runtime_table` — Slice of `IMAGE_RUNTIME_FUNCTION` entries describing the module's valid code ranges.
    ///
    /// # Returns
    ///
    /// * `Some((address, frame_size))` — Pointer to the start of the matching gadget and the associated stack frame size.
    /// * `None` — If the gadget was not found.
    pub fn find_gadget(module: *mut c_void, pattern: &[u8], runtime_table: &[IMAGE_RUNTIME_FUNCTION]) -> Option<(*mut u8, u32)> {
        unsafe {
            let mut gadgets = Vec::new();
            for runtime in runtime_table.iter() {
                let start = module as u64 + runtime.BeginAddress as u64;
                let end = module as u64 + runtime.EndAddress as u64;
                let size = end - start;

                let bytes = from_raw_parts(start as *const u8, size as usize);
                if let Some(pos) = memchr::memmem::find(bytes, pattern) {
                    let addr = (start as *mut u8).add(pos);
                    if let Some(size) = StackFrame::ignoring_set_fpreg(module, runtime) {
                        if size != 0 {
                            gadgets.push((addr, size))
                        }
                    }
                }
            }

            // No gadget found? return None
            if gadgets.is_empty() {
                return None;
            }

            // Randomizes the order of possible frames found (if there is more than one),
            // helps to shuffle patterns and reduce repetition-based heuristics
            shuffle(&mut gadgets);

            // Take the first occurrence
            gadgets.first().copied()
        }
    }

    /// Scans the current thread's stack to locate the return address that falls within
    /// the range of the `BaseThreadInitThunk` function from `kernel32.dll`.
    ///
    /// # Returns
    ///
    /// * `Some(usize)` — The stack address (`RSP`) where a return to `BaseThreadInitThunk` was found.
    /// * `None` — If `kernel32.dll` or the target function could not be located, or
    ///     if no such return address is found on the stack.
    fn find_base_thread_return_address() -> Option<usize> {
        unsafe {
            // Get handle for kernel32.dll
            let kernel32 = GetModuleHandle(2808682670u32, Some(murmur3));
            if kernel32.is_null() {
                return None;
            }

            // Resolves the address of the BaseThreadInitThunk function
            let base_thread = GetProcAddress(kernel32, 4073232152u32, Some(jenkins3));
            if base_thread.is_null() {
                return None;
            }

            // Calculate the size of the BaseThreadInitThunk function
            let pe_kernel32 = PE::parse(kernel32);
            let size = pe_kernel32.unwind().function_size(base_thread)? as usize;

            // Access the TEB and stack limits
            let teb = NtCurrentTeb();
            let stack_base = (*teb).Reserved1[1] as usize;
            let stack_limit = (*teb).Reserved1[2] as usize;

            // Stack scanning begins
            let base_addr = base_thread as usize;
            let mut rsp = stack_base - 8;
            while rsp >= stack_limit {
                let val = (rsp as *const usize).read();

                // Checks if the return is in the BaseThreadInitThunk range
                if val >= base_addr && val < base_addr + size {
                    return Some(rsp);
                }

                rsp -= 8;
            }

            None
        }
    }

    /// Scans the `RUNTIME_FUNCTION` table to locate the first function with a prologue
    /// considered safe and predictable for call stack spoofing.
    ///
    /// # Arguments
    ///
    /// * `module_base` - Base address of the module being analyzed.
    /// * `runtime_table` - Slice containing the exception directory entries (`IMAGE_RUNTIME_FUNCTION`).
    ///
    /// # Returns
    ///
    /// * `Some(Prolog)` — If a suitable prologue is found, returns its metadata as a `Prolog` struct.
    /// * `None` — If no valid unwindable prologue with a valid instruction offset is located.
    fn find_prolog(module_base: *mut c_void, runtime_table: &[IMAGE_RUNTIME_FUNCTION]) -> Option<Prolog> {
        let mut prologs = Vec::new();
        for runtime in runtime_table.iter() {
            if let Some((true, stack_size)) = StackFrame::stack_frame(module_base, runtime) {
                if let Some(offset) = Self::find_valid_instruction_offset(module_base, runtime) {
                    let frame = module_base as u64 + runtime.BeginAddress as u64;
                    let prolog = Prolog {
                        frame,
                        stack_size,
                        offset,
                        rbp_offset: 0,
                    };

                    prologs.push(prolog);
                }
            }
        }

        // No prologue found? return None
        if prologs.is_empty() {
            return None;
        }

        // Randomizes the order of possible frames found (if there is more than one),
        // helps to shuffle patterns and reduce repetition-based heuristics
        shuffle(&mut prologs);

        // Take the first occurrence
        prologs.first().copied()
    }

    /// Searches for the first function in the exception directory that contains a classic
    /// `push rbp` prologue, which is typically associated with frame pointer-based stack frames.
    ///
    /// # Arguments
    ///
    /// * `module_base` - Base address of the loaded module.
    /// * `runtime_table` - Slice of entries from the exception directory (`IMAGE_RUNTIME_FUNCTION`).
    ///
    /// # Returns
    ///
    /// * `Some(Prolog)` — If a valid function is found with `push rbp` and a proper unwindable frame.
    /// * `None` — If no appropriate frame pointer-based function is located.
    fn find_push_rbp(module_base: *mut c_void, runtime_table: &[IMAGE_RUNTIME_FUNCTION]) -> Option<Prolog> {
        let mut prologs = Vec::new();
        for runtime in runtime_table.iter() {
            if let Some((rbp_offset, stack_size)) = StackFrame::rbp_offset(module_base, runtime) {
                if rbp_offset != 0 && stack_size != 0 && stack_size > rbp_offset {
                    if let Some(offset) = Self::find_valid_instruction_offset(module_base, runtime) {
                        let frame = module_base as u64 + runtime.BeginAddress as u64;
                        let prolog = Prolog {
                            frame,
                            stack_size,
                            offset,
                            rbp_offset,
                        };

                        prologs.push(prolog);
                    }
                }
            }
        }

        // No prologue found? return None
        if prologs.is_empty() {
            return None;
        }

        // The first pop rbp frame is not suitable on most windows versions
        prologs.remove(0);

        // Randomizes the order of possible frames found (if there is more than one),
        // helps to shuffle patterns and reduce repetition-based heuristics
        shuffle(&mut prologs);

        // Take the first occurrence
        prologs.first().copied()
    }
}

/// Internal module responsible for executing call stack spoofing flows used by macros.
pub mod internal {
    use core::{ffi::c_void, ptr::null_mut};
    use super::*;

    /// Launches a spoofed execution using either desynchronized or synthetic stack spoofing.
    ///
    /// # Arguments
    ///
    /// * `addr` - Target function pointer. For syscalls, this should be `null_mut()`.
    /// * `kind` - The spoofing mode: [`Function`](SpoofKind::Function) or [`Syscall`](SpoofKind::Syscall).
    /// * `args` - A fixed list of up to 11 arguments, cast to raw pointers.
    /// * `synthetic` - If `true`, a fully synthetic (simulated) call stack is used.
    ///     If `false`, spoofing reuses the real thread's stack.
    ///
    /// # Returns
    ///
    /// * `Ok(*mut c_void)` — On success, returns the result of the spoofed call.
    /// * `Err(anyhow::Error)` — If the spoofing setup fails or the target is invalid.
    #[inline(always)]
    pub fn uwd_entry(
        addr: *mut c_void, 
        kind: SpoofKind<'_>, 
        args: &[*const c_void], 
        synthetic: bool
    ) -> Result<*mut c_void> {
        match kind {
            SpoofKind::Function => {
                if synthetic {
                    Uwd::spoof_synthetic(addr, args, SpoofKind::Function)
                } else {
                    Uwd::spoof(addr, args, SpoofKind::Function)
                }
            }
            SpoofKind::Syscall(name) => {
                if synthetic {
                    Uwd::spoof_synthetic(null_mut(), args, SpoofKind::Syscall(name))
                } else {
                    Uwd::spoof(null_mut(), args, SpoofKind::Syscall(name))
                }
            }
        }
    }
}

/// Represents a utility struct for stack frame analysis and spoofing logic.
pub struct StackFrame;

impl StackFrame {
    /// Checks if the `RBP` register is pushed or saved on the stack in a spoofable manner.
    ///
    /// # Arguments
    ///
    /// * `module` - Base address of the loaded module.
    /// * `runtime` - A reference to the function's `IMAGE_RUNTIME_FUNCTION`.
    ///
    /// # Returns
    ///
    /// * `Some((rbp_offset, total_stack))` — If `RBP` is pushed or saved safely.  
    ///     - `rbp_offset` — Offset (in bytes) from `RSP` where `RBP` is stored.  
    ///     - `total_stack` — Total stack size allocated by the function.
    /// * `None` — If `RBP` is not safely saved or `RSP` is manipulated directly.
    pub fn rbp_offset(module: *mut c_void, runtime: &IMAGE_RUNTIME_FUNCTION) -> Option<(u32, u32)> {
        unsafe {
            let unwind_info = (module as usize + runtime.UnwindData as usize) as *mut UNWIND_INFO;
            let unwind_code = (unwind_info as *mut u8).add(4) as *mut UNWIND_CODE;
            let flag = (*unwind_info).VersionFlags.Flags();

            let mut i = 0usize;
            let mut total_stack = 0u32;
            let mut rbp_pushed = false;
            let mut stack_offset = 0;

            while i < (*unwind_info).CountOfCodes as usize {
                // Accessing `UNWIND_CODE` based on the index
                let unwind_code = unwind_code.add(i);

                // Information used in operation codes
                let op_info = (*unwind_code).Anonymous.OpInfo() as usize;
                let unwind_op = (*unwind_code).Anonymous.UnwindOp();

                match UNWIND_OP_CODES::try_from(unwind_op) {
                    // Saves a non-volatile register on the stack.
                    //
                    // Example: push <reg>
                    Ok(UWOP_PUSH_NONVOL) => {
                        if Registers::Rsp == op_info {
                            return None;
                        }

                        if Registers::Rbp == op_info {
                            if rbp_pushed {
                                return None;
                            }

                            rbp_pushed = true;
                            stack_offset = total_stack;
                        }

                        total_stack += 8;
                        i += 1;
                    }

                    // Allocates large space on the stack.
                    // - OpInfo == 0: The next slot contains the /8 size of the allocation (maximum 512 KB - 8).
                    // - OpInfo == 1: The next two slots contain the full size of the allocation (up to 4 GB - 8).
                    //
                    // Example (OpInfo == 0): sub rsp, 0x100 ; Allocates 256 bytes
                    // Example (OpInfo == 1): sub rsp, 0x10000 ; Allocates 65536 bytes (two slots used)
                    Ok(UWOP_ALLOC_LARGE) => {
                        if (*unwind_code).Anonymous.OpInfo() == 0 {
                            // Case 1: OpInfo == 0 (Size in 1 slot, divided by 8)
                            // Multiplies by 8 to the actual value

                            let frame_offset = ((*unwind_code.add(1)).FrameOffset) * 8;
                            total_stack += frame_offset as u32;

                            // Consumes 2 slots (1 for the instruction, 1 for the size divided by 8)
                            i += 2
                        } else {
                            // Case 2: OpInfo == 1 (Size in 2 slots, 32 bits)
                            let frame_offset = *(unwind_code.add(1) as *mut u32);
                            total_stack += frame_offset;

                            // Consumes 3 slots (1 for the instruction, 2 for the full size)
                            i += 3
                        }
                    }

                    // Allocates small space in the stack.
                    //
                    // Example (OpInfo = 3): sub rsp, 0x20  ; Aloca 32 bytes (OpInfo + 1) * 8
                    Ok(UWOP_ALLOC_SMALL) => {
                        total_stack += ((op_info + 1) * 8) as u32;
                        i += 1;
                    }

                    // UWOP_SAVE_NONVOL: Saves the contents of a non-volatile register in a specific position on the stack.
                    // - Reg: Name of the saved register.
                    // - FrameOffset: Offset indicating where the value of the register is saved.
                    //
                    // Example: mov [rsp + 0x40], rsi ; Saves the contents of RSI in RSP + 0x40
                    Ok(UWOP_SAVE_NONVOL) => {
                        if Registers::Rsp == op_info {
                            return None;
                        }

                        if Registers::Rbp == op_info {
                            if rbp_pushed {
                                return None;
                            }

                            let offset = (*unwind_code.add(1)).FrameOffset * 8;
                            stack_offset = total_stack + offset as u32;
                            rbp_pushed = true;
                        }

                        i += 2;
                    }

                    // Saves a non-volatile register to a stack address with a long offset.
                    // - Reg: Name of the saved register.
                    // - FrameOffset: Long offset indicating where the value of the register is saved.
                    //
                    // Example: mov [rsp + 0x1040], rsi ; Saves the contents of RSI in RSP + 0x1040.
                    Ok(UWOP_SAVE_NONVOL_BIG) => {
                        if Registers::Rsp == op_info {
                            return None;
                        }

                        if Registers::Rbp == op_info {
                            if rbp_pushed {
                                return None;
                            }

                            let offset = *(unwind_code.add(1) as *mut u32);
                            stack_offset = total_stack + offset;
                            rbp_pushed = true;
                        }

                        i += 3;
                    }

                    // Return
                    Ok(UWOP_SET_FPREG) => return None,

                    // - Reg: Name of the saved XMM register.
                    // - FrameOffset: Offset indicating where the value of the register is saved.
                    Ok(UWOP_SAVE_XMM128) => i += 2,

                    // UWOP_SAVE_XMM128BIG: Saves the contents of a non-volatile XMM register to a stack address with a long offset.
                    // - Reg: Name of the saved XMM register.
                    // - FrameOffset: Long offset indicating where the value of the register is saved.
                    //
                    // Example: movaps [rsp + 0x1040], xmm6 ; Saves the contents of XMM6 in RSP + 0x1040.
                    Ok(UWOP_SAVE_XMM128BIG) => i += 3,

                    // Reserved code, not currently used.
                    Ok(UWOP_EPILOG) | Ok(UWOP_SPARE_CODE) => i += 1,

                    // Push a machine frame. This unwind code is used to record the effect of a hardware interrupt or exception.
                    Ok(UWOP_PUSH_MACH_FRAME) => {
                        total_stack += if op_info == 0 { 0x40 } else { 0x48 };
                        i += 1
                    }

                    _ => {}
                }
            }

            // If there is a chain unwind structure, it too must be processed
            // recursively and included in the stack size calculation.
            if (flag & UNW_FLAG_CHAININFO) != 0 {
                let count = (*unwind_info).CountOfCodes as usize;
                let index = if count & 1 == 1 { count + 1 } else { count };
                let runtime = unwind_code.add(index) as *const IMAGE_RUNTIME_FUNCTION;
                if let Some((_, child_total)) = Self::rbp_offset(module, &*runtime) {
                    total_stack += child_total;
                } else {
                    return None;
                }
            }

            Some((stack_offset, total_stack))
        }
    }

    /// Calculates the stack size of a function and checks if it uses `RBP` as frame pointer.
    ///
    /// # Arguments
    ///
    /// * `module` - Base address of the loaded module.
    /// * `runtime` - A reference to the function's `IMAGE_RUNTIME_FUNCTION`.
    ///
    /// # Returns
    ///
    /// * `Some((true, stack_size))` — If the frame is valid and uses `RBP` as frame pointer.  
    /// * `Some((false, stack_size))` — If the frame has `setfp` but not `rbp`.  
    /// * `None` — If the frame is unsafe for spoofing or uses invalid constructs.
    pub fn stack_frame(module: *mut c_void, runtime: &IMAGE_RUNTIME_FUNCTION) -> Option<(bool, u32)> {
        unsafe {
            let unwind_info = (module as usize + runtime.UnwindData as usize) as *mut UNWIND_INFO;
            let unwind_code = (unwind_info as *mut u8).add(4) as *mut UNWIND_CODE;
            let flag = (*unwind_info).VersionFlags.Flags();

            let mut i = 0usize;
            let mut set_fpreg_hit = false;
            let mut total_stack = 0i32;
            while i < (*unwind_info).CountOfCodes as usize {
                // Accessing `UNWIND_CODE` based on the index
                let unwind_code = unwind_code.add(i);

                // Information used in operation codes
                let op_info = (*unwind_code).Anonymous.OpInfo() as usize;
                let unwind_op = (*unwind_code).Anonymous.UnwindOp();

                match UNWIND_OP_CODES::try_from(unwind_op) {
                    // Saves a non-volatile register on the stack.
                    //
                    // Example: push <reg>
                    Ok(UWOP_PUSH_NONVOL) => {
                        if Registers::Rsp == op_info && !set_fpreg_hit {
                            return None;
                        }

                        total_stack += 8;
                        i += 1;
                    }

                    // Allocates small space in the stack.
                    //
                    // Example (OpInfo = 3): sub rsp, 0x20  ; Aloca 32 bytes (OpInfo + 1) * 8
                    Ok(UWOP_ALLOC_SMALL) => {
                        total_stack += ((op_info + 1) * 8) as i32;
                        i += 1;
                    }

                    // Allocates large space on the stack.
                    // - OpInfo == 0: The next slot contains the /8 size of the allocation (maximum 512 KB - 8).
                    // - OpInfo == 1: The next two slots contain the full size of the allocation (up to 4 GB - 8).
                    //
                    // Example (OpInfo == 0): sub rsp, 0x100 ; Allocates 256 bytes
                    // Example (OpInfo == 1): sub rsp, 0x10000 ; Allocates 65536 bytes (two slots used)
                    Ok(UWOP_ALLOC_LARGE) => {
                        if (*unwind_code).Anonymous.OpInfo() == 0 {
                            // Case 1: OpInfo == 0 (Size in 1 slot, divided by 8)
                            // Multiplies by 8 to the actual value

                            let frame_offset = ((*unwind_code.add(1)).FrameOffset) * 8;
                            total_stack += frame_offset as i32;

                            // Consumes 2 slots (1 for the instruction, 1 for the size divided by 8)
                            i += 2
                        } else {
                            // Case 2: OpInfo == 1 (Size in 2 slots, 32 bits)
                            let frame_offset = *(unwind_code.add(1) as *mut i32);
                            total_stack += frame_offset;

                            // Consumes 3 slots (1 for the instruction, 2 for the full size)
                            i += 3
                        }
                    }

                    // UWOP_SAVE_NONVOL: Saves the contents of a non-volatile register in a specific position on the stack.
                    // - Reg: Name of the saved register.
                    // - FrameOffset: Offset indicating where the value of the register is saved.
                    //
                    // Example: mov [rsp + 0x40], rsi ; Saves the contents of RSI in RSP + 0x40
                    Ok(UWOP_SAVE_NONVOL) => {
                        if Registers::Rsp == op_info || Registers::Rbp == op_info {
                            return None;
                        }

                        i += 2;
                    }

                    // Saves a non-volatile register to a stack address with a long offset.
                    // - Reg: Name of the saved register.
                    // - FrameOffset: Long offset indicating where the value of the register is saved.
                    //
                    // Example: mov [rsp + 0x1040], rsi ; Saves the contents of RSI in RSP + 0x1040.
                    Ok(UWOP_SAVE_NONVOL_BIG) => {
                        if Registers::Rsp == op_info || Registers::Rbp == op_info {
                            return None;
                        }

                        i += 3;
                    }

                    // Saves the contents of a non-volatile XMM register on the stack.
                    // - Reg: Name of the saved XMM register.
                    // - FrameOffset: Offset indicating where the value of the register is saved.
                    //
                    // Example: movaps [rsp + 0x20], xmm6 ; Saves the contents of XMM6 in RSP + 0x20.
                    Ok(UWOP_SAVE_XMM128) => i += 2,

                    // UWOP_SAVE_XMM128BIG: Saves the contents of a non-volatile XMM register to a stack address with a long offset.
                    // - Reg: Name of the saved XMM register.
                    // - FrameOffset: Long offset indicating where the value of the register is saved.
                    //
                    // Example: movaps [rsp + 0x1040], xmm6 ; Saves the contents of XMM6 in RSP + 0x1040.
                    Ok(UWOP_SAVE_XMM128BIG) => i += 3,

                    // UWOP_SET_FPREG: Marks use of register as stack base (e.g. RBP).
                    // Ignore if not RBP, has EH handler or chained unwind.
                    // Subtract `FrameOffset << 4` from the stack total.
                    Ok(UWOP_SET_FPREG) => {
                        if (flag & UNW_FLAG_EHANDLER) != 0 && (flag & UNW_FLAG_CHAININFO) != 0 {
                            return None;
                        }

                        if (*unwind_info).FrameInfo.FrameRegister() != Registers::Rbp as u8 {
                            return None;
                        }

                        set_fpreg_hit = true;
                        let offset = ((*unwind_info).FrameInfo.FrameOffset() as i32) << 4;
                        total_stack -= offset;
                        i += 1
                    }

                    // Reserved code, not currently used.
                    Ok(UWOP_EPILOG) | Ok(UWOP_SPARE_CODE) => i += 1,

                    // Push a machine frame. This unwind code is used to record the effect of a hardware interrupt or exception.
                    Ok(UWOP_PUSH_MACH_FRAME) => {
                        total_stack += if op_info == 0 { 0x40 } else { 0x48 };
                        i += 1
                    }
                    _ => {}
                }
            }

            // If there is a chain unwind structure, it too must be processed
            // recursively and included in the stack size calculation.
            if (flag & UNW_FLAG_CHAININFO) != 0 {
                let count = (*unwind_info).CountOfCodes as usize;
                let index = if count & 1 == 1 { count + 1 } else { count };
                let runtime = unwind_code.add(index) as *const IMAGE_RUNTIME_FUNCTION;
                if let Some((chained_fpreg_hit, chained_stack)) = Self::stack_frame(module, &*runtime) {
                    total_stack += chained_stack as i32;
                    set_fpreg_hit |= chained_fpreg_hit;
                } else {
                    return None;
                }
            }

            Some((set_fpreg_hit, total_stack as u32))
        }
    }

    /// Calculates the total stack frame size of a function, ignoring `setfp` frames.
    ///
    /// Rejects any function that uses `UWOP_SET_FPREG` or manipulates `RSP` directly.
    ///
    /// # Arguments
    ///
    /// * `module` - Base address of the loaded module.
    /// * `runtime` - A reference to the function's `IMAGE_RUNTIME_FUNCTION`.
    ///
    /// # Returns
    ///
    /// * Stack size in bytes if the frame is spoof-safe.
    /// * Returns `0` if the frame is unsafe or unspoofable.
    pub fn ignoring_set_fpreg(module: *mut c_void, runtime: &IMAGE_RUNTIME_FUNCTION) -> Option<u32> {
        unsafe {
            let unwind_info = (module as usize + runtime.UnwindData as usize) as *mut UNWIND_INFO;
            let unwind_code = (unwind_info as *mut u8).add(4) as *mut UNWIND_CODE;
            let flag = (*unwind_info).VersionFlags.Flags();

            let mut i = 0usize;
            let mut total_stack = 0u32;
            while i < (*unwind_info).CountOfCodes as usize {
                // Accessing `UNWIND_CODE` based on the index
                let unwind_code = unwind_code.add(i);

                // Information used in operation codes
                let op_info = (*unwind_code).Anonymous.OpInfo() as usize;
                let unwind_op = (*unwind_code).Anonymous.UnwindOp();

                match UNWIND_OP_CODES::try_from(unwind_op) {
                    // Saves a non-volatile register on the stack.
                    //
                    // Example: push <reg>
                    Ok(UWOP_PUSH_NONVOL) => {
                        if Registers::Rsp == op_info {
                            return None;
                        }

                        total_stack += 8;
                        i += 1;
                    }

                    // Allocates small space in the stack.
                    //
                    // Example (OpInfo = 3): sub rsp, 0x20  ; Aloca 32 bytes (OpInfo + 1) * 8
                    Ok(UWOP_ALLOC_SMALL) => {
                        total_stack += ((op_info + 1) * 8) as u32;
                        i += 1;
                    }

                    // Allocates large space on the stack.
                    // - OpInfo == 0: The next slot contains the /8 size of the allocation (maximum 512 KB - 8).
                    // - OpInfo == 1: The next two slots contain the full size of the allocation (up to 4 GB - 8).
                    //
                    // Example (OpInfo == 0): sub rsp, 0x100 ; Allocates 256 bytes
                    // Example (OpInfo == 1): sub rsp, 0x10000 ; Allocates 65536 bytes (two slots used)
                    Ok(UWOP_ALLOC_LARGE) => {
                        if (*unwind_code).Anonymous.OpInfo() == 0 {
                            // Case 1: OpInfo == 0 (Size in 1 slot, divided by 8)
                            // Multiplies by 8 to the actual value

                            let frame_offset = ((*unwind_code.add(1)).FrameOffset) * 8;
                            total_stack += frame_offset as u32;

                            // Consumes 2 slots (1 for the instruction, 1 for the size divided by 8)
                            i += 2
                        } else {
                            // Case 2: OpInfo == 1 (Size in 2 slots, 32 bits)
                            let frame_offset = *(unwind_code.add(1) as *mut u32);
                            total_stack += frame_offset;

                            // Consumes 3 slots (1 for the instruction, 2 for the full size)
                            i += 3
                        }
                    }

                    // UWOP_SAVE_NONVOL: Saves the contents of a non-volatile register in a specific position on the stack.
                    // - Reg: Name of the saved register.
                    // - FrameOffset: Offset indicating where the value of the register is saved.
                    //
                    // Example: mov [rsp + 0x40], rsi ; Saves the contents of RSI in RSP + 0x40
                    Ok(UWOP_SAVE_NONVOL) => {
                        if Registers::Rsp == op_info {
                            return None;
                        }

                        i += 2;
                    }

                    // Saves a non-volatile register to a stack address with a long offset.
                    // - Reg: Name of the saved register.
                    // - FrameOffset: Long offset indicating where the value of the register is saved.
                    //
                    // Example: mov [rsp + 0x1040], rsi ; Saves the contents of RSI in RSP + 0x1040.
                    Ok(UWOP_SAVE_NONVOL_BIG) => {
                        if Registers::Rsp == op_info {
                            return None;
                        }

                        i += 3;
                    }

                    // Saves the contents of a non-volatile XMM register on the stack.
                    // - Reg: Name of the saved XMM register.
                    // - FrameOffset: Offset indicating where the value of the register is saved.
                    //
                    // Example: movaps [rsp + 0x20], xmm6 ; Saves the contents of XMM6 in RSP + 0x20.
                    Ok(UWOP_SAVE_XMM128) => i += 2,

                    // UWOP_SAVE_XMM128BIG: Saves the contents of a non-volatile XMM register to a stack address with a long offset.
                    // - Reg: Name of the saved XMM register.
                    // - FrameOffset: Long offset indicating where the value of the register is saved.
                    //
                    // Example: movaps [rsp + 0x1040], xmm6 ; Saves the contents of XMM6 in RSP + 0x1040.
                    Ok(UWOP_SAVE_XMM128BIG) => i += 3,

                    // Ignoring
                    Ok(UWOP_SET_FPREG) => i += 1,

                    // Reserved code, not currently used.
                    Ok(UWOP_EPILOG) | Ok(UWOP_SPARE_CODE) => i += 1,

                    // Push a machine frame. This unwind code is used to record the effect of a hardware interrupt or exception.
                    Ok(UWOP_PUSH_MACH_FRAME) => {
                        total_stack += if op_info == 0 { 0x40 } else { 0x48 };
                        i += 1
                    }
                    _ => {}
                }
            }

            // If there is a chain unwind structure, it too must be processed
            // recursively and included in the stack size calculation.
            if (flag & UNW_FLAG_CHAININFO) != 0 {
                let count = (*unwind_info).CountOfCodes as usize;
                let index = if count & 1 == 1 { count + 1 } else { count };
                let runtime = unwind_code.add(index) as *const IMAGE_RUNTIME_FUNCTION;
                if let Some(chained_stack) = Self::ignoring_set_fpreg(module, &*runtime) {
                    total_stack += chained_stack;
                } else {
                    return None;
                }
            }

            Some(total_stack)
        }
    }
}

/// Trait that allows casting any type to a raw pointer (`*const c_void` or `*mut c_void`).
pub trait AsUwd {
    /// Casts an immutable reference to a `*const c_void`.
    fn as_uwd_const(&self) -> *const c_void;

    /// Casts a mutable reference to a `*mut c_void`.
    fn as_uwd_mut(&mut self) -> *mut c_void;
}

impl<T> AsUwd for T {
    #[inline(always)]
    fn as_uwd_const(&self) -> *const c_void {
        self as *const _ as *const c_void
    }

    #[inline(always)]
    fn as_uwd_mut(&mut self) -> *mut c_void {
        self as *mut _ as *mut c_void
    }
}

/// Specifies the type of spoof being performed
pub enum SpoofKind<'a> {
    /// Spoofs a call to a regular function pointer (e.g. a Windows API)
    Function,

    /// Spoofs a native system call using its name (e.g. `"NtAllocateVirtualMemory"`).
    Syscall(&'a str),
}
