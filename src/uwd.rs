use alloc::{string::String, vec::Vec};
use core::ffi::c_void;

use anyhow::{Context, Result, bail};
use obfstr::obfstring as s;
use dinvk::{
    GetModuleHandle, GetProcAddress,
    data::IMAGE_RUNTIME_FUNCTION,
    hash::murmur3,
    pe::PE
};

use super::util::*;
use super::data::{
    Config, Registers,
    UNWIND_OP_CODES::{self, *},
};
use super::data::{
    UNW_FLAG_CHAININFO,
    UNW_FLAG_EHANDLER,
    UNWIND_CODE,
    UNWIND_INFO,
};

#[cfg(feature = "desync")]
unsafe extern "C" {
    /// Function responsible for Call Stack Spoofing (Desync)
    fn Spoof(config: &mut Config) -> *mut c_void;
}

#[cfg(not(feature = "desync"))]
unsafe extern "C" {
    /// Function responsible for Call Stack Spoofing (Synthetic)
    fn SpoofSynthetic(config: &mut Config) -> *mut c_void;
}

/// Invokes the function using a synthetic stack layout.
///
/// # Arguments
///
/// * `$addr` - A pointer to the function to spoof-call.
/// * `$arg` - A list of arguments to be passed to the spoofed function (up to 11 maximum).
#[macro_export]
macro_rules! spoof {
    ($addr:expr, $($arg:expr),+ $(,)?) => {
        unsafe {
            $crate::internal::uwd_entry(
                $addr,
                &[$(::core::mem::transmute($arg as usize)),*],
                $crate::SpoofKind::Function,
            )
        }
    };
}

/// Wraps a native Windows syscall with a simulated stack layout.
///
/// # Arguments
///
/// * `$name` - The name of the syscall as a string literal.
/// * `$arg` - A list of arguments to be passed to the spoofed function (up to 11 maximum)
#[macro_export]
macro_rules! syscall {
    ($name:expr, $($arg:expr),* $(,)?) => {
        unsafe {
            $crate::internal::uwd_entry(
                core::ptr::null_mut(),
                &[$(::core::mem::transmute($arg as usize)),*],
                $crate::SpoofKind::Syscall($name),
            )
        }
    };
}

/// Internal module responsible for executing call stack spoofing.
pub mod internal {
    use core::{ffi::c_void, ptr::null_mut};
    use super::*;

    /// Performs call stack spoofing in `synthetic` mode, simulating a fake stack from scratch.
    #[cfg(not(feature = "desync"))]
    fn spoof(addr: *mut c_void, args: &[*const c_void], kind: SpoofKind) -> Result<*mut c_void> {
        // Max 11 arguments allowed
        if args.len() > 11 {
            bail!(s!("too many arguments"));
        }

        // Prevent calling a null function unless it's a syscall
        if let SpoofKind::Function = kind && addr.is_null() {
            bail!(s!("null function address"));
        }

        // Preparing the `Config` structure for spoofing
        let mut config = Config::default();

        // Get the base address of kernelbase.dll
        let kernelbase = GetModuleHandle(2737729883u32, Some(murmur3));

        // Parse the IMAGE_RUNTIME_FUNCTION table into usable Rust slices
        let pe_kernelbase = PE::parse(kernelbase);
        let tables = pe_kernelbase.unwind().entries().context(s!(
            "failed to read IMAGE_RUNTIME_FUNCTION entries from .pdata section"
        ))?;

        // Preparing addresses to use as artificial frames to emulate thread stack initialization
        let ntdll = GetModuleHandle(2788516083u32, Some(murmur3));
        if ntdll.is_null() {
            bail!(s!("ntdll.dll not found"));
        }

        let kernel32 = GetModuleHandle(2808682670u32, Some(murmur3));
        let rlt_user_addr = GetProcAddress(ntdll, 1578834099u32, Some(murmur3));
        let base_thread_addr = GetProcAddress(kernel32, 4083630997u32, Some(murmur3));
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
        let rtl_user_size = ignoring_set_fpreg(ntdll, rtl_user_runtime)
            .context(s!("RtlUserThreadStart stack size not found"))?;
        
        let base_thread_size = ignoring_set_fpreg(kernel32, base_thread_runtime)
            .context(s!("BaseThreadInitThunk stack size not found"))?;

        config.rtl_user_thread_size = rtl_user_size as u64;
        config.base_thread_size = base_thread_size as u64;

        // First frame: a normal function with a clean prologue
        let first_prolog = Prolog::find_prolog(kernelbase, tables)
            .context(s!("first prolog not found"))?;
        
        config.first_frame_fp = (first_prolog.frame + first_prolog.offset as u64) as *const c_void;
        config.first_frame_size = first_prolog.stack_size as u64;

        // Second frame: looks specifically for a prologue with `push rbp`
        let second_prolog = Prolog::find_push_rbp(kernelbase, tables)
            .context(s!("second prolog not found"))?;
        
        config.second_frame_fp = (second_prolog.frame + second_prolog.offset as u64) as *const c_void;
        config.second_frame_size = second_prolog.stack_size as u64;
        config.rbp_stack_offset = second_prolog.rbp_offset as u64;

        // Find a gadget `add rsp, 0x58; ret`
        let (add_rsp_addr, size) = find_gadget(kernelbase, &[0x48, 0x83, 0xC4, 0x58, 0xC3], tables)
            .context(s!("add rsp gadget not found"))?;
        
        config.add_rsp_gadget = add_rsp_addr as *const c_void;
        config.add_rsp_frame_size = size as u64;

        // Find a gadget that performs `jmp rbx` - to restore the original call
        let (jmp_rbx_addr, size) = find_gadget(kernelbase, &[0xFF, 0x23], tables)
            .context(s!("jmp rbx gadget not found"))?;
        
        config.jmp_rbx_gadget = jmp_rbx_addr as *const c_void;
        config.jmp_rbx_frame_size = size as u64;

        // Preparing arguments
        let len = args.len();
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
                config.ssn = dinvk::ssn(name, ntdll).context(s!("ssn not found"))?;
                config.spoof_function = dinvk::get_syscall_address(addr)
                    .context(s!("syscall address not found"))? as *const c_void;
            }
        }

        // Call the external spoofing routine
        Ok(unsafe { SpoofSynthetic(&mut config) })
    }

    /// Performs call stack spoofing in `desync` mode, reusing the thread's real stack.
    #[cfg(feature = "desync")]
    fn spoof(addr: *mut c_void, args: &[*const c_void], kind: SpoofKind) -> Result<*mut c_void> {
        // Max 11 arguments allowed
        if args.len() > 11 {
            bail!(s!("too many arguments"));
        }

        // Prevent calling a null function unless it's a syscall
        if let SpoofKind::Function = kind && addr.is_null() {
            bail!(s!("null function address"));
        }

        // Preparing the `Config` structure for spoofing
        let mut config = Config::default();

        // Get the base address of kernelbase.dll
        let kernelbase = GetModuleHandle(2737729883u32, Some(murmur3));

        // Parse the IMAGE_RUNTIME_FUNCTION table into usable Rust slices
        let pe = PE::parse(kernelbase);
        let tables = pe.unwind().entries().context(s!(
            "failed to read IMAGE_RUNTIME_FUNCTION entries from .pdata section"
        ))?;

        // Locate a return address from BaseThreadInitThunk on the current stack
        config.return_address = find_base_thread_return_address()
            .context(s!("return address not found"))? as *const c_void;

        // First frame: a normal function with a clean prologue
        let first_prolog = Prolog::find_prolog(kernelbase, tables)
            .context(s!("first prolog not found"))?;
        
        config.first_frame_fp = (first_prolog.frame + first_prolog.offset as u64) as *const c_void;
        config.first_frame_size = first_prolog.stack_size as u64;

        // Second frame: looks specifically for a prologue with `push rbp`
        let second_prolog = Prolog::find_push_rbp(kernelbase, tables)
            .context(s!("second prolog not found"))?;
        
        config.second_frame_fp = (second_prolog.frame + second_prolog.offset as u64) as *const c_void;
        config.second_frame_size = second_prolog.stack_size as u64;
        config.rbp_stack_offset = second_prolog.rbp_offset as u64;

        // Find a gadget `add rsp, 0x58; ret`
        let (add_rsp_addr, size) = find_gadget(kernelbase, &[0x48, 0x83, 0xC4, 0x58, 0xC3], tables)
            .context(s!("add rsp gadget not found"))?;

        config.add_rsp_gadget = add_rsp_addr as *const c_void;
        config.add_rsp_frame_size = size as u64;

        // Find a gadget that performs `jmp rbx` - to restore the original call
        let (jmp_rbx_addr, size) = find_gadget(kernelbase, &[0xFF, 0x23], tables)
            .context(s!("jmp rbx gadget not found"))?;

        config.jmp_rbx_gadget = jmp_rbx_addr as *const c_void;
        config.jmp_rbx_frame_size = size as u64;

        // Preparing arguments
        let len = args.len();
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
                config.ssn = dinvk::ssn(name, ntdll).context(s!("ssn not found"))?;
                config.spoof_function = dinvk::get_syscall_address(addr)
                    .context(s!("syscall address not found"))? as *const c_void;
            }
        }

        // Call the external spoofing routine
        Ok(unsafe { Spoof(&mut config) })
    }

    /// Launches a spoofed execution using either desynchronized or synthetic stack spoofing.
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
    /// The raw return value of the spoofed call, or an error if spoofing fails.
    #[inline(always)]
    pub fn uwd_entry(
        addr: *mut c_void, 
        args: &[*const c_void],
        kind: SpoofKind<'_>,  
    ) -> Result<*mut c_void> {
        match kind {
            SpoofKind::Function => {
                spoof(addr, args, SpoofKind::Function)
            }
            SpoofKind::Syscall(name) => {
                spoof(null_mut(), args, SpoofKind::Syscall(name))
            }
        }
    }
}

/// Represents metadata extracted from a function's prologue used for call stack spoofing.
#[derive(Copy, Clone)]
struct Prolog {
    /// Address of the function's entry point or relevant instruction.
    frame: u64,

    /// Total stack space reserved by the function.
    stack_size: u32,

    /// Offset inside the function where a specific instruction pattern is found.
    offset: u32,

    /// Offset in the stack where `rbp` is pushed.
    rbp_offset: u32,
}

impl Prolog {
    /// Scans the `RUNTIME_FUNCTION` table to locate the first function with a prologue
    /// considered safe and predictable for call stack spoofing.
    ///
    /// # Arguments
    ///
    /// * `module_base` - Base address of the module being analyzed.
    /// * `runtime_table` - Slice containing the exception directory entries.
    ///
    /// # Returns
    ///
    /// Metadata of the first suitable prologue, or `None` if no suitable prologue is found.
    fn find_prolog(module_base: *mut c_void, runtime_table: &[IMAGE_RUNTIME_FUNCTION]) -> Option<Self> {
        let mut prologs = runtime_table
            .iter()
            .filter_map(|runtime| {
                let (is_valid, stack_size) = stack_frame(module_base, runtime)?;
                if !is_valid {
                    return None;
                }

                let offset = find_valid_instruction_offset(module_base, runtime)?;
                let frame = module_base as u64 + runtime.BeginAddress as u64;
                Some(Self {
                    frame,
                    stack_size,
                    offset,
                    rbp_offset: 0,
                })
            })
            .collect::<Vec<Self>>();

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
    /// * `runtime_table` - Slice of entries from the exception directory.
    ///
    /// # Returns
    ///
    /// The prologue metadata if a valid `push rbp` function is found, or `None` if no suitable match exists.
    fn find_push_rbp(module_base: *mut c_void, runtime_table: &[IMAGE_RUNTIME_FUNCTION]) -> Option<Self> {
        let mut prologs = runtime_table
            .iter()
            .filter_map(|runtime| {
                let (rbp_offset, stack_size) = rbp_offset(module_base, runtime)?;
                if rbp_offset == 0 || stack_size == 0 || stack_size <= rbp_offset {
                    return None;
                }

                let offset = find_valid_instruction_offset(module_base, runtime)?;
                let frame = module_base as u64 + runtime.BeginAddress as u64;
                Some(Self {
                    frame,
                    stack_size,
                    offset,
                    rbp_offset,
                })
            })
            .collect::<Vec<Self>>();

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

/// Checks if the `RBP` register is pushed or saved on the stack in a spoofable manner.
///
/// # Arguments
///
/// * `module` - Base address of the loaded module.
/// * `runtime` - A reference to the function's `IMAGE_RUNTIME_FUNCTION`.
///
/// # Returns
///
/// Tuple with the RBP offset and the total stack size.
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

                        let frame_offset = ((*unwind_code.add(1)).FrameOffset as i32) * 8;
                        total_stack += frame_offset as u32;

                        // Consumes 2 slots (1 for the instruction, 1 for the size divided by 8)
                        i += 2
                    } else {
                        // Case 2: OpInfo == 1 (Size in 2 slots, 32 bits)
                        let frame_offset = *(unwind_code.add(1) as *mut i32);
                        total_stack += frame_offset as u32;

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
            if let Some((_, child_total)) = rbp_offset(module, &*runtime) {
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
/// A flag indicating RBP usage and the total stack size.
pub fn stack_frame(module: *mut c_void, runtime: &IMAGE_RUNTIME_FUNCTION) -> Option<(bool, u32)> {
    unsafe {
        let unwind_info = (module as usize + runtime.UnwindData as usize) as *mut UNWIND_INFO;
        let unwind_code = (unwind_info as *mut u8).add(4) as *mut UNWIND_CODE;
        let flag = (*unwind_info).VersionFlags.Flags();

        let mut i = 0usize;
        let mut set_fpreg_hit = false;
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

                        let frame_offset = ((*unwind_code.add(1)).FrameOffset as i32) * 8;
                        total_stack += frame_offset as u32;

                        // Consumes 2 slots (1 for the instruction, 1 for the size divided by 8)
                        i += 2
                    } else {
                        // Case 2: OpInfo == 1 (Size in 2 slots, 32 bits)
                        let frame_offset = *(unwind_code.add(1) as *mut i32);
                        total_stack += frame_offset as u32;

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
                    total_stack -= offset as u32;
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
            if let Some((chained_fpreg_hit, chained_stack)) = stack_frame(module, &*runtime) {
                total_stack += chained_stack as u32;
                set_fpreg_hit |= chained_fpreg_hit;
            } else {
                return None;
            }
        }

        Some((set_fpreg_hit, total_stack))
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
/// Total stack size in bytes for a spoof‑safe frame.
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

                        let frame_offset = ((*unwind_code.add(1)).FrameOffset as i32) * 8;
                        total_stack += frame_offset as u32;

                        // Consumes 2 slots (1 for the instruction, 1 for the size divided by 8)
                        i += 2
                    } else {
                        // Case 2: OpInfo == 1 (Size in 2 slots, 32 bits)
                        let frame_offset = *(unwind_code.add(1) as *mut i32);
                        total_stack += frame_offset as u32;

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

                // Ignoring.
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
            if let Some(chained_stack) = ignoring_set_fpreg(module, &*runtime) {
                total_stack += chained_stack;
            } else {
                return None;
            }
        }

        Some(total_stack)
    }
}

/// Trait for casting references to raw `c_void` pointers.
pub trait AsPointer {
    /// Returns a raw immutable pointer to `self` as `*const c_void`.
    fn as_ptr_const(&self) -> *const c_void;

    /// Returns a raw mutable pointer to `self` as `*mut c_void`.
    fn as_ptr_mut(&mut self) -> *mut c_void;
}

impl<T> AsPointer for T {
    #[inline(always)]
    fn as_ptr_const(&self) -> *const c_void {
        self as *const _ as *const c_void
    }

    #[inline(always)]
    fn as_ptr_mut(&mut self) -> *mut c_void {
        self as *mut _ as *mut c_void
    }
}

/// Specifies the type of spoof being performed
pub enum SpoofKind<'a> {
    /// Spoofs a call to a regular function pointer.
    Function,

    /// Spoofs a native system call using its name.
    Syscall(&'a str),
}
