use core::{ffi::c_void, slice::from_raw_parts};
use alloc::vec::Vec;

use obfstr::obfbytes as b;
use dinvk::data::IMAGE_RUNTIME_FUNCTION;

use super::ignoring_set_fpreg;

/// Searches for a specific instruction pattern inside a function's code region,
/// returning the relative offset from the function's start if found.
///
/// # Arguments
///
/// * `module` - Base address of the module containing the target function.
/// * `runtime` - A reference to the IMAGE_RUNTIME_FUNCTION describing the function.
///
/// # Returns
///
/// The relative offset inside the function where the gadget was found.
///
/// # Notes
///
/// The pattern being searched is a `call qword ptr [rip+0]`, encoded as `48 FF 15 00 00 00 00`,
/// and the function returns the offset *after* the full instruction (+7).
pub fn find_valid_instruction_offset(module: *mut c_void, runtime: &IMAGE_RUNTIME_FUNCTION) -> Option<u32> {
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
/// * `module` - Base address of the loaded module to scan.
/// * `pattern` - Byte sequence representing the target gadget.
/// * `runtime_table` - Slice of `IMAGE_RUNTIME_FUNCTION` entries describing the module's valid code ranges.
///
/// # Returns
///
/// Pointer to the start of the matching gadget and the associated stack frame size.
pub fn find_gadget(
    module: *mut c_void, 
    pattern: &[u8], 
    runtime_table: &[IMAGE_RUNTIME_FUNCTION]
) -> Option<(*mut u8, u32)> {
    unsafe {
        let mut gadgets = runtime_table
            .iter()
            .filter_map(|runtime| {
                let start = module as u64 + runtime.BeginAddress as u64;
                let end = module as u64 + runtime.EndAddress as u64;
                let size = end.saturating_sub(start);

                // Read bytes from the function's code region
                let bytes = from_raw_parts(start as *const u8, size as usize);
                let pos = memchr::memmem::find(bytes, pattern)?;

                let addr = (start as *mut u8).wrapping_add(pos);
                let frame_size = ignoring_set_fpreg(module, runtime)?;
                if frame_size == 0 {
                    return None;
                }

                Some((addr, frame_size))
            })
            .collect::<Vec<(*mut u8, u32)>>();

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
/// The stack address (`RSP`) where a return to `BaseThreadInitThunk` was found.
#[cfg(feature = "desync")]
pub fn find_base_thread_return_address() -> Option<usize> {
    use dinvk::{GetModuleHandle, GetProcAddress};
    use dinvk::{hash::{jenkins3, murmur3}, pe::PE};

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
        let teb = dinvk::NtCurrentTeb();
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

/// Randomly shuffles the elements of a mutable slice in-place using a pseudo-random
/// number generator seeded by the CPU's timestamp counter (`rdtsc`).
///
/// The shuffling algorithm is a variant of the Fisher-Yates shuffle.
///
/// # Arguments
/// 
/// * `list` - A mutable slice of elements to be shuffled.
pub fn shuffle<T>(list: &mut [T]) {
    let mut seed = unsafe { core::arch::x86_64::_rdtsc() };
    for i in (1..list.len()).rev() {
        seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
        let j = seed as usize % (i + 1);
        list.swap(i, j);
    }
}
