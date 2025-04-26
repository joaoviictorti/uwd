use std::{ffi::c_void, ptr::null_mut};
use uwd::{syscall, syscall_synthetic, AsUwd};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Running indirect syscall with Call Stack Spoofing (Desync)
    let mut addr = null_mut::<c_void>();
    let mut size = (1 << 12) as usize;
    let mut status = syscall!("NtAllocateVirtualMemory", -1isize, addr.cast_mut(), 0, size.cast_mut(), 0x3000, 0x04)? as i32;
    if !(status >= 0) {
        eprintln!("NtAllocateVirtualMemory Failed With Status: {status:#X}");
        return Ok(())
    }

    println!("[+] Address allocated: {:?}", addr);

    // Running indirect syscall with Call Stack Spoofing (Synthetic)
    let mut addr = null_mut::<c_void>();
    let mut size = (1 << 12) as usize;
    status = syscall_synthetic!("NtAllocateVirtualMemory", -1isize, addr.cast_mut(), 0, size.cast_mut(), 0x3000, 0x04)? as i32;
    if !(status >= 0) {
        eprintln!("NtAllocateVirtualMemory Failed With Status [2]: {status:#X}");
        return Ok(())
    }

    println!("[+] Address allocated: {:?}", addr);

    Ok(())
}

