use std::{ffi::c_void, ptr::null_mut};
use uwd::{AsUwd, syscall, syscall_synthetic};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Running indirect syscall with Call Stack Spoofing (Desync)
    let mut addr = null_mut::<c_void>();
    let mut size = (1 << 12) as usize;
    let mut status = syscall!("NtAllocateVirtualMemory", -1isize, addr.as_uwd_mut(), 0, size.as_uwd_mut(), 0x3000, 0x04)? as i32;
    if status < 0 {
        eprintln!("NtAllocateVirtualMemory Failed With Status: {status:#X}");
        return Ok(());
    }

    println!("[+] Address allocated (Desync): {:?}", addr);

    // Running indirect syscall with Call Stack Spoofing (Synthetic)
    let mut addr = null_mut::<c_void>();
    let mut size = (1 << 12) as usize;
    status = syscall_synthetic!("NtAllocateVirtualMemory", -1isize, addr.as_uwd_mut(), 0, size.as_uwd_mut(), 0x3000, 0x04)? as i32;
    if status < 0 {
        eprintln!("NtAllocateVirtualMemory Failed With Status [2]: {status:#X}");
        return Ok(());
    }

    println!("[+] Address allocated (Synthetic): {:?}", addr);

    Ok(())
}
