use std::{ffi::c_void, ptr::null_mut};
use uwd::{syscall, syscall_synthetic};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Running indirect syscall with Call Stack Spoofing (Desync)
    let mut addr = null_mut::<c_void>();
    let mut size = (1 << 12) as usize;
    syscall!("NtAllocateVirtualMemory", -1isize as *mut c_void, &mut addr as *mut _, 0, &mut size as *mut _, 0x3000, 0x04);
    println!("[+] Address: {:?}", addr);

    // Running indirect syscall with Call Stack Spoofing (Synthetic)
    let mut addr = null_mut::<c_void>();
    let mut size = (1 << 12) as usize;
    syscall_synthetic!("NtAllocateVirtualMemory", -1isize as *mut c_void, &mut addr as *mut _, 0, &mut size as *mut _, 0x3000, 0x04);
    println!("[+] Address: {:?}", addr);

    Ok(())
}

