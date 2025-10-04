use std::{ffi::c_void, ptr::null_mut};
use uwd::{AsPointer, syscall};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Running indirect syscall with Call Stack Spoofing (Desync)
    let mut addr = null_mut::<c_void>();
    let mut size = (1 << 12) as usize;
    let status = syscall!("NtAllocateVirtualMemory", -1isize, addr.as_ptr_mut(), 0, size.as_ptr_mut(), 0x3000, 0x04)? as i32;
    if status < 0 {
        eprintln!("NtAllocateVirtualMemory Failed With Status: {status:#X}");
        return Ok(());
    }

    println!("[+] Address allocated: {:?}", addr);

    Ok(())
}
