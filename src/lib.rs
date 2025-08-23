//! # uwd 🦀
//!
//! A Rust library for **call stack spoofing** on Windows.
//!
//! Inspired by [SilentMoonwalk](https://github.com/klezVirus/SilentMoonwalk),
//! this crate brings low-level spoofing capabilities into an idiomatic Rust interface,
//! with support for:
//!
//! - ✅ Call stack spoofing via **Desync** and **Synthetic** techniques  
//! - ✅ Inline macros: [`spoof!`], [`spoof_synthetic!`], [`syscall!`], [`syscall_synthetic!`]  
//! - ✅ Works with both **MSVC** and **GNU** toolchains (x64)  
//! - ✅ `#[no_std]` support (with `alloc`)  
//!
//! ## Examples
//!
//! ### Spoofing `WinExec`
//!
//! ```no_run
//! use dinvk::{GetModuleHandle, GetProcAddress};
//! use uwd::{spoof, spoof_synthetic};
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let kernel32 = GetModuleHandle("kernel32.dll", None);
//!     let win_exec = GetProcAddress(kernel32, "WinExec", None);
//!
//!     let cmd = c"calc.exe";
//!
//!     // Call Stack Spoofing (Desync)
//!     spoof!(win_exec, cmd.as_ptr(), 1)?;
//!
//!     // Call Stack Spoofing (Synthetic)
//!     spoof_synthetic!(win_exec, cmd.as_ptr(), 1)?;
//!
//!     Ok(())
//! }
//! ```
//!
//! ### Spoofing an Indirect Syscall (`NtAllocateVirtualMemory`)
//!
//! ```no_run
//! use std::{ffi::c_void, ptr::null_mut};
//! use dinvk::NT_SUCCESS;
//! use uwd::{syscall, syscall_synthetic, AsUwd};
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Desync technique
//!     let mut addr = null_mut::<c_void>();
//!     let mut size = (1 << 12) as usize;
//!     let mut status = syscall!(
//!         "NtAllocateVirtualMemory",
//!         -1isize,
//!         addr.as_uwd_mut(),
//!         0,
//!         size.as_uwd_mut(),
//!         0x3000,
//!         0x04
//!     )? as i32;
//!
//!     if !NT_SUCCESS(status) {
//!         eprintln!("NtAllocateVirtualMemory failed: {status:#X}");
//!         return Ok(());
//!     }
//!
//!     println!("[+] Address allocated: {:?}", addr);
//!
//!     // Synthetic technique
//!     let mut addr = null_mut::<c_void>();
//!     let mut size = (1 << 12) as usize;
//!     status = syscall_synthetic!(
//!         "NtAllocateVirtualMemory",
//!         -1isize,
//!         addr.as_uwd_mut(),
//!         0,
//!         size.as_uwd_mut(),
//!         0x3000,
//!         0x04
//!     )? as i32;
//!
//!     if !NT_SUCCESS(status) {
//!         eprintln!("NtAllocateVirtualMemory failed [2]: {status:#X}");
//!         return Ok(());
//!     }
//!
//!     println!("[+] Address allocated: {:?}", addr);
//!
//!     Ok(())
//! }
//! ```
//! 
//! # More Information
//!
//! For updates, usage guides, and examples, visit the [repository].
//!
//! [repository]: https://github.com/joaoviictorti/uwd

#![no_std]
#![allow(
    clippy::doc_overindented_list_items,
    clippy::collapsible_if
)]

extern crate alloc;

mod data;
mod uwd;

pub use uwd::*;
