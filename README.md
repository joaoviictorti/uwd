# uwd 🦀

![Rust](https://img.shields.io/badge/made%20with-Rust-red)
![crate](https://img.shields.io/crates/v/uwd.svg)
![docs](https://docs.rs/uwd/badge.svg)
![Forks](https://img.shields.io/github/forks/joaoviictorti/uwd)
![Stars](https://img.shields.io/github/stars/joaoviictorti/uwd)
![License](https://img.shields.io/github/license/joaoviictorti/uwd)

`uwd` (Unwind Desynchronizer) is a Rust library for call stack spoofing on Windows, allowing you to execute arbitrary functions with a forged call stack that evades analysis, logging, or detection during stack unwinding.

Inspired by [SilentMoonwalk](https://github.com/klezVirus/SilentMoonwalk), this crate brings low-level spoofing capabilities into a clean, idiomatic Rust interface with full support for `#[no_std]`, `MSVC` and `GNU` toolchains, and automated gadget resolution.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
    - [Spoofing WinExec](#spoofing-winexec)
    - [Spoofing an Indirect Syscall](#spoofing-an-indirect-syscall)
- [Additional Resources](#additional-resources)
- [Contributing to uwd](#contributing-to-uwd)
- [References](#references)
- [License](#license)

## Features

- ✅ Call stack spoofing via `Synthetic` (Simulating a fake stack from scratch) and `Desync` (Reusing the thread's real stack)
- ✅ Compatible with both `MSVC` and `GNU` toolchains (**x64**)
- ✅ Inline macros: `spoof!`, `spoof_synthetic!`, `syscall!`, `syscall_synthetic!`
- ✅ Supports `#[no_std]` environments (with `alloc`)

## Installation

Add `uwd` to your project by updating your `Cargo.toml`:
```bash
cargo add uwd
```

## Usage

`uwd` allows you to spoof the call stack in Rust when calling either standard Windows APIs or performing indirect syscalls. The library handles the full setup of fake frames, gadget chains, and register preparation to make execution appear as if it came from a legitimate source.

You can spoof:

* Normal functions (like `VirtualAlloc`, `WinExec`, etc.)
* Native syscalls with automatic SSN and stub resolution (like `NtAllocateVirtualMemory`)

The macros `spoof!` / `spoof_synthetic!` and `syscall!` / `syscall_synthetic!` abstract all the complexity.

### Spoofing WinExec

This example shows how to spawn `calc.exe` using a spoofed call stack. We call `WinExec` twice once using the Desync technique, and again using the Synthetic one.

```rs
use dinvk::{GetModuleHandle, GetProcAddress};
use uwd::{spoof, spoof_synthetic};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Resolves addresses of the WinAPI functions to be used
    let kernel32 = GetModuleHandle("kernel32.dll", None);
    let win_exec = GetProcAddress(kernel32, "WinExec", None);
    
    // Execute command with `WinExec`
    // Call Stack Spoofing (Desync)
    let cmd = c"calc.exe";
    let mut result = spoof!(win_exec, cmd.as_ptr(), 1)?;
    if result.is_null() {
        eprintln!("WinExec Failed");
        return Ok(());
    }

    // Call Stack Spoofing (Synthetic)
    result = spoof_synthetic!(win_exec, cmd.as_ptr(), 1)?;
    if result.is_null() {
        eprintln!("WinExec Failed [2]");
        return Ok(());
    }

    Ok(())
}
```

### Spoofing an Indirect Syscall

This example performs a indirect system call to `NtAllocateVirtualMemory` with a spoofed call stack.

```rs
use std::{ffi::c_void, ptr::null_mut};
use uwd::{syscall, syscall_synthetic, AsUwd};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Running indirect syscall with Call Stack Spoofing (Desync)
    let mut addr = null_mut::<c_void>();
    let mut size = (1 << 12) as usize;
    let mut status = syscall!("NtAllocateVirtualMemory", -1isize, addr.as_uwd_mut(), 0, size.as_uwd_mut(), 0x3000, 0x04)? as i32;
    if !(status >= 0) {
        eprintln!("NtAllocateVirtualMemory Failed With Status: {status:#X}");
        return Ok(())
    }

    println!("[+] Address allocated: {:?}", addr);

    // Running indirect syscall with Call Stack Spoofing (Synthetic)
    let mut addr = null_mut::<c_void>();
    let mut size = (1 << 12) as usize;
    status = syscall_synthetic!("NtAllocateVirtualMemory", -1isize, addr.as_uwd_mut(), 0, size.as_uwd_mut(), 0x3000, 0x04)? as i32;
    if !(status >= 0) {
        eprintln!("NtAllocateVirtualMemory Failed With Status [2]: {status:#X}");
        return Ok(())
    }

    println!("[+] Address allocated: {:?}", addr);

    Ok(())
}
```

## Additional Resources

For more examples, check the [examples](/examples) folder in the repository.

## Contributing to uwd

To contribute to **uwd**, follow these steps:

1. Fork this repository.
2. Create a branch: `git checkout -b <branch_name>`.
3. Make your changes and commit them: `git commit -m '<commit_message>'`.
4. Push your changes to your branch: `git push origin <branch_name>`.
5. Create a pull request.

Alternatively, consult the [GitHub documentation](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests) on how to create a pull request.

## References

I want to express my gratitude to these projects that inspired me to create `uwd` and contribute with some features:

- [SilentMoonwalk](https://github.com/klezVirus/SilentMoonwalk)

Special thanks to:

- [Kudaes](https://x.com/_Kudaes_)
- [Klez](https://x.com/KlezVirus)
- [Waldo-IRC](https://x.com/waldoirc)
- [Trickster0](https://x.com/trickster012)
- [namazso](https://x.com/namazso)

## License

This project is licensed under the MIT License. See the [LICENSE](/LICENSE) file for details.