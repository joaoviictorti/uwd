# uwd 🦀

![Rust](https://img.shields.io/badge/made%20with-Rust-red)
![crate](https://img.shields.io/crates/v/uwd.svg)
![docs](https://docs.rs/uwd/badge.svg)
[![build](https://github.com/joaoviictorti/uwd/actions/workflows/ci.yml/badge.svg)](https://github.com/joaoviictorti/uwd/actions/workflows/ci.yml)
![Forks](https://img.shields.io/github/forks/joaoviictorti/uwd)
![Stars](https://img.shields.io/github/stars/joaoviictorti/uwd)
![License](https://img.shields.io/github/license/joaoviictorti/uwd)

`uwd` is a Rust library for call stack spoofing on Windows, allowing you to execute arbitrary functions with a forged call stack that evades analysis, logging, or detection during stack unwinding.

Inspired by [SilentMoonwalk](https://github.com/klezVirus/SilentMoonwalk), this crate brings low-level spoofing capabilities into a clean, idiomatic Rust interface with full support for `#[no_std]`, `MSVC` and `GNU` toolchains, and automated gadget resolution.

## Features

- ✅ Call stack spoofing via `Synthetic` and `Desync`.
- ✅ Compatible with both `MSVC` and `GNU` toolchains (**x64**).
- ✅ Inline macros: `spoof!` / `syscall!`.
- ✅ Supports `#[no_std]` environments (with `alloc`).

To enable Desync mode, activate the `desync` feature in your project, the macros will automatically use Desync behavior when the feature is enabled.

## Getting started

Add `uwd` to your project by updating your `Cargo.toml`:
```bash
cargo add uwd
```

## Usage

`uwd` allows you to spoof the call stack in Rust when calling either standard Windows APIs or performing indirect syscalls. The library handles the full setup of fake frames, gadget chains, and register preparation to make execution appear as if it came from a legitimate source.

You can spoof:

* Normal functions (like `VirtualAlloc`, `WinExec`, etc.)
* Native syscalls with automatic SSN and stub resolution (like `NtAllocateVirtualMemory`)

### Spoofing WinExec

This example shows how to spawn `calc.exe` using a spoofed call stack. We call `WinExec` twice once using the Desync technique, and again using the Synthetic one.

```rust
use dinvk::{GetModuleHandle, GetProcAddress};
use uwd::spoof;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Resolves addresses of the WinAPI functions to be used
    let kernel32 = GetModuleHandle("kernel32.dll", None);
    let win_exec = GetProcAddress(kernel32, "WinExec", None);
    
    // Execute command with `WinExec`
    let cmd = c"calc.exe";
    let mut result = spoof!(win_exec, cmd.as_ptr(), 1)?;
    if result.is_null() {
        eprintln!("WinExec Failed");
        return Ok(());
    }

    Ok(())
}
```

### Spoofing an Indirect Syscall

This example performs a indirect system call to `NtAllocateVirtualMemory` with a spoofed call stack.

```rust
use std::{ffi::c_void, ptr::null_mut};
use dinvk::NT_SUCCESS;
use uwd::{syscall, AsPointer};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Running indirect syscall with Call Stack Spoofing
    let mut addr = null_mut::<c_void>();
    let mut size = (1 << 12) as usize;
    let mut status = syscall!("NtAllocateVirtualMemory", -1isize, addr.as_ptr_mut(), 0, size.as_ptr_mut(), 0x3000, 0x04)? as i32;
    if !NT_SUCCESS(status) {
        eprintln!("[-] NtAllocateVirtualMemory Failed With Status: {status:#X}");
        return Ok(())
    }

    println!("[+] Address allocated: {:?}", addr);

    Ok(())
}
```

## Additional Resources

For more examples, check the [examples](https://github.com/joaoviictorti/uwd/tree/main/examples) folder in the repository.

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

This project is licensed under the MIT License. See the [LICENSE](https://github.com/joaoviictorti/uwd/tree/main/LICENSE) file for details.
