
<div align="right">
  <details>
    <summary >🌐 Language</summary>
    <div>
      <div align="right">
        <p><a href="https://openaitx.github.io/view.html?user=joaoviictorti&project=uwd&lang=en">English</a></p>
        <p><a href="https://openaitx.github.io/view.html?user=joaoviictorti&project=uwd&lang=zh-CN">简体中文</a></p>
        <p><a href="https://openaitx.github.io/view.html?user=joaoviictorti&project=uwd&lang=zh-TW">繁體中文</a></p>
        <p><a href="https://openaitx.github.io/view.html?user=joaoviictorti&project=uwd&lang=ja">日本語</a></p>
        <p><a href="https://openaitx.github.io/view.html?user=joaoviictorti&project=uwd&lang=ko">한국어</a></p>
        <p><a href="https://openaitx.github.io/view.html?user=joaoviictorti&project=uwd&lang=hi">हिन्दी</a></p>
        <p><a href="https://openaitx.github.io/view.html?user=joaoviictorti&project=uwd&lang=th">ไทย</a></p>
        <p><a href="https://openaitx.github.io/view.html?user=joaoviictorti&project=uwd&lang=fr">Français</a></p>
        <p><a href="https://openaitx.github.io/view.html?user=joaoviictorti&project=uwd&lang=de">Deutsch</a></p>
        <p><a href="https://openaitx.github.io/view.html?user=joaoviictorti&project=uwd&lang=es">Español</a></p>
        <p><a href="https://openaitx.github.io/view.html?user=joaoviictorti&project=uwd&lang=it">Itapano</a></p>
        <p><a href="https://openaitx.github.io/view.html?user=joaoviictorti&project=uwd&lang=ru">Русский</a></p>
        <p><a href="https://openaitx.github.io/view.html?user=joaoviictorti&project=uwd&lang=pt">Português</a></p>
        <p><a href="https://openaitx.github.io/view.html?user=joaoviictorti&project=uwd&lang=nl">Nederlands</a></p>
        <p><a href="https://openaitx.github.io/view.html?user=joaoviictorti&project=uwd&lang=pl">Polski</a></p>
        <p><a href="https://openaitx.github.io/view.html?user=joaoviictorti&project=uwd&lang=ar">العربية</a></p>
        <p><a href="https://openaitx.github.io/view.html?user=joaoviictorti&project=uwd&lang=fa">فارسی</a></p>
        <p><a href="https://openaitx.github.io/view.html?user=joaoviictorti&project=uwd&lang=tr">Türkçe</a></p>
        <p><a href="https://openaitx.github.io/view.html?user=joaoviictorti&project=uwd&lang=vi">Tiếng Việt</a></p>
        <p><a href="https://openaitx.github.io/view.html?user=joaoviictorti&project=uwd&lang=id">Bahasa Indonesia</a></p>
      </div>
    </div>
  </details>
</div>

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
- ✅ Inline macros: `spoof!`, `spoof_synthetic!`, `syscall!`, `syscall_synthetic!`.
- ✅ Supports `#[no_std]` environments (with `alloc`).

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
use dinvk::NT_SUCCESS;
use uwd::{syscall, syscall_synthetic, AsUwd};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Running indirect syscall with Call Stack Spoofing (Desync)
    let mut addr = null_mut::<c_void>();
    let mut size = (1 << 12) as usize;
    let mut status = syscall!("NtAllocateVirtualMemory", -1isize, addr.as_uwd_mut(), 0, size.as_uwd_mut(), 0x3000, 0x04)? as i32;
    if !NT_SUCCESS(status) {
        eprintln!("NtAllocateVirtualMemory Failed With Status: {status:#X}");
        return Ok(())
    }

    println!("[+] Address allocated: {:?}", addr);

    // Running indirect syscall with Call Stack Spoofing (Synthetic)
    let mut addr = null_mut::<c_void>();
    let mut size = (1 << 12) as usize;
    status = syscall_synthetic!("NtAllocateVirtualMemory", -1isize, addr.as_uwd_mut(), 0, size.as_uwd_mut(), 0x3000, 0x04)? as i32;
    if !NT_SUCESS(status) {
        eprintln!("NtAllocateVirtualMemory Failed With Status [2]: {status:#X}");
        return Ok(())
    }

    println!("[+] Address allocated: {:?}", addr);

    Ok(())
}
```

## Additional Resources

For more examples, check the [examples](/examples) folder in the repository.

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
