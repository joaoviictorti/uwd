use dinvk::{GetModuleHandle, GetProcAddress};
use uwd::{spoof, spoof_synthetic};

#[rustfmt::skip]
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
