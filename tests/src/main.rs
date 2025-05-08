use dinvk::{GetModuleHandle, GetProcAddress};
use uwd::spoof;

#[rustfmt::skip]
fn main() -> Result<(), Box<dyn core::error::Error>> {
    // Resolves addresses of the WinAPI functions to be used
    let kernel32 = GetModuleHandle("kernel32.dll", None);
    let win_exec = GetProcAddress(kernel32, "WinExec", None);
    
    // Execute command with `WinExec`
    let cmd = c"calc.exe";

    // 0:000> bp kernel32!WinExec "k ; g"
    for _ in 0..50 {
        spoof!(win_exec, cmd.as_ptr(), 1)?;
    }

    Ok(())
}
