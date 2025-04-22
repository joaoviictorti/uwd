use dinvk::{GetModuleHandle, GetProcAddress};
use uwd::spoof;

#[rustfmt::skip]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Resolves addresses of the WinAPI functions to be used
    let kernel32 = GetModuleHandle("kernel32.dll", None);
    let win_exec = GetProcAddress(kernel32, "WinExec", None);
    
    // Execute command with `WinExec`
    let cmd = c"calc.exe";

    // 0:000> x kernel32!WinExec
    // 0:000> bp <addr> "k ; g"
    for _ in 0..50 {
        spoof!(win_exec, cmd.as_ptr(), 1)
            .filter(|&ptr| !ptr.is_null())
            .ok_or("WinExec Failed")?;
    }

    Ok(())
}
