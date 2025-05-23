#[test]
fn test_win_exec() -> Result<(), Box<dyn core::error::Error>> {
    // Resolves addresses of the WinAPI functions to be used
    let kernel32 = dinvk::GetModuleHandle("kernel32.dll", None);
    let win_exec = dinvk::GetProcAddress(kernel32, "WinExec", None);
    
    // Execute command with `WinExec`
    let cmd = c"calc.exe";

    // 0:000> bp kernel32!WinExec "k ; g"
    for _ in 0..50 {
        uwd::spoof!(win_exec, cmd.as_ptr(), 1)?;
    }

    Ok(())
}

#[test]
fn test_win_exec_synthetic() -> Result<(), Box<dyn core::error::Error>> {
    // Resolves addresses of the WinAPI functions to be used
    let kernel32 = dinvk::GetModuleHandle("kernel32.dll", None);
    let win_exec = dinvk::GetProcAddress(kernel32, "WinExec", None);
    
    // Execute command with `WinExec`
    let cmd = c"calc.exe";

    // 0:000> bp kernel32!WinExec "k ; g"
    for _ in 0..50 {
        uwd::spoof_synthetic!(win_exec, cmd.as_ptr(), 1)?;
    }

    Ok(())
}
