use dinvk::module::{get_module_address, get_proc_address};
use uwd::spoof;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Resolves addresses of the WinAPI functions to be used
    let kernel32 = get_module_address("kernel32.dll", None);
    let win_exec = get_proc_address(kernel32, "WinExec", None);
    
    // Execute command with `WinExec`
    let cmd = c"calc.exe";
    let result = spoof!(win_exec, cmd.as_ptr(), 1)?;
    if result.is_null() {
        eprintln!("WinExec Failed");
        return Ok(());
    }

    Ok(())
}
