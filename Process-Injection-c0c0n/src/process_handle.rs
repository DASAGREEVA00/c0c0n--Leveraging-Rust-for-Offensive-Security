use std::io;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Threading::{OpenProcess, PROCESS_ALL_ACCESS};
use windows::core::Error;

fn main() {
    let mut pid = String::new();
    println!("Enter the PID of the target process:");
    io::stdin().read_line(&mut pid).expect("Unable to read line");

    let pid: u32 = match pid.trim().parse() {
        Ok(num) => num,
        Err(_) => {
            eprintln!("Invalid PID input");
            return;
        }
    };

    // Open the process using OpenProcess
    unsafe {
        match OpenProcess(PROCESS_ALL_ACCESS, false, pid) {
            Ok(process_handle) => {
                println!("Successfully obtained handle to the process: {:?}", process_handle);
                windows::Win32::Foundation::CloseHandle(process_handle);
            }
            Err(e) => {
                eprintln!("Failed to open process: {}", e);
            }
        }
    }
}
