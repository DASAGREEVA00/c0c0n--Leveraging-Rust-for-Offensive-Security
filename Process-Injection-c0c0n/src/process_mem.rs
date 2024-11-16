use std::io;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Threading::{OpenProcess, PROCESS_ALL_ACCESS, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};
use windows::Win32::System::ProcessStatus::GetProcessImageFileNameW;
use windows::Win32::System::ProcessStatus::K32GetProcessMemoryInfo;
use windows::Win32::System::SystemInformation::PROCESS_MEMORY_COUNTERS_EX;
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

    // Open the process with additional access rights
    unsafe {
        match OpenProcess(PROCESS_ALL_ACCESS | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) {
            Ok(process_handle) => {
                println!("Successfully obtained handle to the process: {:?}", process_handle);

                // Retrieve memory information
                let mut mem_counters = PROCESS_MEMORY_COUNTERS_EX::default();
                if K32GetProcessMemoryInfo(
                    process_handle,
                    &mut mem_counters as *mut _ as *mut _,
                    std::mem::size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32,
                ).as_bool() {
                    println!("Memory Usage: {} KB", mem_counters.WorkingSetSize / 1024);
                } else {
                    println!("Failed to retrieve memory usage information.");
                }

                // Retrieve executable path
                let mut image_filename = vec![0u16; 260]; // Buffer for file path (MAX_PATH length)
                let length = GetProcessImageFileNameW(process_handle, &mut image_filename);
                if length > 0 {
                    let path = String::from_utf16_lossy(&image_filename[..length as usize]);
                    println!("Executable Path: {}", path);
                } else {
                    println!("Failed to retrieve executable path.");
                }

                windows::Win32::Foundation::CloseHandle(process_handle);
            }
            Err(e) => {
                eprintln!("Failed to open process: {}", e);
            }
        }
    }
}
