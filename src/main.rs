use std::{ffi::{c_void, CString}, mem};
use windows::{
    core::PCSTR,
    Win32::{
        Foundation::HWND,
        System::{
            Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory},
            LibraryLoader::{GetProcAddress, LoadLibraryA},
            Memory::{VirtualProtect, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS},
            Threading::GetCurrentProcess,
        },
        UI::WindowsAndMessaging::{MessageBoxA, MESSAGEBOX_RESULT, MESSAGEBOX_STYLE},
    },
};

trait FromStr {
    fn from_str(string: &str) -> PCSTR;
}

impl FromStr for PCSTR {
    fn from_str(string: &str) -> PCSTR {
        let c_string = CString::new(string).expect("CString::new failed");
        PCSTR::from_raw(c_string.into_raw() as *const u8)
    }
}

fn main() {
    let lib_name_ptr = PCSTR::from_str("user32.dll");
    let h_lib = unsafe { LoadLibraryA(lib_name_ptr).expect("Could not get library") };
    println!("{:?}", h_lib);

    let func_to_hook = PCSTR::from_str("MessageBoxA");

    // Cast as c_void so we can easily increment the pointer
    let func_addr = unsafe { GetProcAddress(h_lib, func_to_hook).expect("Could not find function") }
        as *const c_void;
    println!("{:?}", func_addr);

    // Save the first 16 bytes of the function
    // We need 16 bytes in order to fit a jmp and our relative offset in it's place
    const N_SIZE: usize = 13; // jmp instructions are fixed to 64 bits wide
    let mut saved_buffer: [u8; N_SIZE] = [0; N_SIZE];
    let mut num_bytes_read: usize = 0;

    unsafe {
        ReadProcessMemory(
            GetCurrentProcess(),
            func_addr,
            saved_buffer.as_mut_ptr() as *mut c_void,
            N_SIZE,
            Some(&mut num_bytes_read),
        )
        .expect("Unable to read process memory");
    }

    println!("Savedbuffer: {saved_buffer:x?}");

    let mut old_protect: PAGE_PROTECTION_FLAGS = PAGE_PROTECTION_FLAGS::default();
    unsafe {
        VirtualProtect(func_addr, N_SIZE, PAGE_EXECUTE_READWRITE, &mut old_protect)
            .expect("Unable to change access permissions to memory")
    };

    // mov r10, addr
    // jmp r10
    // The 0x00's will be populated with the memory address of message_box_a_proxy_func
    let mut relay_function: [u8; N_SIZE] = [
        0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x41, 0xFF, 0xE2,
    ];
    println!("{:x?}", relay_function);

    let byte_ptr = unsafe { std::slice::from_raw_parts(message_box_a_proxy_func as *const u8, mem::size_of::<*const ()>()) };
    // println!("{:x?}", byte_ptr.iter().rev());

    for (mut idx, byte) in byte_ptr.iter().rev().enumerate() { // reverse for little endian
        idx += 2; // offset of 2 for the relay function
        relay_function[idx] = *byte;
    }

    println!("Relay function: {relay_function:x?}");

    unsafe {
        WriteProcessMemory(
            GetCurrentProcess(),
            func_addr,
            relay_function.as_ptr() as *const c_void,
            N_SIZE,
            None,
        )
        .expect("Could not write memory")
    };


    let mut backup_protect: PAGE_PROTECTION_FLAGS = PAGE_PROTECTION_FLAGS::default();


    // unsafe {
    //     WriteProcessMemory(
    //         GetCurrentProcess(),
    //         func_addr,
    //         saved_buffer.as_ptr() as *const c_void,
    //         N_SIZE,
    //         None,
    //     )
    //     .expect("Could not write memory")
    // };

    unsafe {
        VirtualProtect(func_addr, N_SIZE, old_protect, &mut backup_protect)
            .expect("Unable to change access permissions to memory back")
    };

    // Sanity check to see if the memory was written properly
    let mut new_test_buffer: [u8; N_SIZE] = [0; N_SIZE];
    let mut new_num_bytes_read: usize = 0;
    unsafe {
        ReadProcessMemory(
            GetCurrentProcess(),
            func_addr as *const c_void,
            new_test_buffer.as_mut_ptr() as *mut c_void,
            N_SIZE,
            Some(&mut new_num_bytes_read),
        )
        .expect("Unable to read process memory");
    }

    println!("New test buffer: {new_test_buffer:x?} {new_num_bytes_read}"); // read more bytes to make sure it's writing correctly


    unsafe {
        MessageBoxA(
            None,
            PCSTR::from_str("hello world"),
            PCSTR::from_str("lmao"),
            MESSAGEBOX_STYLE(1),
        )
    };
}

#[no_mangle]
// MessageBoxAProxy
extern "system" fn message_box_a_proxy_func(
    hwnd: Option<HWND>,
    lptext: PCSTR,
    lpcaption: PCSTR,
    utype: MESSAGEBOX_STYLE,
) -> MESSAGEBOX_RESULT {
    println!(
        "hooked B-) - hwnd: {hwnd:?} lptext: {lptext:?} lpcaption: {lpcaption:?} utype: {utype:?}"
    );
    MESSAGEBOX_RESULT::default()
}
