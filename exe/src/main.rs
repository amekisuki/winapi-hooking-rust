// Based on work from https://kylehalladay.com/blog/2020/11/13/Hooking-By-Example.html
mod util;

use crate::util::find_func_addr;
use std::ffi::c_void;
use windows::{
    core::s,
    Win32::{
        System::{
            Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory},
            Memory::{VirtualProtect, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS},
            Threading::GetCurrentProcess,
        },
        UI::WindowsAndMessaging::{MessageBoxA, MESSAGEBOX_STYLE},
    },
};

static N_SIZE: usize = 13;

fn main() {
    let func_addr = find_func_addr("user32.dll", "MessageBoxA").unwrap_or_else(|err| {
        println!("Error: {}", err.details);
        std::process::exit(1);
    });

    // Save the protection flags for the region
    let mut original_protect = PAGE_PROTECTION_FLAGS::default();
    unsafe {
        VirtualProtect(
            func_addr,
            N_SIZE,
            PAGE_EXECUTE_READWRITE,
            &mut original_protect,
        )
        .expect("Unable to change access permissions to memory")
    };

    // Save the first 13 bytes of the function
    // We need 13 bytes in order to fit a jmp and our relative offset in it's place
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

    // mov r10, addr
    // jmp r10
    //
    // The 0x00's will be populated with the memory address of message_box_a_proxy_func
    let mut relay_function: [u8; N_SIZE] = [
        0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x41, 0xFF, 0xE2,
    ];

    let proc_addr =
        find_func_addr("rs_test_dll.dll", "message_box_a_proxy_func").unwrap_or_else(|err| {
            println!("Error: {}", err.details);
            std::process::exit(1);
        }) as *const () as usize;

    println!("Proxy Address: {proc_addr:x}");

    // Place the address of the proxy function into the relay_function
    relay_function[2..10].copy_from_slice(&proc_addr.to_ne_bytes());
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

    unsafe {
        VirtualProtect(
            func_addr,
            N_SIZE,
            original_protect,
            &mut PAGE_PROTECTION_FLAGS::default(),
        )
        .expect("Unable to change access permissions to memory back")
    };

    unsafe { MessageBoxA(None, s!("hello world"), s!("lmao"), MESSAGEBOX_STYLE(1)) };
}
