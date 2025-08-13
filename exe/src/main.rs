// Based on work from https://kylehalladay.com/blog/2020/11/13/Hooking-By-Example.html
mod util;

use crate::util::{find_func_addr, relocate_prologue_to_trampoline};
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

static MIN_SIZE: usize = 14;
static TRAMPOLINE_SIZE: usize = MIN_SIZE + 16;

fn main() {
    let func_addr = find_func_addr("user32.dll", "MessageBoxA").unwrap_or_else(|err| {
        println!("Error: {}", err.details);
        std::process::exit(1);
    });

    println!("Original Function Address: {:x?}", func_addr);

    println!("Next RIP-Relative Address: {:x?}", unsafe {
        func_addr.add(MIN_SIZE)
    });

    // Save the protection flags for the region
    let mut original_protect = PAGE_PROTECTION_FLAGS::default();
    unsafe {
        VirtualProtect(
            func_addr,
            MIN_SIZE,
            PAGE_EXECUTE_READWRITE,
            &mut original_protect,
        )
        .expect("Unable to change access permissions to memory")
    };

    // Save the first 14 bytes of the function
    // MessageBoxA starts with the following bytes, so we should see these in the `saved_buffer`
    // .text:0000000180078B70 48 83 EC 38            sub     rsp, 38h
    // .text:0000000180078B74 45 33 DB               xor     r11d, r11d
    // .text:0000000180078B77 44 39 1D 92 87 03 00   cmp     cs:?gfEMIEnable@@3HA, r11d ; int gfEMIEnable
    let mut saved_buffer: [u8; MIN_SIZE] = [0; MIN_SIZE];

    let mut num_bytes_read: usize = 0;
    unsafe {
        ReadProcessMemory(
            GetCurrentProcess(),
            func_addr,
            saved_buffer.as_mut_ptr() as *mut c_void,
            MIN_SIZE,
            Some(&mut num_bytes_read),
        )
        .expect("Unable to read process memory");
    }

    println!("Saved buffer: \n  {:x?}", saved_buffer);

    // The 0x00's will be populated with the memory address of message_box_a_proxy_func
    // mov r10, addr
    // jmp r10
    let mut new_func_prologue: [u8; MIN_SIZE] = [
        0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x41, 0xFF, 0xE2, 0x00, 
    ];

    // When we overwrite the function prologue, use NOPs to ensure we don't have invalid instructions
    let nop_func_prologue: [u8; MIN_SIZE] = [0x90; MIN_SIZE];

    let mut trampoline = Vec::new();

    let _ = relocate_prologue_to_trampoline(
        saved_buffer.as_ptr(),
        trampoline.as_mut_ptr(),
        MIN_SIZE,
    )
    .expect("Uh oh, stinky");

    println!("Trampoline: \n  {trampoline:x?}");

    let proc_addr =
        find_func_addr("rs_test_dll.dll", "message_box_a_proxy_func").unwrap_or_else(|err| {
            println!("Error: {}", err.details);
            std::process::exit(1);
        }) as *const () as usize;

    println!("Proxy Address: \n  {proc_addr:x}");

    // Place the address of the proxy function into the new_func_prologue
    new_func_prologue[2..10].copy_from_slice(&proc_addr.to_ne_bytes());
    println!("Relay function: \n  {new_func_prologue:x?}");

    unsafe {
        WriteProcessMemory(
            GetCurrentProcess(),
            func_addr,
            new_func_prologue.as_ptr() as *const c_void,
            MIN_SIZE,
            None,
        )
        .expect("Could not write memory")
    };

    unsafe {
        VirtualProtect(
            func_addr,
            MIN_SIZE,
            original_protect,
            &mut PAGE_PROTECTION_FLAGS::default(),
        )
        .expect("Unable to change access permissions to memory back")
    };

    unsafe { MessageBoxA(None, s!("hello world"), s!("lmao"), MESSAGEBOX_STYLE(1)) };
}
