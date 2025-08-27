mod instructions;
mod util;

use std::{
    ffi::c_void,
    sync::atomic::{AtomicPtr, Ordering},
};

use util::find_func_addr;
#[allow(unused_imports)]
use windows::{
    core::{s, BOOL, PCSTR},
    Win32::{
        Foundation::{HANDLE, HWND, POINT},
        System::DataExchange::GetClipboardData,
        System::Threading::Sleep,
        UI::WindowsAndMessaging::{GetCursorPos, MessageBoxA, MESSAGEBOX_STYLE},
    },
};

use crate::instructions::{
    alloc_trampoline_mem_near_address, build_trampoline, init_relay_function, install_hook, byte_len_instructions, pad_relay_function, steal_bytes
};

type MessageBoxASig = unsafe extern "system" fn(HWND, PCSTR, PCSTR, u32) -> i32;
type GetCursorPosSig = unsafe extern "system" fn(POINT) -> BOOL;
type GetClipboardDataSig = unsafe extern "system" fn(u32) -> HANDLE;
type SleepSig = unsafe extern "system" fn(u32) -> c_void;

// Global pointer to the trampoline code
static P_TRAMPOLINE: AtomicPtr<()> = AtomicPtr::new(std::ptr::null_mut());

fn main() {
    // let func_addr = find_func_addr("user32.dll", "MessageBoxA").unwrap();
    let func_addr = find_func_addr("user32.dll", "GetCursorPos").unwrap();
    // let func_addr = find_func_addr("user32.dll", "GetClipboardData").unwrap();
    // let func_addr = find_func_addr("Kernel32.dll", "Sleep").unwrap();

    // Use for disassembling
    println!("Actual Func: dis -s {func_addr:x?} -c 10 -b ");

    // let proxy_func = message_box_a_proxy_func as *const c_void;
    let proxy_func = get_cursor_pos_proxy as *const c_void;
    // let proxy_func = get_clipboard_data_proxy as *const c_void;
    // let proxy_func = sleep_proxy as *const c_void;

    // 1) Create the relay function that will overwrite the MessageBoxA function prologue
    let mut relay_func = init_relay_function(proxy_func);

    // 2) Get the length of the relay function in bytes
    let relay_func_len = byte_len_instructions(&relay_func);
    println!("Relay function length in bytes {relay_func_len}");

    // 3) Steal bytes from the prologue of the function up to the length of the relay_function
    let stolen_bytes = steal_bytes(func_addr, relay_func_len);
    // println!(
    //     "Stolen bytes {:?}",
    //     byte_len_instructions(&stolen_bytes.instrs)
    // );
    println!("Need {:?} more byte(s)", stolen_bytes.num_bytes - relay_func_len);

    // 4) Re-encode the relay function with no-ops
    //   * The relay function likely splits an instruction and breaks shit, so we need to ensure
    //     that the relay function is the same length as the number of bytes we stole
    if stolen_bytes.num_bytes > relay_func_len {
        relay_func = pad_relay_function(relay_func, stolen_bytes.num_bytes - relay_func_len);
    }

    // 5) Alloc memory near the original function for the trampoline
    let mut trampoline = alloc_trampoline_mem_near_address(func_addr).unwrap();

    // 6) Build the trampoline
    build_trampoline(func_addr, &stolen_bytes, &mut trampoline);
    println!("Trampoline size: {}", trampoline.size.unwrap());
    println!("Trampoline addr: {:x?}", trampoline.addr);

    // 7) Store a reference to the trampoline addr for the proxy to callback
    // TODO: Fix RIP relative instructions on trampoline to ensure they point to correct memory
    //     1) Disassemble actual function: dis -s 0x7ffa4f4c8b70 -c 10 -b
    //     2) Disassemble actual function after copying: dis -s 0x7ffa4f4c8b70 -c 10 -b
    //     3) Disable trampoline function: dis -s 0x7ffa4f440000 -c 10 -b

    // Need to calc 0x7ffe4fc5d22e + 0x4362a = 0x7ffe4fca0858 
    P_TRAMPOLINE.store(trampoline.addr as *mut (), Ordering::Release);

    // 8) Install the hook
    install_hook(relay_func, func_addr, stolen_bytes);

    // unsafe { MessageBoxA(None, s!("hello world"), s!("lmao"), MESSAGEBOX_STYLE(1)) };

    // This doesn't work, I'm assuming because of the int3 instruction that is getting copied to the trampoline
    let mut point = POINT::default();
    unsafe { GetCursorPos(&mut point).unwrap() };
    println!("{point:?}");

    // let _ = unsafe { GetClipboardData(0) };

    // println!("eepy time");
    // unsafe { Sleep(5000) };
    // println!("waky waky");
}

#[no_mangle]
pub extern "system" fn message_box_a_proxy_func(
    hwnd: HWND,
    lptext: PCSTR,
    lpcaption: PCSTR,
    utype: u32,
) -> i32 {
    println!("HOOKED");
    println!("  hwnd: {hwnd:?}");
    println!("  lptext: '{}'", unsafe { lptext.to_string().unwrap() });
    println!("  lpcaption: '{}'", unsafe {
        lpcaption.to_string().unwrap()
    });
    println!("  utype: {:?}", utype);

    // Call original function
    let p = P_TRAMPOLINE.load(std::sync::atomic::Ordering::Acquire);
    let orig = unsafe { std::mem::transmute::<*mut (), MessageBoxASig>(p) };

    let new_text = s!("hooged");

    unsafe { orig(hwnd, new_text, lpcaption, utype) }
}

#[no_mangle]
pub extern "system" fn get_cursor_pos_proxy(mut lppoint: POINT) -> BOOL {
    println!("HOOKED");
    println!("  lppoint: {lppoint:?}");

    // Call original function
    let p = P_TRAMPOLINE.load(std::sync::atomic::Ordering::Acquire);
    let orig = unsafe { std::mem::transmute::<*mut (), GetCursorPosSig>(p) };

    lppoint.x = 69;
    lppoint.y = 420;

    return unsafe { orig(lppoint) }
}

#[no_mangle]
pub extern "system" fn get_clipboard_data_proxy(u_format: u32) -> HANDLE {
    println!("HOOKED");
    println!("  u_format: {u_format:?}");

    // Call original function
    let p = P_TRAMPOLINE.load(std::sync::atomic::Ordering::Acquire);
    let orig = unsafe { std::mem::transmute::<*mut (), GetClipboardDataSig>(p) };

    unsafe { orig(u_format) }
}

#[no_mangle]
pub extern "system" fn sleep_proxy(ms: u32) -> () {
    println!("HOOKED");
    println!("  Milliseconds: {ms:?}");

    // Call original function
    let p = P_TRAMPOLINE.load(std::sync::atomic::Ordering::Acquire);
    let orig = unsafe { std::mem::transmute::<*mut (), SleepSig>(p) };

    println!("Actually sleeping for 2 seconds");
    unsafe { orig(2) };
}
