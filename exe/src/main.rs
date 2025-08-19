mod instructions;
mod util;

use std::{ffi::c_void, sync::atomic::{AtomicPtr, Ordering}};

use util::find_func_addr;
use windows::{
    core::{s, PCSTR},
    Win32::{
        Foundation::HWND,
        UI::WindowsAndMessaging::{MessageBoxA, MESSAGEBOX_STYLE},
    },
};

use crate::instructions::{
    alloc_trampoline_mem_near_address, build_trampoline, overwrite_func_with_relay,
};

type MessageBoxASig = unsafe extern "system" fn(HWND, PCSTR, PCSTR, u32) -> i32;

// Global pointer to the trampoline code
static P_TRAMPOLINE: AtomicPtr<()> = AtomicPtr::new(std::ptr::null_mut());

fn main() {
    let func_addr = find_func_addr("user32.dll","MessageBoxA").unwrap();

    // Alloc a trampoline in memory near the original function
    let mut trampoline = alloc_trampoline_mem_near_address(func_addr).unwrap();

    // Build the trampoline
    build_trampoline(func_addr, &mut trampoline);
    println!("Trampoline size: {}", trampoline.size.unwrap());
    println!("{:?}", trampoline.addr);

    P_TRAMPOLINE.store(trampoline.addr as *mut (), Ordering::Release);
    overwrite_func_with_relay(func_addr, message_box_a_proxy_func as *const c_void);
    unsafe { MessageBoxA(None, s!("hello world"), s!("lmao"), MESSAGEBOX_STYLE(1)) };
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

    0

    // Call original function
    // let p = P_TRAMPOLINE.load(std::sync::atomic::Ordering::Acquire);
    // println!("{p:?}");
    // let orig = unsafe { std::mem::transmute::<*mut (), MessageBoxASig>(p) };
    // return unsafe { orig(hwnd, lptext, lpcaption, utype) };
}
