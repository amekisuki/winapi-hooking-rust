mod instructions;
mod util;

use std::ffi::c_void;

use util::find_func_addr;
use windows::{
    core::{s, BOOL, PCSTR},
    Win32::{
        Foundation::{HWND, POINT},
        System::DataExchange::GetClipboardData,
        UI::WindowsAndMessaging::{GetCursorPos, MessageBoxA, MESSAGEBOX_STYLE},
    },
};

use crate::instructions::{
    alloc_trampoline_mem_near_address, build_trampoline, overwrite_func_with_relay,
};

fn main() {
    let func_addr = find_func_addr("user32.dll", "GetCursorPos").unwrap_or_else(|err| {
        println!("Error: {}", err);
        std::process::exit(1);
    });

    // Alloc a trampoline in memory near the original function
    let mut trampoline = alloc_trampoline_mem_near_address(func_addr).unwrap();

    // Build the trampoline
    build_trampoline(func_addr, &mut trampoline);

    println!("Trampoline size: {}", trampoline.size);

    overwrite_func_with_relay(func_addr, get_cursor_pos_proxy as *const c_void);

    // unsafe { MessageBoxA(None, s!("hello world"), s!("lmao"), MESSAGEBOX_STYLE(1)) };

    // let _ = unsafe { GetClipboardData(0).unwrap() };

    let mut lppoint = POINT::default();
    let _ = unsafe { GetCursorPos(&mut lppoint) };
    println!("{lppoint:?}");
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
}

#[no_mangle]
pub extern "system" fn get_clipboard_data_proxy(uformat: u32) -> i32 {
    println!("HOOKED");
    println!("  uFormat: {:?}", uformat);

    0
}

pub extern "system" fn get_cursor_pos_proxy(lppoint: &mut POINT) -> BOOL {
    print!("HOOKED");
    print!("  LPPOINT: {:?}", lppoint);
    BOOL(1)
}
