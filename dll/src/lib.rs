use windows::{core::PCSTR, Win32::{
    Foundation::HWND,
    // UI::WindowsAndMessaging::{MESSAGEBOX_RESULT, MESSAGEBOX_STYLE},
}};

// MessageBoxAProxy
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
    println!("  lpcaption: '{}'", unsafe { lpcaption.to_string().unwrap() });
    println!("  utype: {:?}", utype);

    0

    // This should call the original implementation at some point
    // unsafe {
    //     match GATEWAY_PTR{
    //         Some(ptr) => ptr(hwnd, lptext, lpcaption, utype),
    //         None => {
    //             println!("set_gateway never called");
    //             0
    //         }
    //     }
    // }
}

static mut GATEWAY_PTR: Option<extern "system" fn(HWND, PCSTR, PCSTR, u32) -> i32> = None;

#[no_mangle]
pub extern "system" fn set_gateway(ptr: usize) -> () {
    println!("Setting gateway");
    unsafe {
        GATEWAY_PTR = Some(std::mem::transmute(ptr));
    }

    println!("{:x?}", unsafe { GATEWAY_PTR });
}