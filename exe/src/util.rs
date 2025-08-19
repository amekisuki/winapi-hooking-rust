use std::{
    ffi::{c_void, CString, OsStr},
    fmt,
    os::windows::ffi::OsStrExt,
};

use windows::{
    core::{PCSTR, PCWSTR},
    Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW},
};

#[derive(Debug)]
pub enum HookError {
    LoadLibrary(String),
    FuncAddr(String),
    Alloc(String),
    Parse(String),
}
impl fmt::Display for HookError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HookError::LoadLibrary(msg) => write!(f, "LoadLibrary: {}", msg),
            HookError::FuncAddr(msg) => write!(f, "FuncAddr: {}", msg),
            HookError::Alloc(msg) => write!(f, "Alloc: {}", msg),
            HookError::Parse(msg) => write!(f, "Unable to parse: {}", msg),
        }
    }
}

/// Get the address of a library function
///
/// # Arguments
///
/// * `lib_name` - Name of the library
/// * `func_name` - Name of the function in the library
///
/// # Returns
///
/// `func_addr` - `*const c_void`
pub fn find_func_addr(lib_name: &str, func_name: &str) -> Result<*const c_void, HookError> {
    // For when loading library in the main app
    let wide_lib: Vec<u16> = OsStr::new(&lib_name).encode_wide().chain(Some(0)).collect();
    let lib_name = PCWSTR(wide_lib.as_ptr());

    let h_lib = match unsafe { LoadLibraryW(lib_name) } {
        Err(err) => {
            return Err(HookError::LoadLibrary(format!(
                "Could not get library {:?} {:?}",
                lib_name, err
            )))
        }
        Ok(val) => val,
    };

    let wide_func = match CString::new(func_name) {
        Err(_) => {
            return Err(HookError::Parse(format!(
                "Unable to parse str into CString {func_name}"
            )))
        }
        Ok(c) => c,
    };
    let func_name = PCSTR(wide_func.as_ptr() as *const u8);

    let Some(func_addr) = (unsafe { GetProcAddress(h_lib, func_name) }) else {
        return Err(HookError::FuncAddr(format!(
            "Could not find address of function {func_name:?}"
        )));
    };

    Ok(func_addr as *const c_void)
}
