use std::ffi::c_void;

use windows::{
    core::PCSTR,
    Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA},
};

#[derive(Debug)]
pub struct HookError {
    pub details: String,
}
impl HookError {
    pub fn new(msg: impl Into<String>) -> Self {
        Self {
            details: msg.into(),
        }
    }
}

pub trait ToPcstr {
    fn into_pcstr(self) -> PCSTR;
}

impl ToPcstr for &str {
    fn into_pcstr(self) -> PCSTR {
        let mut vec = self.as_bytes().to_vec();
        vec.push(0);
        PCSTR(vec.as_ptr())
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
    let lib_name = lib_name.into_pcstr();

    let Ok(h_lib) = (unsafe { LoadLibraryA(lib_name) }) else {
        return Err(HookError::new("Could not get library"));
    };

    let func_name = func_name.into_pcstr();

    let Some(func_addr) = (unsafe { GetProcAddress(h_lib, func_name) }) else {
        return Err(HookError::new(format!(
            "Could not find address of function {func_name:?}"
        )));
    };

    Ok(func_addr as *const c_void)
}
