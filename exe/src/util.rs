use std::{ffi::c_void, fmt};

use windows::{
    core::PCSTR,
    Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA},
};

#[derive(Debug)]
pub enum HookError {
    LoadLibrary(String),
    FuncAddr(String),
    Alloc(String),
}
impl fmt::Display for HookError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HookError::LoadLibrary(msg) => write!(f, "LoadLibrary: {}", msg),
            HookError::FuncAddr(msg) => write!(f, "FuncAddr: {}", msg),
            HookError::Alloc(msg) => write!(f, "Alloc: {}", msg),
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
    let h_lib = match unsafe { LoadLibraryA(lib_name.into_pcstr()) } {
        Err(err) => {
            return Err(HookError::LoadLibrary(format!(
                "Could not get library {:?} {:?}",
                lib_name, err
            )))
        }
        Ok(val) => val,
    };

    let func_name = func_name.into_pcstr();

    let Some(func_addr) = (unsafe { GetProcAddress(h_lib, func_name) }) else {
        return Err(HookError::FuncAddr(format!(
            "Could not find address of function {func_name:?}"
        )));
    };

    Ok(func_addr as *const c_void)
}
