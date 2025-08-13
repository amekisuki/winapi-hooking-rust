use std::ffi::c_void;

use iced_x86::{
    BlockEncoder, BlockEncoderOptions, Code, Decoder, DecoderOptions, FlowControl, Formatter,
    Instruction, InstructionBlock, NasmFormatter, Register, IntelFormatter
};
use windows::{
    core::PCSTR,
    Win32::System::{
        Diagnostics::Debug::FlushInstructionCache,
        LibraryLoader::{GetProcAddress, LoadLibraryA},
        Memory::{
            VirtualAlloc, VirtualProtect, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READ,
            PAGE_PROTECTION_FLAGS, PAGE_READWRITE,
        },
        Threading::GetCurrentProcess,
    },
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
    let h_lib = match unsafe { LoadLibraryA(lib_name.into_pcstr()) } {
        Err(err) => {
            return Err(HookError::new(format!(
                "Could not get library {:?} {:?}",
                lib_name, err
            )))
        }
        Ok(val) => val,
    };

    let func_name = func_name.into_pcstr();

    let Some(func_addr) = (unsafe { GetProcAddress(h_lib, func_name) }) else {
        return Err(HookError::new(format!(
            "Could not find address of function {func_name:?}"
        )));
    };

    Ok(func_addr as *const c_void)
}

/// Take the original function prologue and put it in the trampoline
///
/// Transforms any RIP-relative address into an absolute address
pub fn relocate_prologue_to_trampoline(
    orig: *const u8,
    trampoline: *mut u8,
    stolen_len: usize,
) -> Result<usize, HookError> {
    let code = unsafe { std::slice::from_raw_parts(orig, stolen_len) };
    let mut decoder = Decoder::with_ip(64, code, orig as u64, DecoderOptions::NONE);

    let mut read = 0usize;
    let mut instructions: Vec<Instruction> = Vec::new();

    // For debugging
    let print_instr = |instr: &Instruction, param: bool| { 
        let mut formatter = NasmFormatter::new();
        let mut output = String::new();
        formatter.format(instr, &mut output);
        if !param {
            println!("  {output}");
        } else {
            println!("  ({output})");
        }
    };

    while read < stolen_len {
        let instr = decoder.decode();
        read += instr.len();

        if instr.flow_control() != FlowControl::Next {
            panic!("Flow control instruction found in prologue. Bailing");
        }

        instructions.push(instr);
    }

    println!("Instructions");
    let mut out: Vec<Instruction> = Vec::with_capacity(instructions.len() * 2);
    for instr in instructions {
        print_instr(&instr, false);

        if instr.is_ip_rel_memory_operand() {
            let abs = instr.ip_rel_memory_address();
            let mov_r10_abs = Instruction::with2(Code::Mov_r64_imm64, Register::R10, abs)
                .expect("Unable to build new instruction");

            out.push(mov_r10_abs);

            print_instr(&mov_r10_abs, true);
        } else {
            out.push(instr);
        }
    }

    println!("Append absolute jump back to original function");
    let jmp_r10 = Instruction::with1(Code::Jmp_rm64, Register::R10).expect("Unable to create jmp");

    out.push(jmp_r10);

    let encoder = BlockEncoder::encode(
        64,
        InstructionBlock::new(&out, trampoline as u64),
        BlockEncoderOptions::NONE,
    )
    .expect("Unable to encode new buffer");

    // unsafe {
    //     std::ptr::copy_nonoverlapping(encoder.code_buffer.as_ptr(), trampoline, written);
    // }

    // let back = (orig as u64) + (stolen_len as u64);
    // let p = unsafe { trampoline.add(written) };

    // // mov rax, imm64
    // unsafe { *p.add(0) = 0x48 };
    // unsafe { *p.add(1) = 0xB8 };
    // unsafe { *(p.add(2) as *mut u64) = back };

    // // jmp rax
    // unsafe { *p.add(10) = 0xFF };
    // unsafe { *p.add(11) = 0xE0 };

    // written += 12;

    // let mut old: PAGE_PROTECTION_FLAGS = PAGE_PROTECTION_FLAGS(0u32);

    // unsafe {
    //     VirtualProtect(trampoline as _, written, PAGE_EXECUTE_READ, &mut old)
    //         .expect("Unable to change memory protection level")
    // };

    // let _ = unsafe {
    //     FlushInstructionCache(GetCurrentProcess(), Some(trampoline as _), written)
    //         .expect("Unable to flush instruction cache")
    // };

    Ok(encoder.code_buffer.len())
}


fn steal_bytes(prologue: *const u8, num_of_bytes: usize) {
    // This changes a *const u8 into a &[u8]
    let code = unsafe { std::slice::from_raw_parts(prologue, num_of_bytes) };
    let mut decoder = Decoder::with_ip(64, code, prologue as u64, DecoderOptions::NONE);

    
}