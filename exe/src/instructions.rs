use iced_x86::{
    BlockEncoder, BlockEncoderOptions, Code, Decoder, DecoderOptions, Instruction,
    InstructionBlock, Register,
};
use std::{cmp, ffi::c_void, ptr};
use windows::Win32::System::{
    Memory::{
        VirtualAlloc, VirtualProtect, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
        PAGE_PROTECTION_FLAGS,
    },
    SystemInformation::{GetSystemInfo, SYSTEM_INFO},
};

use crate::util::HookError;

const MIN_SIZE: usize = 5usize; // Trying to steal the least number of bytes possible

#[derive(Debug)]
pub struct X64Instructions {
    pub instrs: Vec<Instruction>,
    pub num_bytes: usize,
}
impl X64Instructions {
    fn new(instrs: Vec<Instruction>, num_bytes: usize) -> Self {
        Self { instrs, num_bytes }
    }
}

#[derive(Debug)]
pub struct TrampolineMem {
    pub addr: *mut c_void,
    pub size: u64,
}
impl TrampolineMem {
    fn new(addr: *mut c_void, size: u64) -> Self {
        Self { addr, size }
    }
}

/// Copy the first MIN_SIZE bytes from the prologue of a function
/// Decode the bytes using iced_x86 disassembler into Instructions
pub fn steal_bytes(func_addr: *const c_void) -> X64Instructions {
    let mut saved_buffer: [u8; MIN_SIZE] = [0; MIN_SIZE];

    // Get the prologue of the function
    unsafe {
        ptr::copy_nonoverlapping(
            func_addr,
            saved_buffer.as_mut_ptr() as *mut c_void,
            MIN_SIZE,
        )
    };

    let p_saved_buffer = saved_buffer.as_mut_ptr();

    let code = unsafe { std::slice::from_raw_parts(p_saved_buffer, MIN_SIZE) };
    let mut dec = Decoder::with_ip(64, code, p_saved_buffer as u64, DecoderOptions::NONE);

    let mut read = 0usize;
    let mut instructions: Vec<Instruction> = Vec::new();

    while read < MIN_SIZE {
        let instr = dec.decode();

        if instr.is_invalid() {
            break;
        }

        read += instr.len();
        instructions.push(instr);
    }

    X64Instructions::new(instructions, read)
}

pub fn alloc_trampoline_mem_near_address(
    func_addr: *const c_void,
) -> Result<TrampolineMem, HookError> {
    let mut info: SYSTEM_INFO = SYSTEM_INFO::default();
    unsafe { GetSystemInfo(&mut info) };
    let size: u64 = info.dwPageSize.into();

    let two_gb_window = 0x7FFFFF00; // 2,147,483,392 bytes

    let start_address = func_addr as u64 & !(size - 1);

    let min_address = cmp::min(
        start_address - two_gb_window,
        info.lpMinimumApplicationAddress as u64,
    );
    let max_address = cmp::max(
        start_address + two_gb_window,
        info.lpMaximumApplicationAddress as u64,
    );

    let start_page = start_address - (start_address % size);

    let mut offset = 1;
    loop {
        let byte_offset = offset * size;

        let high_addr = start_page + byte_offset;
        let low_addr = if start_page > byte_offset {
            start_page - byte_offset
        } else {
            0
        };

        let needs_exit = high_addr > max_address && low_addr < min_address;

        if high_addr < max_address {
            let addr = unsafe {
                VirtualAlloc(
                    Some(high_addr as *const c_void),
                    size as usize,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_EXECUTE_READWRITE,
                )
            };
            if !addr.is_null() {
                return Ok(TrampolineMem::new(addr, size));
            }
        }

        if low_addr > min_address {
            let addr = unsafe {
                VirtualAlloc(
                    Some(low_addr as *const c_void),
                    size as usize,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_EXECUTE_READWRITE,
                )
            };
            if !addr.is_null() {
                return Ok(TrampolineMem::new(addr, size));
            }
        }

        offset += 1;

        if needs_exit {
            return Err(HookError::Alloc(format!(
                "Unable to allocate memory near address {func_addr:?}"
            )));
        }
    }
}

pub fn build_trampoline(func_addr: *const c_void, dst_hook_mem: &mut TrampolineMem) {
    let stolen_bytes = steal_bytes(func_addr);

    let jmp_back_addr = unsafe { func_addr.add(stolen_bytes.num_bytes) };

    let mut instructions = stolen_bytes.instrs;

    // Adding jmp to get back to original function
    instructions.push(
        Instruction::with2(Code::Mov_r64_imm64, Register::R10, jmp_back_addr as u64).unwrap(), // mov r10, addr
    );
    instructions.push(
        Instruction::with1(Code::Jmp_rm64, Register::R10).unwrap(), // jmp r10
    );

    // The block encoder should auto-magically fix any RIP relative addressing
    let encoded_instrs = BlockEncoder::encode(
        64,
        InstructionBlock::new(&instructions, dst_hook_mem.addr as u64),
        BlockEncoderOptions::NONE,
    )
    .unwrap();

    unsafe {
        std::ptr::copy_nonoverlapping(
            encoded_instrs.code_buffer.as_ptr(),
            dst_hook_mem.addr as *mut u8,
            encoded_instrs.code_buffer.len(),
        )
    };

    dst_hook_mem.size = encoded_instrs.code_buffer.len() as u64;
}

/// Overwrites a given function with a jmp instr to jump to the intended proxy function
pub fn overwrite_func_with_relay(func_addr: *const c_void, proxy_func: *const c_void) {
    let instructions: Vec<Instruction> = vec![
        Instruction::with2(Code::Mov_r64_imm64, Register::R10, proxy_func as u64).unwrap(), // mov r10, addr
        Instruction::with1(Code::Jmp_rm64, Register::R10).unwrap(),                         // jmp r10
    ];

    let encoded_instrs = BlockEncoder::encode(
        64,
        InstructionBlock::new(&instructions, func_addr as u64),
        BlockEncoderOptions::NONE,
    )
    .unwrap();

    // Overwrite the function prologue with a jmp to the proxy function!

    // 1) Change the protection level of the memory to be writable
    let mut original_protect = PAGE_PROTECTION_FLAGS::default();
    unsafe {
        VirtualProtect(
            func_addr,
            encoded_instrs.code_buffer.len(),
            PAGE_EXECUTE_READWRITE,
            &mut original_protect,
        )
        .expect("Unable to change access permissions to memory")
    };

    // 2) Overwrite the function prologue
    unsafe {
        std::ptr::copy_nonoverlapping(
            encoded_instrs.code_buffer.as_ptr(),
            func_addr as *mut u8,
            encoded_instrs.code_buffer.len(),
        )
    };

    // 3) Reapply the original protections
    unsafe {
        VirtualProtect(
            func_addr,
            encoded_instrs.code_buffer.len(),
            original_protect,
            &mut PAGE_PROTECTION_FLAGS::default(),
        )
        .expect("Unable to reassign original memory access permissions")
    };
}
