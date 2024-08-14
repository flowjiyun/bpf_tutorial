#![no_std]
#![no_main]

#![allow(non_upper_case_globals)]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(dead_code)]

use aya_ebpf::{helpers::{bpf_get_current_uid_gid, bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes}, macros::{kprobe, map}, maps::PerCpuArray, programs::ProbeContext};
use aya_log_ebpf::info;
use binding::{dentry, file, path, qstr};
mod binding;
struct Buffer {
    pub data: [u8; 1024],
}

#[map]
static mut BUFFER: PerCpuArray<Buffer> = PerCpuArray::with_max_entries(1, 0);

#[map]
static mut USER_LIST: PerCpuArray<u32> = PerCpuArray::with_max_entries(1024, 0);

#[kprobe]
pub fn array(ctx: ProbeContext) -> u32 {
    match try_array(ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}
fn check_valid_user(uid: u32) -> bool {
    for i in 0..1024 {
        match unsafe {USER_LIST.get(i) } {
            Some(&user_id) => {
                if user_id == uid {
                    return true;
                }
            }
            None => {
                continue;
            }
        }
    }
    false
}

fn try_array(ctx: ProbeContext) -> Result<u32, i64> {
    let file: *mut file  = ctx.arg(0).ok_or(1i64)?;
    let uid = bpf_get_current_uid_gid() as u32;
    if !check_valid_user(uid) {
        return Ok(0);
    }
    // let mut buf = [0u8; 100];
    let buffer = unsafe {
        let ptr = BUFFER.get_ptr_mut(0).ok_or(1i64)?;
        &mut *ptr
    };
    let path = unsafe {
        bpf_probe_read_kernel(&(*file).f_path as *const path)
            .map_err(|e| e)?
    };

    let dentry = unsafe {
        bpf_probe_read_kernel(path.dentry as *const dentry)
            .map_err(|e| e)?
    };
    let dname = unsafe {
        bpf_probe_read_kernel(&dentry.d_name as *const qstr)
            .map_err(|e| e)?
    };
    let file_name_str = unsafe {
        core::str::from_utf8_unchecked(bpf_probe_read_kernel_str_bytes(dname.name, &mut buffer.data)?)
    };

    // info!(&ctx, "user_id : {} function security_file_open called : {}", uid, file_name_str);
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
