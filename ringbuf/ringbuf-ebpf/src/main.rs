#![no_std]
#![no_main]

#![allow(non_upper_case_globals)]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(dead_code)]

use aya_ebpf::{helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes}, macros::{kprobe, map}, maps::RingBuf, programs::ProbeContext};
use aya_log_ebpf::warn;
use binding::{dentry, file, path, qstr};
use ringbuf_common::Event;

mod binding;
#[map]
static RINGBUF: RingBuf = RingBuf::with_byte_size(128 * 4096, 0); // 128 pages = 256KB

#[kprobe]
pub fn ringbuf(ctx: ProbeContext) -> u32 {
    match try_ringbuf(ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn try_ringbuf(ctx: ProbeContext) -> Result<u32, i64> {
    let file:*mut file  = ctx.arg(0).ok_or(1i64)?;
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

    if let Some(mut event_reserved) = RINGBUF.reserve::<Event>(0) {
        unsafe {
            (*event_reserved.as_mut_ptr()).uid = bpf_get_current_uid_gid() as u32;
            (*event_reserved.as_mut_ptr()).pid = (bpf_get_current_pid_tgid() >> 32) as u32;
            (*event_reserved.as_mut_ptr()).task_name = match bpf_get_current_comm() {
                Ok(data) => data,
                Err(_) => {
                    event_reserved.discard(0);
                    warn!(&ctx, "fail to reserve buffer");
                    return Err(1i64);
                }
            };
            match bpf_probe_read_kernel_str_bytes(dname.name, &mut (*event_reserved.as_mut_ptr()).file_path) {
                Ok(_) => {}
                Err(_) => {
                    event_reserved.discard(0);
                    warn!(&ctx, "fail to reserve buffer");
                    return Err(1i64);
                }
            }
        }
        event_reserved.submit(0);
    } else {
        warn!(&ctx, "fail to reserve buffer");
        return Err(1i64);
    }
    
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
