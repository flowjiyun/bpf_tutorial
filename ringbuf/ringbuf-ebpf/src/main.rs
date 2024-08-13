#![no_std]
#![no_main]

#![allow(non_upper_case_globals)]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(dead_code)]

use aya_ebpf::{helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes}, macros::{kprobe, map}, maps::RingBuf, programs::ProbeContext};
use aya_log_ebpf::{info, warn};
use binding::{dentry, file, path, qstr};
use ringbuf_common::Event;

mod binding;
#[map]
static mut RINGBUF: RingBuf = RingBuf::with_byte_size(128 * 4096, 0); // 128 pages = 256KB

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

    let mut event_reserved = match unsafe { RINGBUF.reserve::<Event>(0) } {
        Some(event) => event,
        None => {
            warn!(&ctx, "ringbuf full");
            return Err(1i64)
        }
    };

    unsafe {
        let event ={
            let event_ptr = event_reserved.as_mut_ptr();
            &mut *event_ptr
        };
        event.uid = bpf_get_current_uid_gid() as u32;
        event.pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        event.task_name = bpf_get_current_comm()?;
        bpf_probe_read_kernel_str_bytes(dname.name, &mut event.file_path)?;

        event_reserved.submit(0);
    }


    // info!(&ctx, "function security_file_open called");
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
