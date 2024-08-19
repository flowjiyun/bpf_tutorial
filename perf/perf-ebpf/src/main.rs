#![no_std]
#![no_main]

#![allow(non_upper_case_globals)]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(dead_code)]

use aya_ebpf::{cty::c_void, helpers::{self, bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_task, bpf_get_current_uid_gid, bpf_ktime_get_ns, bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes}, macros::{kprobe, map}, maps::{PerCpuArray, PerfEventArray}, programs::ProbeContext};
use binding::{dentry, file, path, qstr, task_struct}; use perf_common::Event; mod binding;

#[map]
static mut EVENT_BUF: PerCpuArray<Event> = PerCpuArray::with_max_entries(1, 0);

#[map]
static mut TASK_BUF: PerCpuArray<task_struct> = PerCpuArray::with_max_entries(1, 0);

#[map]
static mut EVENTS: PerfEventArray<Event> = PerfEventArray::new(0);

#[kprobe]
pub fn perf(ctx: ProbeContext) -> u32 {
    match try_perf(ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn try_perf(ctx: ProbeContext) -> Result<u32, i64> {
    let file:*mut file  = ctx.arg(0).ok_or(1i64)?;
    let task = unsafe {bpf_get_current_task() as *const task_struct};
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
    // let file_name_str = unsafe {
    //     core::str::from_utf8_unchecked(bpf_probe_read_kernel_str_bytes(dname.name, &mut buf)?)
    // };
    let event = unsafe {
        let ptr = EVENT_BUF.get_ptr_mut(0).ok_or(1i64)?;
        &mut *ptr
    };

    let p_task = unsafe {
        TASK_BUF.get_ptr_mut(0).ok_or(1i64)?
    };
    unsafe {
        helpers::gen::bpf_probe_read_kernel(p_task as *mut c_void, core::mem::size_of::<task_struct>() as u32, task as *const c_void);
    }
    event.uid = bpf_get_current_uid_gid() as u32;
    event.pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    event.ppid = unsafe {(*p_task).pid};
    // event.ppid = unsafe { bpf_probe_read_kernel((*p_task).pid as *const i32).map_err(|e| e)? };
    event.f_flag = unsafe { bpf_probe_read_kernel(&(*file).f_flags as *const u32).map_err(|e| e)?};
    event.time = unsafe { bpf_ktime_get_ns()};
    event.task_name = bpf_get_current_comm()?;
    unsafe {
        bpf_probe_read_kernel_str_bytes(dname.name, &mut event.file_path)?;
        EVENTS.output(&ctx, event, 0);
    }
    // info!(&ctx, "function security_file_open called");

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
