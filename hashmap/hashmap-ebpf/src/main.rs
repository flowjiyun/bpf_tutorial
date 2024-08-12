#![no_std]
#![no_main]

#![allow(non_upper_case_globals)]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(dead_code)]

use aya_ebpf::{helpers::bpf_get_current_uid_gid, macros::{kprobe, map}, maps::PerCpuHashMap, programs::ProbeContext};

mod binding;

#[repr(C)]
#[derive(Clone, Copy)]

pub struct FileOpenInfo {
    pub count: u64,
}

#[map]
static mut FILE_OPEN_COUNT: PerCpuHashMap<u32, FileOpenInfo> = PerCpuHashMap::with_max_entries(1024, 0);

#[kprobe]
pub fn hashmap(ctx: ProbeContext) -> u32 {
    match try_hashmap(ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn try_hashmap(_ctx: ProbeContext) -> Result<u32, i64> {
    // let file:*mut file  = ctx.arg(0).ok_or(1i64)?;
    let uid = bpf_get_current_uid_gid() as u32;

    unsafe {
        // let info: &FileOpenInfo = FILE_OPEN_COUNT.get(&uid).unwrap_or(&FileOpenInfo { count: 0 });
        // let info = FileOpenInfo { count: info.count + 1 };  
        // FILE_OPEN_COUNT.insert(&uid, &info, 0)?;

        if let Some(info_ptr) = FILE_OPEN_COUNT.get_ptr_mut(&uid) {
            let info = &mut *info_ptr;
            info.count += 1;
        } else {
            let info = FileOpenInfo { count: 1 };
            FILE_OPEN_COUNT.insert(&uid, &info, 0)?;
        }
    }
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
