use std::ffi::CStr;

use aya::maps::RingBuf;
use aya::programs::KProbe;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use log::{warn, debug};
use ringbuf_common::Event;
use tokio::task;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/ringbuf"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/ringbuf"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program: &mut KProbe = bpf.program_mut("ringbuf").unwrap().try_into()?;
    program.load()?;
    program.attach("security_file_open", 0)?;

    let mut ring_buf = RingBuf::try_from(bpf.map_mut("RINGBUF").unwrap()).unwrap();

    // let mut poll = poll_fd

    loop {
        if let Some(item) = ring_buf.next() {
            let buf = &*item;
            if let Ok(event) = parse_event(buf) {
                let file_path = CStr::from_bytes_until_nul(&event.file_path).unwrap().to_str().unwrap();
                let task_name = CStr::from_bytes_until_nul(&event.task_name).unwrap().to_str().unwrap();
                // let task_name = String::from_utf8_lossy(&event.task_name);
                println!("uid : {}, pid : {}, task_name : {}, file_path : {}", event.uid, event.pid, task_name, file_path);
            } else {
                eprintln!("fail to parse event!");
            }
        }
    }
    // info!("Waiting for Ctrl-C...");
    // signal::ctrl_c().await?;
    // info!("Exiting...");

    // Ok(())
}

fn parse_event(buf: &[u8]) -> Result<Event, ()> {
    if buf.len() < core::mem::size_of::<Event>() {
        return Err(());
    }
    let event = unsafe {
        core::ptr::read_unaligned(buf.as_ptr() as *const Event)
    };
    Ok(event)
}