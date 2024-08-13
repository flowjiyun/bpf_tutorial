
use std::ffi::{c_char, CStr};

use aya::maps::AsyncPerfEventArray;
use aya::programs::KProbe;
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use bytes::BytesMut;
use log::{info, warn, debug};
use perf_common::Event;
use tokio::signal;

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
        "../../target/bpfel-unknown-none/debug/perf"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/perf"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program: &mut KProbe = bpf.program_mut("perf").unwrap().try_into()?;
    program.load()?;
    program.attach("security_file_open", 0)?;

    let mut perf_array = AsyncPerfEventArray::try_from(bpf.take_map("EVENTS").unwrap())?;

    for cpu_id in online_cpus()? {
        let mut buf = perf_array.open(cpu_id, None)?;
        tokio::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();
            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();

                for i in 0..events.read{
                    let buf = &mut buffers[i];
                    if let Ok(event) = parse_event(buf) {
                        let file_path = CStr::from_bytes_until_nul(&event.file_path).unwrap().to_str().unwrap();
                        let task_name = CStr::from_bytes_until_nul(&event.task_name).unwrap().to_str().unwrap();
                        println!("uid : {}, pid : {}, task_name : {}, file_path : {}", event.uid, event.pid, task_name, file_path);
                    } else {
                        eprintln!("failed to parse event");
                    }
                }
            }
        });
    }
    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
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