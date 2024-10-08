use std::ffi::CStr;

use aya::maps::AsyncPerfEventArray;
use aya::programs::TracePoint;
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use bytes::BytesMut;
use log::{info, warn, debug};
use tokio::signal;
use trace_point_execve_common::Event;

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
        "../../target/bpfel-unknown-none/debug/trace-point-execve"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/trace-point-execve"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program_execve: &mut TracePoint = bpf.program_mut("trace_point_execve").unwrap().try_into()?;

    program_execve.load()?;
    program_execve.attach("syscalls", "sys_enter_execve")?;

    let program_execveat: &mut TracePoint = bpf.program_mut("trace_point_execveat").unwrap().try_into()?;
    program_execveat.load()?;
    program_execveat.attach("syscalls", "sys_enter_execveat")?;

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
                        print!("pid: {}, uid: {}", event.pid, event.uid);
                        // let file_path = CStr::from_bytes_until_nul(&event.filename).unwrap().to_str().unwrap();
                        let file_path = std::str::from_utf8(&event.filename).unwrap();
                        println!(" file_path : {}", file_path);
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
