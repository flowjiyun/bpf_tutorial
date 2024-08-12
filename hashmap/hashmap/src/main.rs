use std::collections::HashMap;
use std::time::Duration;

use aya::maps::PerCpuHashMap;
use aya::programs::KProbe;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use log::{info, warn, debug};
use tokio::signal;
use aya::Pod;


#[repr(C)]
#[derive(Clone, Copy)]

pub struct FileOpenInfo {
    pub count: u64,
}

unsafe impl Pod for FileOpenInfo {}

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
        "../../target/bpfel-unknown-none/debug/hashmap"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/hashmap"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program: &mut KProbe = bpf.program_mut("hashmap").unwrap().try_into()?;
    program.load()?;
    program.attach("security_file_open", 0)?;

    let mut interval = tokio::time::interval(Duration::from_secs(3));
    info!("Waiting for Ctrl-C...");
    loop {
        tokio::select! {
            _ = interval.tick() => {
                let file_open_map: PerCpuHashMap<_, u32, FileOpenInfo> = PerCpuHashMap::try_from(bpf.map("FILE_OPEN_COUNT").unwrap())?;

                let mut total_map: HashMap<u32, u64> = HashMap::new();
                for ret in file_open_map.iter() {
                    let (uid, cpu_data) = ret?;
                    let total_cnt = cpu_data.iter().map(|info| info.count).sum::<u64>();
                    let counter = total_map.entry(uid).or_insert(0);
                    *counter += total_cnt;
                }

                for (uid, cnt) in total_map {
                    info!("uid: {}, open count: {}", uid, cnt);
                }
            }
            _ = signal::ctrl_c() => {
                break;
            }
        }
    }
    info!("Exiting...");

    Ok(())
}
