use aya::maps::RingBuf;
use aya::programs::KProbe;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use log::{info, warn, debug};
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


    }
    // info!("Waiting for Ctrl-C...");
    // signal::ctrl_c().await?;
    // info!("Exiting...");

    // Ok(())
}


struct Guard<'a, T>(&'a mut PollFd<T>);
impl<T> Guard<'_, T> {
    fn inner_mut(&mut self) -> &mut T {
        let Guard(PollFd(t)) = self;
        t
    }
    fn clear_ready(&mut self) {}
}
struct PollFd<T>(T);
fn poll_fd<T>(t: T) -> PollFd<T> {PollFd(t)}
impl<T> PollFd<T> {
}