//! Bounded, single-client UDP fault injector. Test-only; never a production relay.
use std::{
    io,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{net::UdpSocket, task::JoinHandle, time::Instant};

#[derive(Default)]
pub struct FaultStats {
    pub dropped: AtomicUsize,
    pub reordered: AtomicUsize,
    pub duplicated: AtomicUsize,
    pub forwarded: AtomicUsize,
}

pub struct FaultProxy {
    pub addr: SocketAddr,
    pub stats: Arc<FaultStats>,
    armed: Arc<AtomicBool>,
    task: JoinHandle<()>,
}

impl FaultProxy {
    pub async fn spawn(backend: SocketAddr) -> io::Result<Self> {
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let addr = socket.local_addr()?;
        let stats = Arc::new(FaultStats::default());
        let armed = Arc::new(AtomicBool::new(false));
        let counters = stats.clone();
        let enabled = armed.clone();
        let task = tokio::spawn(async move {
            let mut client = None;
            let mut buffer = vec![0; 65_536];
            let mut counts = [0usize; 2];
            // At most one held datagram per direction, flushed even if no successor arrives.
            let mut held: [Option<(Vec<u8>, SocketAddr, Instant)>; 2] = [None, None];
            let mut tick = tokio::time::interval(Duration::from_millis(10));
            loop {
                tokio::select! {
                    _ = tick.tick() => {
                        for pending in &mut held {
                            if pending.as_ref().is_some_and(|(_, _, at)| at.elapsed() >= Duration::from_millis(20)) {
                                let (bytes, target, _) = pending.take().unwrap();
                                socket.send_to(&bytes, target).await.unwrap();
                                counters.forwarded.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                    packet = socket.recv_from(&mut buffer) => {
                        let Ok((size, source)) = packet else { break };
                        let (direction, target) = if source == backend {
                            let Some(target) = client else { continue };
                            (1, target)
                        } else {
                            // This fixture intentionally supports exactly one client.
                            if let Some(expected) = client { assert_eq!(source, expected); }
                            client = Some(source);
                            (0, backend)
                        };
                        let fault = enabled.load(Ordering::Relaxed);
                        // Force multi-datagram transfer, including on loopback's huge MTU.
                        if fault && size > 1232 {
                            counters.dropped.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                        if fault {
                            counts[direction] += 1;
                            match counts[direction] % 11 {
                                1 => {
                                    counters.dropped.fetch_add(1, Ordering::Relaxed);
                                    continue;
                                }
                                3 if held[direction].is_none() => {
                                    held[direction] = Some((buffer[..size].to_vec(), target, Instant::now()));
                                    continue;
                                }
                                6 => {
                                    socket.send_to(&buffer[..size], target).await.unwrap();
                                    counters.duplicated.fetch_add(1, Ordering::Relaxed);
                                }
                                _ => {}
                            }
                        }
                        socket.send_to(&buffer[..size], target).await.unwrap();
                        counters.forwarded.fetch_add(1, Ordering::Relaxed);
                        if let Some((bytes, target, _)) = held[direction].take() {
                            socket.send_to(&bytes, target).await.unwrap();
                            counters.forwarded.fetch_add(1, Ordering::Relaxed);
                            counters.reordered.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            }
        });
        Ok(Self {
            addr,
            stats,
            armed,
            task,
        })
    }

    pub fn arm(&self) {
        self.armed.store(true, Ordering::Relaxed);
    }

    pub fn assert_exercised(&self) {
        assert!(!self.task.is_finished(), "fault relay exited unexpectedly");
        assert!(
            self.stats.dropped.load(Ordering::Relaxed) > 0,
            "no loss injected"
        );
        assert!(
            self.stats.reordered.load(Ordering::Relaxed) > 0,
            "no reordering injected"
        );
        assert!(
            self.stats.duplicated.load(Ordering::Relaxed) > 0,
            "no duplication injected"
        );
    }
}

impl Drop for FaultProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}
