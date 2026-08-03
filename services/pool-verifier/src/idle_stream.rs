//! No-progress deadline for one ingress socket (PB-27).
//!
//! PB-26 released an ingress permit only when the peer's socket reported
//! EOF or RST. A peer that connected and never spoke therefore held its
//! slot for the life of the process, and 32 such sockets locked out
//! every legitimate stream. The reported measurement: eight silent
//! sockets against a cap of eight kept a legitimate peer out for the
//! full 45 s of the probe.
//!
//! The budget here is **idle since last progress**, never total
//! connection age. That distinction is the launch gate, not a nicety: a
//! 20 MiB `raw_block_hex` line is why `MAX_INTERNAL_LINE_BYTES` is
//! 20 MiB at all, and over a slow link one line legitimately takes
//! longer than any budget an operator would set against squatters.
//! Wrapping the whole read in one `tokio::time::timeout` would reap that
//! transfer; resetting the deadline on every byte that actually moves
//! does not.
//!
//! One deadline covers both directions, because the wrapper sits under
//! `tokio::io::split` and both halves poll through it. That is what
//! catches the second reported shape, a peer that floods templates and
//! never reads its verdicts: the read side sees progress, but the
//! connection task is parked inside `write_all` against a receive window
//! the peer will never drain, so no read is polled and the deadline
//! fires on the stalled write.
//!
//! The wrapper is applied to the raw `TcpStream` before the TLS
//! acceptor, so it also covers a peer that opens TCP and never sends a
//! `ClientHello`. PB-26 takes the permit before the handshake on purpose
//! and that ordering is preserved.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, Sleep};

/// Wraps a stream with a deadline that only advances when bytes move.
pub(crate) struct IdleTimeout<S> {
    inner: S,
    idle: Duration,
    deadline: Pin<Box<Sleep>>,
    /// Set when the deadline fired, so the connection task can tell a
    /// reap from a peer that closed on its own and count it. Shared with
    /// the accept loop because the stream itself is consumed by
    /// `tokio::io::split` and by the TLS acceptor.
    reaped: Arc<AtomicBool>,
}

impl<S> IdleTimeout<S> {
    /// Wrap `inner`, arming the first deadline at `idle` from now.
    pub(crate) fn new(inner: S, idle: Duration, reaped: Arc<AtomicBool>) -> Self {
        Self {
            inner,
            idle,
            deadline: Box::pin(tokio::time::sleep(idle)),
            reaped,
        }
    }

    /// Bytes moved: push the deadline out.
    fn made_progress(&mut self) {
        let next = Instant::now() + self.idle;
        self.deadline.as_mut().reset(next);
    }

    /// The inner stream is not ready. Either the budget is spent, in
    /// which case the connection ends with a `TimedOut` error the
    /// caller surfaces, or the timer registers the waker and we stay
    /// pending.
    fn poll_no_progress(&mut self, cx: &mut Context<'_>) -> Poll<io::Error> {
        match self.deadline.as_mut().poll(cx) {
            Poll::Ready(()) => {
                self.reaped.store(true, Ordering::Relaxed);
                Poll::Ready(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "ingress connection made no progress within the idle budget",
                ))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for IdleTimeout<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                // A ready read with nothing filled is EOF, which is not
                // progress; the caller ends the connection on it anyway.
                if buf.filled().len() > before {
                    this.made_progress();
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => this.poll_no_progress(cx).map(Err),
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for IdleTimeout<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => {
                if n > 0 {
                    this.made_progress();
                }
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => this.poll_no_progress(cx).map(Err),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_flush(cx) {
            // Deliberately no `made_progress` here. A `TcpStream` flush
            // is a no-op that returns ready without moving a byte, so
            // resetting on it would let a caller that flushes in a loop
            // hold the deadline open forever.
            Poll::Ready(r) => Poll::Ready(r),
            Poll::Pending => this.poll_no_progress(cx).map(Err),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_shutdown(cx) {
            Poll::Ready(r) => Poll::Ready(r),
            Poll::Pending => this.poll_no_progress(cx).map(Err),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::IdleTimeout;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    /// A peer that connects and sends nothing must be ended by the
    /// deadline, and the flag must say the deadline is why.
    #[tokio::test]
    async fn silent_peer_hits_the_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();

        let reaped = Arc::new(AtomicBool::new(false));
        let mut stream = IdleTimeout::new(server, Duration::from_millis(150), reaped.clone());

        // Outer bound so a budget that never fires fails this test
        // instead of hanging the suite.
        let mut buf = [0u8; 16];
        let err = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
            .await
            .expect("the deadline never fired; a silent peer would hold its slot forever")
            .expect_err("must time out");
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        assert!(
            reaped.load(Ordering::Relaxed),
            "the reap must be reportable"
        );
    }

    /// The launch-gate semantics in miniature: a peer that drips bytes
    /// for several multiples of the budget, never pausing longer than
    /// the budget, must not be reaped. A total-connection-age budget
    /// fails this.
    #[tokio::test]
    async fn drip_that_outlasts_the_budget_is_not_reaped() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();

        let idle = Duration::from_millis(200);
        let reaped = Arc::new(AtomicBool::new(false));
        let mut stream = IdleTimeout::new(server, idle, reaped.clone());

        let writer = tokio::spawn(async move {
            for _ in 0..10 {
                tokio::time::sleep(Duration::from_millis(120)).await;
                if client.write_all(b"x").await.is_err() {
                    break;
                }
            }
            // Hold the socket open so the read below ends on the
            // deadline rather than on EOF.
            tokio::time::sleep(Duration::from_secs(5)).await;
        });

        let mut got = 0usize;
        let mut buf = [0u8; 4];
        while got < 10 {
            let n = stream
                .read(&mut buf)
                .await
                .expect("drip must not be reaped");
            assert!(n > 0, "unexpected EOF");
            got += n;
        }
        assert!(
            !reaped.load(Ordering::Relaxed),
            "a peer making progress must never be reaped"
        );
        writer.abort();
    }

    /// A write that cannot drain must also hit the deadline, which is
    /// the peer-that-never-reads shape.
    #[tokio::test]
    async fn stalled_write_hits_the_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();

        let reaped = Arc::new(AtomicBool::new(false));
        let mut stream = IdleTimeout::new(server, Duration::from_millis(150), reaped.clone());

        // Push until the client's unread receive window and the server's
        // send buffer are both full, then the write parks.
        let payload = vec![0u8; 256 * 1024];
        let err = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                match stream.write_all(&payload).await {
                    Ok(()) => {}
                    Err(e) => break e,
                }
            }
        })
        .await
        .expect("the deadline never fired on a write the peer will never drain");
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        assert!(reaped.load(Ordering::Relaxed));
        drop(client);
    }
}
