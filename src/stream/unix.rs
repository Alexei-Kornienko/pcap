//! Support for asynchronous packet iteration.
//!
//! See [`Capture::stream`](super::Capture::stream).
use std::io::{self, ErrorKind};
use std::marker::Unpin;
use std::pin::Pin;
use std::task::{self, Poll};

use futures::ready;
use tokio::io::unix::AsyncFd;

use crate::Active;
use crate::{
    capture::{selectable::SelectableCapture, Activated, Capture},
    codec::PacketCodec,
    Error,
};

/// Implement Stream for async use of pcap
pub struct PacketStream<C: PacketCodec> {
    inner: AsyncFd<SelectableCapture>,
    codec: C,
}

impl<C: PacketCodec> PacketStream<C> {
    pub(crate) fn new(capture: Capture<Active>, codec: C) -> Result<Self, Error> {
        let capture = SelectableCapture::new(capture)?;
        Ok(PacketStream {
            inner: AsyncFd::new(capture)?,
            codec,
        })
    }

    /// Returns a mutable reference to the inner [`Capture`].
    ///
    /// The caller must ensure the capture will not be set to be blocking.
    pub fn capture_mut(&mut self) -> &mut Capture<Active> {
        self.inner.get_mut().get_inner_mut()
    }

    pub async fn sendpacket(&mut self, buf: &[u8]) -> Result<(), Error> {
        loop {
            let mut guard = self.inner.writable_mut().await?;

            match guard.try_io(
                |inner| match inner.get_mut().get_inner_mut().sendpacket(buf) {
                    Ok(r) => Ok(r),
                    Err(e) => match e {
                        Error::IoError(kind) => Err(std::io::Error::new(kind, "Pcap IO error")),
                        _ => panic!("Unknown error {}", e),
                    },
                },
            ) {
                Ok(result) => return result.map_err(|e| Error::IoError(e.kind())),
                Err(_would_block) => continue,
            }
        }
    }
}

impl<C: PacketCodec> Unpin for PacketStream<C> {}

impl<C: PacketCodec> futures::Stream for PacketStream<C> {
    type Item = Result<C::Item, Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut task::Context) -> Poll<Option<Self::Item>> {
        let stream = Pin::into_inner(self);
        let codec = &mut stream.codec;

        loop {
            let mut guard = ready!(stream.inner.poll_read_ready_mut(cx))?;
            match guard.try_io(
                |inner| match inner.get_mut().get_inner_mut().next_packet() {
                    Ok(p) => Ok(Ok(codec.decode(p))),
                    Err(e @ Error::TimeoutExpired) => {
                        Err(io::Error::new(io::ErrorKind::WouldBlock, e))
                    }
                    Err(e) => Ok(Err(e)),
                },
            ) {
                Ok(result) => {
                    return Poll::Ready(Some(result?));
                }
                Err(_would_block) => continue,
            }
        }
    }
}
