use crate::quic::{Request, Response};

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use futures_util::ready;
use tokio::sync::mpsc;

#[derive(Debug)]
pub struct BufReadDgram {
    receiver: mpsc::Receiver<Bytes>,
}

impl BufReadDgram {
    pub(crate) fn new(receiver: mpsc::Receiver<Bytes>) -> BufReadDgram {
        BufReadDgram {
            receiver
        }
    }
    pub async fn read_data(&mut self) -> std::result::Result<Bytes, BufReadDgramError> {
        ReadData { buf_read_dgram: self }.await
    }

    pub fn poll_read_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<Bytes, BufReadDgramError>> {
        match ready!(self.receiver.poll_recv(cx)) {
            Some(bytes) => {
                return Poll::Ready(Ok(bytes));
            }
            None => {
                return Poll::Ready(Err(BufReadDgramError::ConnectionClosed));
            }
        }
    }
}

struct ReadData<'a> {
    buf_read_dgram: &'a mut BufReadDgram,
}

impl<'a> Future for ReadData<'a> {
    type Output = std::result::Result<Bytes, BufReadDgramError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let me = self.get_mut();

        me.buf_read_dgram.poll_read_data(cx)
    }
}

#[derive(Debug)]
pub enum BufReadDgramError {
    ConnectionClosed,
}
