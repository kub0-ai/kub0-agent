//! Per-client output buffering for the event socket.
//!
//! Client sockets are non-blocking, and lines were written with `write_all`.
//! When the kernel buffer filled mid-line -- the greeting alone is hello +
//! 300 activity entries + a snapshot at ~420 B per connection, which passes
//! the ~208 KB default buffer at a few hundred connections, and any stall in
//! the panel does the same during normal running -- `write_all` returned
//! WouldBlock after writing PART of a line, and the daemon treated that as a
//! dead client. The panel got a truncated JSON line, then a disconnect, then
//! the same again on reconnect, and never became current.
//!
//! This keeps what did not fit and sends it when the socket drains. Only a
//! client whose backlog passes `cap` is dropped: that one has stopped reading.

use std::io::{ErrorKind, Write};

pub const DEFAULT_CAP: usize = 8 * 1024 * 1024;

#[derive(Debug)]
pub struct OutQueue {
    buf: Vec<u8>,
    cap: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Flush {
    /// Everything queued has been written.
    Drained,
    /// The socket is full; the rest waits for the next flush.
    Pending,
    /// The peer is gone, or its backlog passed the cap. Drop the client.
    Dead,
}

impl OutQueue {
    pub fn new(cap: usize) -> Self {
        Self { buf: Vec::new(), cap }
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Queue a line and write as much as the socket takes now.
    pub fn send<W: Write>(&mut self, w: &mut W, line: &str) -> Flush {
        self.buf.extend_from_slice(line.as_bytes());
        self.flush(w)
    }

    pub fn flush<W: Write>(&mut self, w: &mut W) -> Flush {
        let mut sent = 0;
        let result = loop {
            if sent == self.buf.len() {
                break Flush::Drained;
            }
            match w.write(&self.buf[sent..]) {
                Ok(0) => break Flush::Dead,
                Ok(n) => sent += n,
                Err(e) if e.kind() == ErrorKind::WouldBlock => break Flush::Pending,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(_) => break Flush::Dead,
            }
        };
        self.buf.drain(..sent);
        if result == Flush::Pending && self.buf.len() > self.cap {
            return Flush::Dead;
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    /// Accepts up to `room` bytes, then WouldBlock until given more room.
    struct Pipe {
        got: Vec<u8>,
        room: usize,
        broken: bool,
    }

    impl Write for Pipe {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            if self.broken {
                return Err(io::Error::from(ErrorKind::BrokenPipe));
            }
            if self.room == 0 {
                return Err(io::Error::from(ErrorKind::WouldBlock));
            }
            let n = b.len().min(self.room).min(7); // short writes, too
            self.got.extend_from_slice(&b[..n]);
            self.room -= n;
            Ok(n)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_full_socket_keeps_the_rest_of_the_line_instead_of_dropping_the_client() {
        let mut p = Pipe { got: vec![], room: 10, broken: false };
        let mut q = OutQueue::new(DEFAULT_CAP);
        assert_eq!(q.send(&mut p, "{\"type\":\"snapshot\",\"n\":1}\n"), Flush::Pending);
        assert_eq!(p.got.len(), 10, "the part that fitted went out");
        assert_eq!(q.send(&mut p, "{\"type\":\"tick\"}\n"), Flush::Pending, "queued behind it, in order");
        p.room = 1000;
        assert_eq!(q.flush(&mut p), Flush::Drained);
        assert_eq!(
            String::from_utf8(p.got).unwrap(),
            "{\"type\":\"snapshot\",\"n\":1}\n{\"type\":\"tick\"}\n",
            "every line arrives whole and in order"
        );
        assert!(q.is_empty());
    }

    #[test]
    fn a_client_that_stops_reading_is_dropped_at_the_cap() {
        let mut p = Pipe { got: vec![], room: 0, broken: false };
        let mut q = OutQueue::new(64);
        assert_eq!(q.send(&mut p, &"x".repeat(60)), Flush::Pending);
        assert_eq!(q.send(&mut p, &"x".repeat(10)), Flush::Dead);
    }

    #[test]
    fn a_closed_peer_is_dead() {
        let mut p = Pipe { got: vec![], room: 100, broken: true };
        let mut q = OutQueue::new(DEFAULT_CAP);
        assert_eq!(q.send(&mut p, "line\n"), Flush::Dead);
    }
}
