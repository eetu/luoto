//! Framing of IP packets on a byte stream: a 2-byte big-endian length, then the packet. The
//! dev's tun and the gate's carry their packets this way over the unix sockets the host joins.

/// The largest length the 2-byte header can carry.
pub const MAX_FRAME: usize = u16::MAX as usize;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    #[error("frame of {len} bytes exceeds the maximum of {max}")]
    Oversize { len: usize, max: usize },
    #[error("empty frame")]
    Empty,
}

/// The header for a packet of `len` bytes.
pub fn header(len: usize) -> Result<[u8; 2], FrameError> {
    if len == 0 {
        return Err(FrameError::Empty);
    }
    let n = u16::try_from(len).map_err(|_| FrameError::Oversize {
        len,
        max: MAX_FRAME,
    })?;
    Ok(n.to_be_bytes())
}

/// Append `packet`, framed, to `out`.
pub fn encode(packet: &[u8], out: &mut Vec<u8>) -> Result<(), FrameError> {
    out.extend_from_slice(&header(packet.len())?);
    out.extend_from_slice(packet);
    Ok(())
}

/// Splits a byte stream back into packets, whatever the chunks it arrives in. A frame longer
/// than `max` or empty is an error: the stream is out of step and must be dropped.
pub struct Decoder {
    buf: Vec<u8>,
    pos: usize,
    max: usize,
}

impl Decoder {
    pub fn new(max: usize) -> Self {
        Decoder {
            buf: Vec::new(),
            pos: 0,
            max: max.min(MAX_FRAME),
        }
    }

    /// Add bytes read from the stream.
    pub fn push(&mut self, data: &[u8]) {
        if self.pos > 0 {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
        self.buf.extend_from_slice(data);
    }

    /// The next whole packet, or `None` until more bytes arrive.
    pub fn next_frame(&mut self) -> Result<Option<&[u8]>, FrameError> {
        let rest = &self.buf[self.pos..];
        let Some(head) = rest.first_chunk::<2>() else {
            return Ok(None);
        };
        let len = usize::from(u16::from_be_bytes(*head));
        if len == 0 {
            return Err(FrameError::Empty);
        }
        if len > self.max {
            return Err(FrameError::Oversize { len, max: self.max });
        }
        if rest.len() < 2 + len {
            return Ok(None);
        }
        let start = self.pos + 2;
        self.pos = start + len;
        Ok(Some(&self.buf[start..start + len]))
    }

    /// Bytes held that are not yet a whole packet.
    pub fn pending(&self) -> usize {
        self.buf.len() - self.pos
    }
}

/// Whether `packet` is an IPv4 packet from `src`.
pub fn ipv4_from(packet: &[u8], src: std::net::Ipv4Addr) -> bool {
    packet.len() >= 20 && packet[0] >> 4 == 4 && packet[12..16] == src.octets()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frames(d: &mut Decoder) -> Result<Vec<Vec<u8>>, FrameError> {
        let mut out = Vec::new();
        while let Some(f) = d.next_frame()? {
            out.push(f.to_vec());
        }
        Ok(out)
    }

    #[test]
    fn round_trip_in_any_chunks() {
        let packets: Vec<Vec<u8>> = (1..=40u8).map(|n| vec![n; usize::from(n) * 30]).collect();
        let mut stream = Vec::new();
        for p in &packets {
            encode(p, &mut stream).unwrap();
        }
        for chunk in [1, 2, 3, 7, 1400, stream.len()] {
            let mut d = Decoder::new(1400);
            let mut got = Vec::new();
            for c in stream.chunks(chunk) {
                d.push(c);
                got.extend(frames(&mut d).unwrap());
            }
            assert_eq!(got, packets, "chunk {chunk}");
            assert_eq!(d.pending(), 0);
        }
    }

    #[test]
    fn partial_frame_waits() {
        let mut d = Decoder::new(100);
        d.push(&[0, 3, 1, 2]);
        assert_eq!(d.next_frame(), Ok(None));
        assert_eq!(d.pending(), 4);
        d.push(&[3]);
        assert_eq!(d.next_frame(), Ok(Some(&[1u8, 2, 3][..])));
    }

    #[test]
    fn oversize_and_empty_are_errors() {
        let mut d = Decoder::new(1400);
        d.push(&1401u16.to_be_bytes());
        assert_eq!(
            d.next_frame(),
            Err(FrameError::Oversize {
                len: 1401,
                max: 1400
            })
        );
        let mut d = Decoder::new(1400);
        d.push(&[0, 0]);
        assert_eq!(d.next_frame(), Err(FrameError::Empty));
        assert_eq!(header(0), Err(FrameError::Empty));
        assert!(matches!(
            encode(&vec![0; MAX_FRAME + 1], &mut Vec::new()),
            Err(FrameError::Oversize { .. })
        ));
        assert_eq!(header(MAX_FRAME), Ok([0xff, 0xff]));
    }

    #[test]
    fn only_ipv4_from_the_source_passes() {
        let src = std::net::Ipv4Addr::new(169, 254, 1, 2);
        let mut p = [0u8; 20];
        p[0] = 0x45;
        p[12..16].copy_from_slice(&src.octets());
        assert!(ipv4_from(&p, src));
        p[15] = 9;
        assert!(!ipv4_from(&p, src), "another source");
        p[15] = 2;
        p[0] = 0x60;
        assert!(!ipv4_from(&p, src), "IPv6");
        assert!(!ipv4_from(&p[..19], src), "short");
    }
}
