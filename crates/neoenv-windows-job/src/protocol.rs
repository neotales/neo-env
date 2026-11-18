//! Bounded frame codec only. It does not authenticate peers or perform I/O.
//!
//! Task payloads can contain secrets. Do not log frame bodies.

use std::io;

const MAGIC: &[u8; 4] = b"NWJ1";
const HEADER: usize = 9;
/// Maximum body bytes permitted in one control frame.
pub const MAX_BODY: usize = 65_536;

/// A protocol message kind. The version is encoded in the magic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Kind {
    /// A non-secret handshake message.
    Hello = 1,
    /// A request, which may contain sensitive data.
    Request = 2,
    /// A result or error response.
    Result = 3,
    /// A host-owned pipe handle offered to the launcher.
    Pipe = 4,
    /// Acknowledges that the offered pipe was duplicated.
    PipeAck = 5,
    /// Confirms the launcher's temporary source handle was closed.
    PipeDone = 6,
    /// Confirms the launcher received completion and still owns its pipe.
    PipeConfirm = 7,
}

/// Encode one bounded frame. The body is copied, but never logged.
pub fn encode(kind: Kind, body: &[u8]) -> io::Result<Vec<u8>> {
    if body.len() > MAX_BODY {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "control frame too large",
        ));
    }
    let mut encoded = Vec::with_capacity(HEADER + body.len());
    encoded.extend_from_slice(MAGIC);
    encoded.push(kind as u8);
    encoded.extend_from_slice(&(body.len() as u32).to_le_bytes());
    encoded.extend_from_slice(body);
    Ok(encoded)
}

/// Parse one frame from a bounded stream buffer.
///
/// Returns `None` when more data is required. The returned body borrows the
/// caller's buffer; its contents are deliberately absent from diagnostics.
pub fn decode(input: &[u8]) -> io::Result<Option<(Kind, &[u8], usize)>> {
    if input.len() < HEADER {
        return Ok(None);
    }
    if &input[..4] != MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid control protocol version",
        ));
    }
    let kind = match input[4] {
        1 => Kind::Hello,
        2 => Kind::Request,
        3 => Kind::Result,
        4 => Kind::Pipe,
        5 => Kind::PipeAck,
        6 => Kind::PipeDone,
        7 => Kind::PipeConfirm,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid control message kind",
            ));
        }
    };
    let length = u32::from_le_bytes(input[5..9].try_into().expect("fixed header")) as usize;
    if length > MAX_BODY {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "control frame too large",
        ));
    }
    let end = HEADER + length;
    if input.len() < end {
        return Ok(None);
    }
    Ok(Some((kind, &input[HEADER..end], end)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip_incrementally_without_exposing_contents() {
        let frame = encode(Kind::Request, b"opaque").unwrap();
        for end in 0..frame.len() {
            assert!(decode(&frame[..end]).unwrap().is_none());
        }
        let (kind, body, consumed) = decode(&frame).unwrap().unwrap();
        assert_eq!(kind, Kind::Request);
        assert_eq!(body, b"opaque");
        assert_eq!(consumed, frame.len());
    }

    #[test]
    fn rejects_unknown_version_kind_and_oversize() {
        let mut frame = encode(Kind::Hello, b"").unwrap();
        frame[3] = b'2';
        assert!(decode(&frame).is_err());
        frame[3] = b'1';
        frame[4] = 255;
        assert!(decode(&frame).is_err());
        frame[4] = 1;
        frame[5..9].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(decode(&frame).is_err());
        assert!(encode(Kind::Request, &vec![0; MAX_BODY + 1]).is_err());
    }

    #[test]
    fn parses_one_frame_without_consuming_the_next() {
        let mut bytes = encode(Kind::Hello, b"a").unwrap();
        let next = encode(Kind::Result, b"b").unwrap();
        bytes.extend_from_slice(&next);
        let (_, _, consumed) = decode(&bytes).unwrap().unwrap();
        assert_eq!(decode(&bytes[consumed..]).unwrap().unwrap().0, Kind::Result);
    }
}
