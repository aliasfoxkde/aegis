//! Bounded newline framing shared by the wire servers.
//!
//! `aegis-mcp` (stdio) and `aegis-daemon` (Unix socket) both speak a
//! newline-delimited JSON protocol, and both must cap frame size: an
//! unbounded line read grows its buffer without limit, so a single
//! authorized peer could exhaust server memory with one line. This
//! module is that cap and its reader, written once.

use tokio::io::{AsyncBufRead, AsyncBufReadExt};

/// Upper bound on one request frame (the JSON line, newline excluded).
///
/// Generous enough for any plausible `scan_string` payload, far below
/// exhaustion territory.
pub const MAX_FRAME_BYTES: usize = 10 * 1024 * 1024;

/// What [`read_bounded_line`] produced.
#[derive(Debug, PartialEq, Eq)]
pub enum FrameRead {
    /// A complete line (a final line without its newline still counts).
    Line,
    /// The peer closed the connection with nothing pending.
    Eof,
    /// The pending line is longer than the configured frame cap.
    Oversize,
}

/// Read one newline-terminated frame without buffering more than the cap.
///
/// Walks [`AsyncBufReadExt::fill_buf`] chunks instead of growing an
/// unbounded buffer, and stops at `max_bytes`. Bytes that are not valid
/// UTF-8 become replacement characters, which the JSON parser then
/// rejects — a parse-error response beats silently dropping the
/// connection.
///
/// # Errors
/// Propagates transport failures; the caller ends the session.
pub async fn read_bounded_line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    max_bytes: usize,
    out: &mut String,
) -> std::io::Result<FrameRead> {
    out.clear();
    let mut buffered = 0usize;
    loop {
        let (line_complete, chunk_len) = {
            let available = reader.fill_buf().await?;
            if available.is_empty() {
                // A final partial line is still a frame; nothing pending
                // means the peer closed the connection.
                return Ok(if buffered == 0 {
                    FrameRead::Eof
                } else {
                    FrameRead::Line
                });
            }
            if let Some(end) = available.iter().position(|&byte| byte == b'\n') {
                if buffered + end > max_bytes {
                    return Ok(FrameRead::Oversize);
                }
                out.push_str(&String::from_utf8_lossy(&available[..end]));
                (true, end + 1)
            } else {
                if buffered + available.len() > max_bytes {
                    return Ok(FrameRead::Oversize);
                }
                out.push_str(&String::from_utf8_lossy(available));
                buffered += available.len();
                (false, available.len())
            }
        };
        reader.consume(chunk_len);
        if line_complete {
            return Ok(FrameRead::Line);
        }
    }
}

#[cfg(all(test, feature = "tokio"))]
mod tests {
    use super::*;

    /// Drive `read_bounded_line` over an in-memory duplex; the tiny buffer
    /// capacity forces `fill_buf` to hand back partial chunks, exercising
    /// the no-newline-yet accumulation path.
    //
    // Test-only helper, but the expects live inside a `tokio::spawn`
    // closure, which clippy's test-function analysis cannot see into.
    #[allow(clippy::expect_used)]
    async fn read_line_over_duplex(input: &[u8], cap: usize) -> std::io::Result<FrameRead> {
        let (mut client, server) = tokio::io::duplex(64);
        let mut reader = tokio::io::BufReader::new(server);
        let input = input.to_vec();
        let writer_task = tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            client.write_all(&input).await.expect("write input");
        });

        let mut line = String::new();
        let outcome = read_bounded_line(&mut reader, cap, &mut line).await;
        writer_task.await.expect("writer task");
        outcome
    }

    #[tokio::test]
    async fn bounded_reader_accepts_a_line_within_the_cap() {
        let outcome = read_line_over_duplex(b"{\"method\":\"ping\"}\n", 64)
            .await
            .expect("read succeeds");
        assert_eq!(outcome, FrameRead::Line);
    }

    #[tokio::test]
    async fn bounded_reader_accepts_a_line_exactly_at_the_cap() {
        let mut input = vec![b'a'; 32];
        input.push(b'\n');
        let outcome = read_line_over_duplex(&input, 32)
            .await
            .expect("read succeeds");
        assert_eq!(outcome, FrameRead::Line);
    }

    #[tokio::test]
    async fn bounded_reader_reports_oversize_frames() {
        let input = vec![b'0'; 65]; // one past the cap, newline never arrives
        let outcome = read_line_over_duplex(&input, 64).await;
        assert_eq!(outcome.expect("read succeeds"), FrameRead::Oversize);
    }

    #[tokio::test]
    async fn bounded_reader_reports_oversize_even_when_newline_follows() {
        let mut input = vec![b'0'; 65];
        input.push(b'\n');
        let outcome = read_line_over_duplex(&input, 64).await;
        assert_eq!(outcome.expect("read succeeds"), FrameRead::Oversize);
    }

    #[tokio::test]
    async fn bounded_reader_treats_eof_with_pending_bytes_as_a_line() {
        let outcome = read_line_over_duplex(b"{\"method\":\"ping\"}", 64)
            .await
            .expect("read succeeds");
        assert_eq!(outcome, FrameRead::Line);
    }

    #[tokio::test]
    async fn bounded_reader_reports_eof_on_empty_input() {
        let outcome = read_line_over_duplex(b"", 64).await;
        assert_eq!(outcome.expect("read succeeds"), FrameRead::Eof);
    }

    #[tokio::test]
    async fn bounded_reader_accumulates_across_partial_chunks() {
        // Larger than the 64-byte duplex buffer and newline-free until the
        // end, so the reader must accumulate several fill_buf chunks.
        let mut input = vec![b'x'; 300];
        input.push(b'\n');
        let outcome = read_line_over_duplex(&input, 1024)
            .await
            .expect("read succeeds");
        assert_eq!(outcome, FrameRead::Line);
    }
}
