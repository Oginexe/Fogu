//! Throughput of `TermHandle::feed`: `scripts/metrics.sh` runs it in release mode.

#![allow(
    clippy::print_stdout,
    clippy::cast_precision_loss,
    reason = "a benchmark that prints one number"
)]

use std::time::Instant;

use fogu_term::{TermHandle, WORD_SEPARATORS};

#[test]
#[ignore = "benchmark: run by scripts/metrics.sh in release mode"]
fn feed_throughput() {
    // Compiler-like output: colours, a wide-character run and a line break per line.
    let line = "\x1b[1;32m   Compiling\x1b[0m fogu-term v0.1.6 (/src/crates/term) \
                \x1b[33mwarning\x1b[0m: unused variable `x` \u{2014} \u{65e5}\u{672c}\u{8a9e}\r\n";
    let chunk = line.repeat(64 * 1024 / line.len());
    let mut term = TermHandle::new(200, 50, 10_000, WORD_SEPARATORS);
    let total = 50 * 1024 * 1024;
    let start = Instant::now();
    let mut fed = 0;
    while fed < total {
        term.feed(chunk.as_bytes());
        fed += chunk.len();
    }
    let secs = start.elapsed().as_secs_f64();
    println!("feed_mb_per_s {:.0}", fed as f64 / secs / 1e6);
}
