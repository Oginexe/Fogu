#!/usr/bin/env bash
# Size and speed of the release build, as `name value` lines: run before and after a change and
# compare. Needs cargo-bloat and a display (for the first frame).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

cargo build --release --locked -q -p fogu
bin=target/release/fogu
echo "binary_bytes $(stat -c %s "$bin")"

# biggest crates; `release-dev` keeps the symbols cargo-bloat needs (shares, not exact bytes)
cargo bloat --profile release-dev --locked -p fogu --crates -n 15 --message-format json 2>/dev/null \
    | python3 -c 'import json,sys; [print("crate_"+c["name"], c["size"]) for c in json.load(sys.stdin)["crates"]]'

times=()
for _ in 1 2 3 4 5; do
    start=$(date +%s%N)
    "$bin" --exit-after-first-frame --no-recovery >/dev/null 2>&1
    times+=($(( ($(date +%s%N) - start) / 1000000 )))
done
echo "first_frame_ms_median $(printf '%s\n' "${times[@]}" | sort -n | sed -n 3p)"

cargo test --release --locked -q -p fogu-term --test throughput -- --ignored --nocapture 2>/dev/null \
    | grep '^feed_'
