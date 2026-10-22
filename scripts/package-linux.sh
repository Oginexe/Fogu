#!/usr/bin/env bash
# Builds a portable Linux x86_64 release and packs it for testers:
#   dist/Fogu-<version>-linux-x86_64.tar.gz  (binary, icons, .desktop entry, install.sh)
# The build runs in the manylinux_2_28 image (AlmaLinux 8, glibc 2.28) through Docker, so the
# binary starts on Debian 10+, Ubuntu 20.04+, RHEL/Alma/Rocky 8+, Fedora, Arch and newer; the
# release built on this machine needs the host's much newer glibc. Needs: docker, cargo-about
# (`cargo install --locked --features cli cargo-about@0.9.2`). Downloads stay in the `fogu-cargo` volume between runs.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
toolchain=$(sed -n 's/^channel = "\(.*\)"/\1/p' rust-toolchain.toml)
image="fogu-build:manylinux228-$toolchain"
name="Fogu-$version-linux-x86_64"

docker build --network host -q -t "$image" - <<EOF >/dev/null
FROM quay.io/pypa/manylinux_2_28_x86_64
ENV RUSTUP_HOME=/opt/rustup PATH=/opt/cargo/bin:\$PATH
RUN curl -sSf https://sh.rustup.rs | CARGO_HOME=/opt/cargo sh -s -- -y --profile minimal \
        --default-toolchain $toolchain
EOF

# Root in the container: the output is handed back to the caller's uid at the end.
docker run --rm --network host -v "$PWD":/src -v fogu-cargo:/cargo-home -w /src \
    -e CARGO_HOME=/cargo-home -e CARGO_TARGET_DIR=/src/target/compat "$image" \
    sh -c "cargo build --release --locked -p fogu && chown -R $(id -u):$(id -g) target/compat"

bin=target/compat/release/fogu
needed=$(objdump -T "$bin" | grep -o 'GLIBC_[0-9.]*' | sort -Vu | tail -1)
echo "Built $bin (needs $needed)"

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
mkdir -p "$stage/$name/icons"
install -m755 "$bin" "$stage/$name/fogu"
cp assets/icons/fogu-{48,128,256,512}.png "$stage/$name/icons/"
cp assets/fogu.desktop "$stage/$name/"
cp LICENSE THIRD_PARTY_LICENSES assets/fonts/*-LICENSE.txt "$stage/$name/"
cargo about generate --locked -m crates/app/Cargo.toml about.hbs -o "$stage/$name/THIRD_PARTY_CRATES"
cat > "$stage/$name/install.sh" <<'EOF'
#!/usr/bin/env bash
# Installs Fogu for the current user (no root): ~/.local/bin, menu entry, icons.
#   ./install.sh              install or update
#   ./install.sh --uninstall  remove it
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
bin_dir="$HOME/.local/bin"
data_dir="${XDG_DATA_HOME:-$HOME/.local/share}"
if [[ "${1:-}" == "--uninstall" ]]; then
    rm -f "$bin_dir/fogu" "$data_dir/applications/fogu.desktop"
    rm -f "$data_dir"/icons/hicolor/*/apps/fogu.png
    echo "Fogu removed."
    exit 0
fi
install -Dm755 fogu "$bin_dir/fogu"
for s in 48 128 256 512; do
    install -Dm644 "icons/fogu-$s.png" "$data_dir/icons/hicolor/${s}x${s}/apps/fogu.png"
done
mkdir -p "$data_dir/applications"
sed "s|^Exec=.*|Exec=$bin_dir/fogu|" fogu.desktop > "$data_dir/applications/fogu.desktop"
command -v update-desktop-database >/dev/null && update-desktop-database "$data_dir/applications" || true
command -v gtk-update-icon-cache >/dev/null && gtk-update-icon-cache -qtf "$data_dir/icons/hicolor" || true
echo "Installed: $bin_dir/fogu (and a \"Fogu\" entry in the application menu)."
EOF
chmod 755 "$stage/$name/install.sh"
cat > "$stage/$name/README.txt" <<EOF
Fogu $version — test build for Linux x86_64 (needs $needed or newer).

Install:    ./install.sh          then start "Fogu" from the menu, or run ~/.local/bin/fogu
Try only:   ./fogu
Uninstall:  ./install.sh --uninstall

Settings live in ~/.config/fogu/config.toml, logs in ~/.local/state/fogu/.
EOF
mkdir -p dist
tar -C "$stage" -czf "dist/$name.tar.gz" "$name"
echo "Packed dist/$name.tar.gz ($(du -h "dist/$name.tar.gz" | cut -f1))"
