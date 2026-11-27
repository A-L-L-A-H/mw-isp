# mw-isp — Rust ISP, RADIUS, and FTTx control-plane service.

**Repository:** [`A-L-L-A-H/mw-isp`](https://github.com/A-L-L-A-H/mw-isp) · **Stack:** Rust 1.89 · axum · tokio · SQLite

## What it does

Provides RADIUS authentication and accounting with delta quotas plus a signed HTTP control contract.

## Quick start

```bash
cp config.example.toml config.toml
cargo run
```

## Verify

```bash
cargo check
cargo test
cargo build --release
```

## Configuration

- **Port:** 1812/udp, 1813/udp, 3000/tcp
- **Key configuration:** config.toml · RADIUS clients

```bash
docker build -t mw-isp .
docker run -p 1812:1812/udp -p 1813:1813/udp -p 3000:3000 mw-isp
```

## Notes

Replace the example RADIUS secret and admin token before any non-local deployment. License: AGPL-3.0-only.
