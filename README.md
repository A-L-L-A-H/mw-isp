# MoonWitness ISP (`mw-isp`)

Standalone Rust ISP, RADIUS (UDP 1812/1813), and FTTx control-plane service extracted from MoonWitness.

## Features

- RADIUS authentication & accounting (`1812/udp`, `1813/udp`) with delta quota and gigaword counters
- HTTP control API (`3000/tcp`) with signed control contract enforcement
- Embedded SQLite migrations via `sqlx`

## Quick Start

```bash
cp config.example.toml config.toml
cargo run
```

## Development

```bash
cargo check
cargo test
cargo build --release
```

## Docker

```bash
docker build -t mw-isp .
docker run -p 1812:1812/udp -p 1813:1813/udp -p 3000:3000 mw-isp
```

## License

AGPL-3.0-only
