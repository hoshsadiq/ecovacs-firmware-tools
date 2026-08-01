# Ecovacs Firmware Tools

A collection of tools to download, decrypt, modify, repack, and serve Ecovacs DEEBOT firmware images.

> Based on reverse engineering of the Ecovacs DEEBOT OZMO T8 AIVI and T20 Omni firmware format.

## Features

- **Download** firmware images from Ecovacs servers using product info from [robotinfo.dev](https://robotinfo.dev)
- **Decrypt** encrypted firmware sections (AES-128-CBC with device-specific key derivation)
- **Repack** modified sections back into encrypted firmware images
- **OTA Serve** modified firmware directly to the robot over LAN (HTTPS + MQTT + DNS)

## Installation

```bash
go install github.com/denysvitali/ecovacs-firmware-tools@latest
```

Or build from source:

```bash
git clone https://github.com/denysvitali/ecovacs-firmware-tools.git
cd ecovacs-firmware-tools
go build -o ecovacs-fw .
```

## Commands

### Download Firmware

Download firmware images from Ecovacs servers:

```bash
# List available products and firmware versions
ecovacs-fw download --list-products

# Download latest firmware for a specific product
ecovacs-fw download --product-id 659yh8

# Download specific firmware version
ecovacs-fw download --product-id 659yh8 --firmware-version 1.7.8
```

### Decrypt Firmware

Decrypt encrypted firmware sections:

```bash
# Decrypt with default parameters (productId: 659yh8, platform: px30)
ecovacs-fw decrypt firmware.bin

# Decrypt with custom device parameters
ecovacs-fw decrypt --device-id 659yh8 --platform px30 firmware.bin

# Specify output directory
ecovacs-fw decrypt --output ./decrypted firmware.bin

# List sections without decrypting
ecovacs-fw decrypt --list-sections firmware.bin
```

Decrypted sections are saved with a `.ecovacs_sections.json` metadata file needed for repacking.

### Repack Firmware

Re-encrypt modified sections into a firmware image:

```bash
# Repack a decrypted directory back into firmware
ecovacs-fw repack decrypted/ modified-firmware.bin

# Override manifest fields during repack
ecovacs-fw repack decrypted/ modified-firmware.bin \
  --fw-ver "1.27.0+custom" \
  --release-date "2025-08-01-12:00:00"
```

Available flags:

| Flag | Description |
|------|-------------|
| `--fw-ver` | Override firmware version (must be >= current for OTA acceptance) |
| `--hw-ver` | Override hardware version |
| `--product` | Override product codename (must match robot's product) |
| `--release-date` | Override release date (format: YYYY-MM-DD-HH:MM:SS) |

The manifest section is space-padded to match the original decrypted size before encryption. All other sections must not exceed their original encrypted size (one AES block of slack is available per section).

### OTA Serve

Serve modified firmware directly to the robot over LAN. Handles HTTPS (firmware download), MQTT (shell command injection), and DNS (domain redirection):

```bash
# HTTPS only (robot must already be pointed at your server)
ecovacs-fw ota-serve --fw modified-firmware.bin

# Full stack: DNS + MQTT + HTTPS (robot auto-connects, gets told to OTA)
ecovacs-fw ota-serve --fw modified-firmware.bin --mqtt --dns --ip 192.168.1.50

# Custom shell command instead of default OTA trigger
ecovacs-fw ota-serve --fw modified-firmware.bin --mqtt --ip 192.168.1.50 \
  --cmd "wget -q https://192.168.1.50/fw.bin -O /tmp/fw.bin && fw_cut.sh /tmp/fw.bin"

# Custom upstream DNS resolver
ecovacs-fw ota-serve --fw modified-firmware.bin --dns --upstream 192.168.1.1:53
```

Available flags:

| Flag | Default | Description |
|------|---------|-------------|
| `--fw` | (required) | Firmware binary to serve |
| `--addr` | `:443` | HTTPS listen address |
| `--cert` / `--key` | auto | TLS certificate (self-signed generated if omitted) |
| `--fw-ver` | | Firmware version to advertise |
| `--product` | | Product codename (auto-read from `--manifest` if omitted) |
| `--manifest` | | Path to manifest.json for auto product/version |
| `--force` | false | Always claim update available |
| `--build-num` | 0 | Build number |
| `--mqtt` | false | Enable MQTT shell command server |
| `--dns` | false | Enable DNS redirect for ecouser.net/ecovacs.com |
| `--ip` | | Your machine's LAN IP (required for --mqtt/--dns) |
| `--cmd` | | Custom shell command (default: download + fw_cut.sh) |
| `--upstream` | `8.8.8.8:53` | Upstream DNS for non-Ecovacs queries |

#### How OTA Serve Works

1. Robot connects to `mq.ecouser.net:8883` (MQTT over TLS, no cert pinning)
2. DNS server redirects `mq.ecouser.net` and `portal.ecouser.net` to your machine
3. MQTT broker accepts the connection (anonymous auth) and sends a shell command
4. Robot executes the command as root (downloads firmware, runs `fw_cut.sh`)
5. Robot downloads firmware from your HTTPS server
6. Firmware is flashed to the inactive A/B partition, robot reboots

The robot's A/B dual-boot system means a bad flash won't brick the device — it falls back to the previous working partition.

## How It Works

Ecovacs firmware images consist of multiple encrypted sections:

1. Each section is encrypted using AES-128-CBC
2. The encryption key and IV are derived from the section type and size using a format string found in the robot's `fw` binary, combined via base64 + SHA-256
3. The manifest section contains firmware metadata (version, product ID, etc.)
4. Firmware updates are delivered via OTA using HTTPS with a signed JSON manifest

### Firmware Structure

```
Firmware Image
├── Manifest Section (JSON, encrypted, space-padded)
├── Pre-upgrade Script (encrypted)
├── Boot Image (encrypted)
├── Root Filesystem (encrypted squashfs)
├── MCU Firmware (encrypted)
├── MCU Station Firmware (encrypted)
├── SL Firmware (encrypted)
├── DSP Files (encrypted, optional)
└── Post-upgrade Script (encrypted)
```

## Development

```bash
# Run tests
go test ./...

# Build
go build -o ecovacs-fw .
```

## Related Projects

- [robotinfo.dev](https://robotinfo.dev) - Ecovacs product and firmware database
- [Bumper](https://github.com/bmartin5692/bumper) - Self-hosted Ecovacs cloud server

## License

MIT

## Author

Denys Vitali (@denysvitali)
