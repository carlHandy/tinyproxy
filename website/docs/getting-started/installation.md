# Installation

**tinyproxy** can be installed via pre-compiled binaries, package managers, or built from source.

## Pre-compiled Binaries

You can download the latest binaries for Linux, macOS, and Windows from the [GitHub Releases](https://github.com/carlHandy/go-tinyproxy/releases) page.

### Debian / Ubuntu (.deb)
1. Download the `.deb` package.
2. Install using `dpkg`:
   ```bash
   sudo dpkg -i tinyproxy_1.1.1_linux_amd64.deb
   ```

### RHEL / Fedora / AlmaLinux (.rpm)
1. Download the `.rpm` package.
2. Install using `rpm`:
   ```bash
   sudo rpm -i tinyproxy_1.1.1_linux_amd64.rpm
   ```

### macOS / Linux (Standalone Binary)
1. Download the `.tar.gz` archive.
2. Extract and move to your path:
   ```bash
   tar -xzf tinyproxy_1.1.1_linux_amd64.tar.gz
   sudo mv tinyproxy /usr/local/bin/
   ```

### Windows
1. Download the `.zip` archive.
2. Extract the content.
3. Use `tinyproxy.exe` from PowerShell or Command Prompt.

## Building from Source

If you have Go 1.23+ installed, you can build from source:

```bash
git clone https://github.com/carlHandy/go-tinyproxy.git
cd go-tinyproxy
go build -o tinyproxy ./cmd/tinyproxy/
sudo mv tinyproxy /usr/local/bin/
```

## Requirements

- **Go 1.23+**: Only required if building from source.
- **mkcert**: Recommended for local development to generate TLS certificates.
