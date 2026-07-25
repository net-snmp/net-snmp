# CI and local testing

## GitHub Actions

Defined in `.github/workflows/buildtest.yml`. On every push and pull request it
runs the matrix of modes below on `ubuntu-latest` (and `macos-latest` for
`regular`). The scripts it calls are:

| Script | Purpose |
|--------|---------|
| `ci/install.sh` | Install build dependencies (apt/brew/pkg) |
| `ci/build.sh` | Configure and compile |
| `ci/test.sh` | Run the test suite |

`ci/install.sh` is the single source of truth for build dependencies — it is
also used by the local Docker workflow below.

### Supported modes

| Mode | What it tests |
|------|--------------|
| `regular` | Default build, all optional features enabled |
| `developer` | Same as regular with extra compiler warnings |
| `disable-ipv6` | Build without IPv6 support |
| `disable-set` | Build without SNMP SET support |
| `mini` | Minimalist/mini-agent build |
| `read-only` | Read-only agent build |
| `without-nl` | Build without netlink |
| `wolfssl` | Replace OpenSSL with WolfSSL |
| `Android` | Cross-compile for Android (needs NDK) |

---

## Local testing with Docker

The Docker workflow mirrors GitHub Actions but runs on your machine.
`wolfssl` and `Android` are not supported locally (they require extra
pre-built dependencies).

### One-time setup — build the deps image

```sh
docker build -f ci/Dockerfile.deps -t net-snmp-deps .
```

The deps image is built from `ci/Dockerfile.deps`, which installs packages by
running `ci/install.sh`. The image is **automatically rebuilt** by
`ci/docker-ci.sh` whenever `ci/Dockerfile.deps` or `ci/install.sh` changes.

### Run the full matrix

```sh
ci/docker-ci.sh
```

Runs all supported modes sequentially. Full output is logged to
`/tmp/net-snmp-ci/<mode>.log`. Only warnings and errors are printed to the
terminal; a clean build produces a single `PASS` line per mode.

### Run specific modes

```sh
ci/docker-ci.sh regular developer
ci/docker-ci.sh mini
```

### Interactive shell — fastest inner loop

Mount the source into a running container and iterate without rebuilding:

```sh
docker run --rm -it -v $(pwd):/src net-snmp-deps bash
```

Inside the container:

```sh
./configure --with-defaults --disable-embedded-perl --without-perl-modules 
make -j$(nproc)
```

When you find a missing package, install it inside the container to verify it
fixes things:

```sh
apt-get install -y <package>
```

Then add the package to `ci/install.sh` and rebuild the deps image.

### Adding a build dependency

1. Add the package to the `packages` list in `ci/install.sh`.
2. Rebuild the deps image:
   ```sh
   docker build -f ci/Dockerfile.deps -t net-snmp-deps .
   ```
   `ci/docker-ci.sh` will also detect the change and rebuild automatically.

---

## Building manually (no Docker)

```sh
./configure --with-defaults \
  --disable-embedded-perl --without-perl-modules
make -j$(nproc)
```

See `INSTALL` and `INSTALL.agent` for the full list of configure options.
