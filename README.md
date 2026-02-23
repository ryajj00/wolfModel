# wolfModel

Cryptographic verification of Edge AI model binaries (.tflite, .onnx, or any binary payload) using wolfSSL/wolfCrypt with no dynamic memory allocations

## Overview

- ECC-256 (ECDSA-P256) signature verification with SHA-256 integrity hash
- Zero-malloc — fully static context (`WOLFMODEL_CTX`), ideal for constrained/embedded environments
- wolfBoot-inspired TLV header format with 256-byte fixed header
- Raw key format: `Qx+Qy` (64 bytes public), `Qx+Qy+d` (96 bytes private) — same as wolfBoot
- Raw signature format: `r||s` (64 bytes fixed) — not DER-encoded
- Pubkey hint for fast key identification and rejection
- ~700 bytes stack usage for `wolfModel_Verify()`
- C89-compatible, MISRA-friendly, safe on unaligned architectures (Cortex-M)
- Hardware hook macros for TPM measured boot, DICE attestation, anti-rollback
- C native signing and key generation tools (like wolfBoot production path)

wolfModel provides a cryptographic verification gate for AI model files before they are loaded into an inference engine. Edge AI formats (TFLite, ONNX) have no built-in integrity protection — any byte modification silently alters model predictions. wolfModel wraps the model binary in a signed `.wmdl` container and verifies authenticity on the device with zero heap allocation.

## Prerequisites

wolfSSL with the required crypto algorithms:

```bash
git clone https://github.com/wolfSSL/wolfssl.git
cd wolfssl
./autogen.sh
./configure --enable-ecc --enable-sha256 --enable-cryptonly --enable-asn \
    CFLAGS="-DWOLFSSL_PUBLIC_MP"
make
sudo make install
sudo ldconfig
```

## Building

```bash
make                                    # build libwolfmodel.a
make WOLFSSL_ROOT=../wolfssl            # use local wolfSSL source tree
make keytools                           # build sign + keygen tools
make test                               # run test suite (8 tests, 47 assertions)
make fixtures                           # generate test key + signed model
make examples                           # build example verify program
make install PREFIX=/usr/local          # install library + headers
```

### Quick Start

```bash
# 1. Build library and tools
make && make keytools

# 2. Generate an ECC-256 signing keypair
build/wolfmodel_keygen keys/
# Creates: keys/ecc256.der (private, 96B) and keys/pubkey.der (public, 64B)

# 3. Sign a model
build/wolfmodel_sign --key keys/ecc256.der \
    --image model.tflite \
    --output model.wmdl \
    --version 1 --type tflite

# 4. Verify the signed model
build/wolfmodel_verify model.wmdl keys/pubkey.der
# Output: Model verified OK. Version: 1, Payload: <size> bytes
```

### Usage

```c
static WOLFMODEL_CTX ctx;    /* global/static, not on stack */

wolfModel_Init(&ctx);
wolfModel_SetPubKey(&ctx, trusted_pubkey, 64);

int rc = wolfModel_Verify(&ctx, wmdl_image, wmdl_size);
if (rc != WOLFMODEL_SUCCESS) {
    /* REJECT — do not load the model */
}

uint32_t modelSz;
const uint8_t *model = wolfModel_GetPayload(&ctx, &modelSz);
/* Pass model/modelSz to TFLite Interpreter */
```

## Testing

`make test` runs the host-side test suite (8 test cases, 47 assertions):

```bash
make WOLFSSL_ROOT=../wolfssl test
```

`make fixtures` generates test fixtures using the C keytools (keygen + sign). The cross-tool test validates that the C signing tool produces images the C library verifies.

## Key Tools

wolfModel uses C native key tools (like wolfBoot production path), not Python. The tools link directly against wolfCrypt:

| Tool | Description |
|---|---|
| `wolfmodel_keygen <output_dir>` | Generate ECC-256 keypair (raw format) |
| `wolfmodel_sign --key <ecc256.der> --image <model.bin> --output <model.wmdl>` | Create signed `.wmdl` image |

Options for `wolfmodel_sign`:

| Option | Description |
|---|---|
| `--key <file>` | Private key file (Qx+Qy+d, 96 bytes) |
| `--image <file>` | Input model binary |
| `--output <file>` | Output `.wmdl` file |
| `--version <N>` | Model version (default: 1) |
| `--type <tflite\|onnx\|raw>` | Model type tag (default: raw) |

## API Reference

| Function | Description |
|---|---|
| `wolfModel_Init()` | Zero-initialize context (no allocation) |
| `wolfModel_SetPubKey()` | Load raw ECC-256 public key (Qx+Qy, 64 bytes) |
| `wolfModel_Verify()` | Parse header, verify SHA-256 hash + ECDSA signature |
| `wolfModel_GetVersion()` | Return parsed model version (valid after verify) |
| `wolfModel_GetPayload()` | Return verified payload pointer + size |
| `wolfModel_GetAIBOMUrl()` | Return AIBOM URL string if present |
| `wolfModel_Free()` | Release wolfCrypt resources, zero status flags (no free) |

## License

GPLv3 -- see [LICENSE](LICENSE) file. Copyright (C) 2006-2025 wolfSSL Inc.

## Links

- [wolfSSL](https://www.wolfssl.com/)
- [wolfBoot](https://github.com/wolfSSL/wolfBoot)
- [wolfSSL GitHub](https://github.com/wolfSSL/wolfssl)
