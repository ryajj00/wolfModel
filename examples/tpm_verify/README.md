# wolfModel + wolfTPM Verification Example

Demonstrates the **full chain of trust** for Edge AI model verification with
hardware-backed TPM measured boot:

1. Initialize wolfTPM (connect to ST33 TPM)
2. Load a signed `.wmdl` model image
3. Verify with `wolfModel_Verify()` (ECC-256 signature + SHA-256 integrity)
4. Extend TPM PCR[1] with the model's header hash
5. Read back PCR[1] and print the hex digest
6. (Optional) Attack demo: tamper one byte, show verification rejects it

## Source

- `main.c` — Example application (Linux/POSIX, uses mmap + filesystem)
- `Makefile` — Builds against installed wolfSSL + local wolfTPM

## Platform Ports

| Platform | Directory | Status |
|----------|-----------|--------|
| Raspberry Pi 5 + STPM4RasPIV2 | [`ports/pi5/`](ports/pi5/) | **Working** |
| NUCLEO-H573ZI + STPM4RasPIV2 | `ports/stm32h5/` | Work-in-progress |

See the port-specific README for hardware setup, build, and run instructions.

## Signing Your Own Model

To sign an actual AI model (`.tflite`, `.onnx`, or any binary):

```bash
# Generate a keypair
./build/wolfmodel_keygen tests/fixtures

# Sign the model
./build/wolfmodel_sign \
  --key tests/fixtures/ecc256.der \
  --image path/to/your_model.tflite \
  --output path/to/your_model.wmdl
```

The `.wmdl` output is a 256-byte wolfBoot-style TLV header prepended to the
original binary. The header contains the SHA-256 payload hash, ECC-256
signature, version, timestamp, and key hint.

## Chain of Trust

```
+-------------------+
|    wolfBoot       |  Secure boot: verify firmware image
|  (boot loader)    |
+---------+---------+
          |
          v
+---------+---------+
|    wolfModel      |  Verify AI model: ECC-256 sig + SHA-256
|   (this library)  |
+---------+---------+
          |
          v
+---------+---------+
|    wolfTPM        |  Extend PCR[1] with model header hash
|  (HW root of     |  (hardware-backed measurement)
|    trust)         |
+---------+---------+
          |
          v
+---------+---------+
|   TF-Lite Micro   |  Load verified payload for inference
|   / ONNX Runtime  |
+-------------------+
```
