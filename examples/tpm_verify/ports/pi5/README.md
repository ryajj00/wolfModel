# Pi 5 + STPM4RasPIV2 — Port Guide

Complete setup guide for running the wolfModel + wolfTPM verification example
on a Raspberry Pi 5 with the ST STPM4RasPIV2 TPM extension board.

**No source code changes required** — the example `main.c` works as-is on
the Pi 5. This guide covers hardware setup and software prerequisites only.

## Hardware

### STPM4RasPIV2 Extension Board

The **STPM4RasPIV2** (ordering code: SCT-TPM-RS2GTPMI) is an official ST
extension board designed for the Raspberry Pi GPIO header. It features two
industrial-grade TPM 2.0 devices on the same board:

- **ST33GTPMISPI** — SPI interface (firmware 3.257)
- **ST33GTPMII2C** — I2C interface (firmware 6.257)

For full schematics, board dimensions, and GPIO pinout see the
[STPM4RasPIV2 Data Brief (DB4720)](https://www.st.com/resource/en/data_brief/stpm4raspiv21.pdf).

The board is compatible with all Raspberry Pi models that have a 40-pin GPIO
header (Pi 3, Pi 4, Pi 5, etc.).

### Board Installation

The STPM4RasPIV2 plugs directly onto the Raspberry Pi GPIO header — no jumper
wires needed:

1. Power off the Raspberry Pi
2. Align the STPM4RasPIV2 26-pin female connector with GPIO pins 1-26
3. Press firmly until fully seated (the board fits inside a standard Pi case)
4. Power on

### Selector Jumper (SPI vs I2C)

The board has a **2-pin selector jumper** that determines which TPM is active:

| Jumper | Active TPM | Interface |
|--------|------------|-----------|
| **ON** (installed) | ST33GTPMISPI | **SPI** — use this for wolfTPM |
| OFF (removed) | ST33GTPMII2C | I2C |

**The selector jumper must be installed (ON) for SPI mode.**

wolfTPM communicates via SPI using its native HAL (`/dev/spidev0.0`),
bypassing the Linux kernel TPM driver entirely.

### SPI Pin Mapping (Reference)

These pins are connected automatically when the board is plugged onto the
GPIO header:

| Signal | RPi GPIO | RPi Pin | Description |
|--------|----------|---------|-------------|
| MOSI   | GPIO 10  | 19      | SPI data to TPM |
| MISO   | GPIO 9   | 21      | SPI data from TPM |
| SCLK   | GPIO 11  | 23      | SPI clock |
| CE0    | GPIO 8   | 24      | Chip select |
| RST    | GPIO 4   | 7       | TPM reset (active low) |
| VCC    |          | 17      | 3.3V power |
| GND    |          | 25      | Ground |

## Software Setup

### 1. Enable SPI

Add to `/boot/firmware/config.txt`:
```
dtparam=spi=on
```

Reboot and verify SPI is available:
```bash
ls /dev/spidev0.0
```

**Do NOT** load the `dtoverlay=tpm-slb9670` kernel overlay. wolfTPM talks
directly to the TPM over SPI via `/dev/spidev0.0`, bypassing the kernel TPM
driver.

### 2. Build and Install wolfSSL

```bash
cd wolfssl
./configure --enable-wolftpm
make
sudo make install
sudo ldconfig
```

The `--enable-wolftpm` flag enables the crypto callback layer and public MP
integers required by wolfTPM.

### 3. Build wolfTPM (Local Build)

```bash
cd wolfTPM
./autogen.sh
./configure --enable-st33 --enable-checkwaitstate
make
```

**Do not `sudo make install`** — keep wolfTPM as a local build and link
against it with `LD_LIBRARY_PATH`. This avoids version conflicts.

Verify the TPM is accessible:
```bash
LD_LIBRARY_PATH=src/.libs ./examples/wrap/caps
```

Expected output:
```
Mfg STM  (2), Vendor ST33KTPM2I, Fw 10.512 (0x10200) ...
```

If this fails, check:
- SPI is enabled: `ls /dev/spidev0.0`
- Selector jumper is ON (SPI mode)
- Board is seated firmly on the GPIO header

### 4. Build wolfModel

```bash
cd wolfModel
make WOLFSSL_ROOT=../wolfssl
make keytools WOLFSSL_ROOT=../wolfssl
```

### 5. Generate Test Fixtures

```bash
make fixtures WOLFSSL_ROOT=../wolfssl
```

This creates:
- `tests/fixtures/ecc256.der` — ECC-256 private key (raw Qx+Qy+d, 96 bytes)
- `tests/fixtures/pubkey.der` — ECC-256 public key (raw Qx+Qy, 64 bytes)
- `tests/fixtures/dummy.wmdl` — Signed model image (256-byte header + payload)

## Build the Example

```bash
cd examples/tpm_verify
make WOLFTPM_ROOT=../../wolfTPM WOLFSSL_ROOT=../../wolfssl
```

To include the attack demo:
```bash
make WOLFTPM_ROOT=../../wolfTPM WOLFSSL_ROOT=../../wolfssl DEMO_ATTACK=1
```

## Run

```bash
LD_LIBRARY_PATH=../../wolfTPM/src/.libs \
  ./wolfmodel_tpm_verify \
    ../../tests/fixtures/dummy.wmdl \
    ../../tests/fixtures/pubkey.der
```

### Expected Output

```
=== wolfTPM Init ===
wolfTPM2_Init: success
  Manufacturer: STM
  Vendor:       ST33KTPM2I
  Firmware:     10.512
  FIPS 140-2:   yes

=== Load Model ===
Loaded ../../tests/fixtures/dummy.wmdl (4352 bytes)

=== wolfModel Verify ===
Model verified OK.
  Version: 1
  Payload: 4096 bytes

=== TPM Measurement ===
Extending PCR[1] with model header hash...
  Hash: <64 hex chars>
wolfTPM2_ExtendPCR: success
  PCR[1] value: <64 hex chars>

Model verified and measured. Ready for inference.
```

### Attack Demo Output

When built with `DEMO_ATTACK=1`:

```
=== Attack Demo ===
Copying model and tampering byte at offset 1024...
[ATTACK DEMO] Tampered model correctly rejected: BAD_HASH (-4)
```

The tampered model is never measured into the TPM — only verified models
have their hash extended into the PCR.

## Run the Test Suite

The wolfModel host-side test suite validates the crypto independently of
the TPM (8 tests, 47 assertions):

```bash
cd wolfModel
make test WOLFSSL_ROOT=../wolfssl
```

This runs: roundtrip verify, tampered payload rejection, wrong key rejection,
truncated header, bad magic, zero payload, pubkey hint mismatch, and
cross-tool validation.

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `wolfTPM2_Init failed` | Check SPI enabled, jumper ON, board seated |
| `/dev/spidev0.0` missing | Add `dtparam=spi=on` to config.txt, reboot |
| `caps` shows wrong vendor | Different TPM board — adjust wolfTPM configure |
| `BAD_SIG` on verify | Regenerate fixtures: `make fixtures` |
| Linker errors | Ensure wolfSSL installed with `--enable-wolftpm` |
