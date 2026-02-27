/* main.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfModel.
 *
 * wolfModel is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfModel is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/*
 * wolfModel + wolfTPM Integration Example
 *
 * Demonstrates the full chain of trust:
 *   1. Initialize wolfTPM, confirm TPM is alive (print vendor info)
 *   2. Load a signed .wmdl model file
 *   3. Verify with wolfModel (ECC-256 signature check)
 *   4. Extend TPM PCR[1] with the model's header hash
 *   5. Read back PCR[1] and print the value
 *   6. (Optional) Attack demo: tamper a byte, show verification fails
 *
 * Platform: Raspberry Pi 5 + STPM4RasPI (ST33 TPM over SPI)
 *           Adaptable to bare-metal STM32H5 (different HAL init, flash
 *           instead of mmap).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

/* wolfSSL */
#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/sha256.h>

/* wolfTPM */
#include <wolftpm/tpm2_wrap.h>
#include <hal/tpm_io.h>

/* wolfModel */
#include <wolfmodel/wolfmodel.h>

/* PCR index for model measurement */
#define WOLFMODEL_PCR_INDEX  1

/*
 * Static globals — WOLFTPM2_DEV and WOLFMODEL_CTX contain large structs
 * (~600 bytes each).  MUST be declared as global/static or in .bss,
 * NEVER on the stack of an RTOS thread with limited stack space.
 */
static WOLFTPM2_DEV tpmDev;
static WOLFMODEL_CTX ctx;

/* Small buffer for the public key (64 bytes: Qx + Qy) */
static uint8_t pubkey_buf[64];

static const char *wolfmodel_err_str(int code)
{
    switch (code) {
        case WOLFMODEL_SUCCESS:      return "SUCCESS";
        case WOLFMODEL_BAD_ARG:      return "BAD_ARG";
        case WOLFMODEL_BAD_MAGIC:    return "BAD_MAGIC";
        case WOLFMODEL_BAD_HEADER:   return "BAD_HEADER";
        case WOLFMODEL_BAD_HASH:     return "BAD_HASH (payload tampered)";
        case WOLFMODEL_BAD_SIG:      return "BAD_SIG (signature invalid)";
        case WOLFMODEL_KEY_ERROR:    return "KEY_ERROR";
        case WOLFMODEL_BAD_VERSION:  return "BAD_VERSION";
        case WOLFMODEL_VERIFY_ERROR: return "VERIFY_ERROR";
        case WOLFMODEL_BAD_RAM_REQ:  return "BAD_RAM_REQ";
        default:                     return "UNKNOWN";
    }
}

/*
 * Compute the header hash using the same zero-and-fill method as
 * wolfModel_Verify() internally.  This is the measurement we extend
 * into the TPM PCR — it covers the entire header including the model
 * version, payload hash, and key hint, but with the signature field
 * zeroed (since the signature itself is not part of the signed data).
 */
static int compute_header_hash(const uint8_t *image, uint8_t *out_hash)
{
    uint8_t header_copy[WOLFMODEL_HEADER_SIZE];
    wc_Sha256 sha;
    const uint8_t *ptr;
    uint16_t offset;
    uint16_t tag;
    uint16_t len;
    int ret;

    XMEMCPY(header_copy, image, WOLFMODEL_HEADER_SIZE);

    /* Walk TLV to find signature tag and zero its value */
    ptr = header_copy + 8; /* skip magic(4) + payload_size(4) */
    offset = 8;
    while (offset + 4 <= WOLFMODEL_HEADER_SIZE) {
        tag = WOLFMODEL_LOAD_LE16(ptr);
        if (tag == WOLFMODEL_TAG_END || tag == WOLFMODEL_TAG_PADDING)
            break;
        len = WOLFMODEL_LOAD_LE16(ptr + 2);
        if (tag == WOLFMODEL_TAG_SIGNATURE) {
            /* Zero the signature value bytes (after tag+len) */
            XMEMSET(header_copy + offset + 4, 0, len);
            break;
        }
        ptr    += 4 + len;
        offset += 4 + len;
    }

    ret = wc_InitSha256(&sha);
    if (ret != 0) return ret;
    ret = wc_Sha256Update(&sha, header_copy, WOLFMODEL_HEADER_SIZE);
    if (ret != 0) return ret;
    ret = wc_Sha256Final(&sha, out_hash);
    return ret;
}

/*
 * Extend a TPM PCR with the model header hash and read back the result.
 * Uses the wolfTPM2 wrapper API (wolfTPM2_ExtendPCR / wolfTPM2_ReadPCR).
 */
static int tpm_measure_model(WOLFTPM2_DEV *dev, int pcrIndex,
                             const uint8_t *hash, int hashSz)
{
    int rc;
    int i;
    byte pcrValue[WC_SHA256_DIGEST_SIZE];
    int pcrLen = (int)sizeof(pcrValue);

    printf("Extending PCR[%d] with model header hash...\n", pcrIndex);
    printf("  Hash: ");
    for (i = 0; i < hashSz; i++)
        printf("%02x", hash[i]);
    printf("\n");

    rc = wolfTPM2_ExtendPCR(dev, pcrIndex, TPM_ALG_SHA256, hash, hashSz);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_ExtendPCR failed 0x%x: %s\n", rc,
               TPM2_GetRCString(rc));
        return rc;
    }
    printf("wolfTPM2_ExtendPCR: success\n");

    rc = wolfTPM2_ReadPCR(dev, pcrIndex, TPM_ALG_SHA256, pcrValue, &pcrLen);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_ReadPCR failed 0x%x: %s\n", rc,
               TPM2_GetRCString(rc));
        return rc;
    }

    printf("  PCR[%d] value: ", pcrIndex);
    for (i = 0; i < pcrLen; i++)
        printf("%02x", pcrValue[i]);
    printf("\n");

    return TPM_RC_SUCCESS;
}

int main(int argc, char **argv)
{
    const char *wmdl_path;
    const char *key_path;
    int fd;
    struct stat st;
    uint8_t *map;
    FILE *fkey;
    size_t key_sz;
    int ret;
    int rc;
    uint32_t payload_sz;
    const uint8_t *payload;
    WOLFTPM2_CAPS caps;
    uint8_t header_hash[WC_SHA256_DIGEST_SIZE];

    if (argc != 3) {
        printf("wolfModel + wolfTPM Verification Example\n\n");
        printf("Usage: %s <model.wmdl> <pubkey.der>\n", argv[0]);
        printf("\nDemonstrates: verify model -> extend TPM PCR -> read PCR\n");
        return 1;
    }

    wmdl_path = argv[1];
    key_path  = argv[2];

    /* ================================================================ */
    /* Step 1: Initialize wolfTPM, confirm TPM is alive                 */
    /* ================================================================ */
    printf("=== wolfTPM Init ===\n");
    rc = wolfTPM2_Init(&tpmDev, TPM2_IoCb, NULL);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_Init failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        return 1;
    }
    printf("wolfTPM2_Init: success\n");

    /* Step 2: Print TPM manufacturer/vendor info */
    rc = wolfTPM2_GetCapabilities(&tpmDev, &caps);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_GetCapabilities failed 0x%x: %s\n", rc,
               TPM2_GetRCString(rc));
        wolfTPM2_Cleanup(&tpmDev);
        return 1;
    }
    printf("  Manufacturer: %s\n", caps.mfgStr);
    printf("  Vendor:       %s\n", caps.vendorStr);
    printf("  Firmware:     %d.%d\n", caps.fwVerMajor, caps.fwVerMinor);
    printf("  FIPS 140-2:   %s\n", caps.fips140_2 ? "yes" : "no");

    /* ================================================================ */
    /* Step 3: Load the .wmdl file via mmap                             */
    /* ================================================================ */
    printf("\n=== Load Model ===\n");
    fd = open(wmdl_path, O_RDONLY);
    if (fd < 0) {
        perror(wmdl_path);
        wolfTPM2_Cleanup(&tpmDev);
        return 1;
    }
    if (fstat(fd, &st) < 0) {
        perror("fstat");
        close(fd);
        wolfTPM2_Cleanup(&tpmDev);
        return 1;
    }
    map = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED) {
        perror("mmap");
        close(fd);
        wolfTPM2_Cleanup(&tpmDev);
        return 1;
    }
    close(fd);
    printf("Loaded %s (%ld bytes)\n", wmdl_path, (long)st.st_size);

    /* Step 4: Read public key (raw Qx+Qy, 64 bytes) */
    fkey = fopen(key_path, "rb");
    if (fkey == NULL) {
        perror(key_path);
        munmap(map, (size_t)st.st_size);
        wolfTPM2_Cleanup(&tpmDev);
        return 1;
    }
    key_sz = fread(pubkey_buf, 1, sizeof(pubkey_buf), fkey);
    fclose(fkey);
    if (key_sz != 64) {
        fprintf(stderr, "Error: pubkey.der must be 64 bytes (Qx+Qy), got %zu\n",
                key_sz);
        munmap(map, (size_t)st.st_size);
        wolfTPM2_Cleanup(&tpmDev);
        return 1;
    }

    /* ================================================================ */
    /* Step 5-7: wolfModel Init, SetPubKey, Verify                      */
    /* ================================================================ */
    printf("\n=== wolfModel Verify ===\n");
    ret = wolfModel_Init(&ctx);
    if (ret != WOLFMODEL_SUCCESS) {
        fprintf(stderr, "wolfModel_Init failed: %s (%d)\n",
                wolfmodel_err_str(ret), ret);
        munmap(map, (size_t)st.st_size);
        wolfTPM2_Cleanup(&tpmDev);
        return 1;
    }

    ret = wolfModel_SetPubKey(&ctx, pubkey_buf, 64);
    if (ret != WOLFMODEL_SUCCESS) {
        fprintf(stderr, "wolfModel_SetPubKey failed: %s (%d)\n",
                wolfmodel_err_str(ret), ret);
        wolfModel_Free(&ctx);
        munmap(map, (size_t)st.st_size);
        wolfTPM2_Cleanup(&tpmDev);
        return 1;
    }

    ret = wolfModel_Verify(&ctx, map, (uint32_t)st.st_size);
    if (ret != WOLFMODEL_SUCCESS) {
        fprintf(stderr, "Verification FAILED: %s (%d)\n",
                wolfmodel_err_str(ret), ret);
        wolfModel_Free(&ctx);
        munmap(map, (size_t)st.st_size);
        wolfTPM2_Cleanup(&tpmDev);
        return 1;
    }

    payload = wolfModel_GetPayload(&ctx, &payload_sz);
    printf("Model verified OK.\n");
    printf("  Version: %u\n", wolfModel_GetVersion(&ctx));
    printf("  Payload: %u bytes\n", payload_sz);
    (void)payload;

    /* ================================================================ */
    /* Step 8: TPM PCR measurement                                      */
    /* ================================================================ */
    printf("\n=== TPM Measurement ===\n");

    /*
     * Compute the header hash (same zero-and-fill method used internally
     * by wolfModel_Verify).  This hash covers: magic, payload_size,
     * version, timestamp, payload SHA-256, pubkey hint, model type, etc.
     * The signature field is zeroed before hashing.
     */
    ret = compute_header_hash(map, header_hash);
    if (ret != 0) {
        fprintf(stderr, "compute_header_hash failed: %d\n", ret);
        wolfModel_Free(&ctx);
        munmap(map, (size_t)st.st_size);
        wolfTPM2_Cleanup(&tpmDev);
        return 1;
    }

    rc = tpm_measure_model(&tpmDev, WOLFMODEL_PCR_INDEX,
                           header_hash, WC_SHA256_DIGEST_SIZE);
    if (rc != TPM_RC_SUCCESS) {
        fprintf(stderr, "TPM measurement failed\n");
        wolfModel_Free(&ctx);
        munmap(map, (size_t)st.st_size);
        wolfTPM2_Cleanup(&tpmDev);
        return 1;
    }

    printf("\nModel verified and measured. Ready for inference.\n");

    /* ================================================================ */
    /* Step 9: Attack demo (compile with -DWOLFMODEL_DEMO_ATTACK)       */
    /* ================================================================ */
#ifdef WOLFMODEL_DEMO_ATTACK
    {
        uint8_t *tampered;
        uint32_t tampered_sz = (uint32_t)st.st_size;

        printf("\n=== Attack Demo ===\n");
        printf("Copying model and tampering byte at offset 1024...\n");

        tampered = malloc(tampered_sz);
        if (tampered == NULL) {
            fprintf(stderr, "malloc failed for attack demo\n");
        }
        else {
            memcpy(tampered, map, tampered_sz);
            /* Flip one byte in the payload area */
            if (tampered_sz > 1024)
                tampered[1024] ^= 0xFF;

            /* Re-init and verify the tampered copy */
            wolfModel_Free(&ctx);
            ret = wolfModel_Init(&ctx);
            if (ret == WOLFMODEL_SUCCESS)
                ret = wolfModel_SetPubKey(&ctx, pubkey_buf, 64);
            if (ret == WOLFMODEL_SUCCESS)
                ret = wolfModel_Verify(&ctx, tampered, tampered_sz);

            if (ret == WOLFMODEL_BAD_HASH) {
                printf("[ATTACK DEMO] Tampered model correctly rejected: "
                       "BAD_HASH (%d)\n", ret);
            }
            else {
                printf("[ATTACK DEMO] Unexpected result: %s (%d)\n",
                       wolfmodel_err_str(ret), ret);
            }

            free(tampered);
        }
    }
#endif /* WOLFMODEL_DEMO_ATTACK */

    /* ================================================================ */
    /* Cleanup                                                          */
    /* ================================================================ */
    wolfModel_Free(&ctx);
    munmap(map, (size_t)st.st_size);
    wolfTPM2_Cleanup(&tpmDev);

    return 0;
}
