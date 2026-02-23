/* wolfmodel.h
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

#ifndef WOLFMODEL_H
#define WOLFMODEL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/ecc.h>

/* ------------------------------------------------------------------ */
/* Constants                                                          */
/* ------------------------------------------------------------------ */

/* Magic: "WMDL" in little-endian = 0x4C444D57 */
#define WOLFMODEL_MAGIC         0x4C444D57UL

/* Default header size (bytes).  Override at compile time if needed. */
#ifndef WOLFMODEL_HEADER_SIZE
#define WOLFMODEL_HEADER_SIZE   256
#endif

/* Maximum AIBOM URL length (bytes) */
#define WOLFMODEL_AIBOM_URL_MAX 64

/* ECC-256 key size (bytes per coordinate) */
#define WOLFMODEL_ECC_KEY_SIZE  32

/* Raw ECDSA-P256 signature size: r (32B) + s (32B) */
#define WOLFMODEL_SIG_SIZE      64

/* ------------------------------------------------------------------ */
/* TLV Tag Definitions (independent format, not wolfBoot extension)   */
/* ------------------------------------------------------------------ */

#define WOLFMODEL_TAG_END          0x0000  /* End-of-tags marker          */
#define WOLFMODEL_TAG_VERSION      0x0001  /* uint32, model version       */
#define WOLFMODEL_TAG_TIMESTAMP    0x0002  /* uint64, unix timestamp      */
#define WOLFMODEL_TAG_SHA256       0x0003  /* 32 B, SHA-256 of payload    */
#define WOLFMODEL_TAG_PUBKEY_HINT  0x0010  /* 32 B, SHA-256 of raw pubkey */
#define WOLFMODEL_TAG_SIGNATURE    0x0020  /* 64 B, raw ECDSA r||s        */
#define WOLFMODEL_TAG_MODEL_TYPE   0x0040  /* uint16, model format ID     */
#define WOLFMODEL_TAG_AIBOM_URL    0x0050  /* var, AI BOM URL (max 64 B)  */
#define WOLFMODEL_TAG_RAM_REQ      0x0060  /* uint32, required SRAM bytes */
#define WOLFMODEL_TAG_PADDING      0x00FF  /* skip byte (no size field)   */

/* Model type identifiers for TAG_MODEL_TYPE */
#define WOLFMODEL_TYPE_UNKNOWN  0x0000
#define WOLFMODEL_TYPE_TFLITE   0x0001
#define WOLFMODEL_TYPE_ONNX     0x0002
#define WOLFMODEL_TYPE_RAW      0x00FF

/* ------------------------------------------------------------------ */
/* Error Codes                                                        */
/* ------------------------------------------------------------------ */

enum {
    WOLFMODEL_SUCCESS       =  0,
    WOLFMODEL_BAD_ARG       = -1,
    WOLFMODEL_BAD_MAGIC     = -2,
    WOLFMODEL_BAD_HEADER    = -3,
    WOLFMODEL_BAD_HASH      = -4,
    WOLFMODEL_BAD_SIG       = -5,
    WOLFMODEL_KEY_ERROR     = -6,
    WOLFMODEL_BAD_VERSION   = -7,   /* anti-rollback rejection */
    WOLFMODEL_VERIFY_ERROR  = -8,
    WOLFMODEL_BAD_RAM_REQ   = -9    /* model requires more RAM than avail */
};

/* ------------------------------------------------------------------ */
/* Safe little-endian reads — no unaligned access faults on Cortex-M  */
/* ------------------------------------------------------------------ */

#define WOLFMODEL_LOAD_LE16(p) \
    ((uint16_t)(p)[0] | ((uint16_t)(p)[1] << 8))

#define WOLFMODEL_LOAD_LE32(p) \
    ((uint32_t)(p)[0]         | ((uint32_t)(p)[1] << 8) | \
     ((uint32_t)(p)[2] << 16) | ((uint32_t)(p)[3] << 24))

#define WOLFMODEL_LOAD_LE64(p) \
    ((uint64_t)(p)[0]         | ((uint64_t)(p)[1] << 8)  | \
     ((uint64_t)(p)[2] << 16) | ((uint64_t)(p)[3] << 24) | \
     ((uint64_t)(p)[4] << 32) | ((uint64_t)(p)[5] << 40) | \
     ((uint64_t)(p)[6] << 48) | ((uint64_t)(p)[7] << 56))

/* ------------------------------------------------------------------ */
/* Hardware Hook Macros (no-ops by default)                           */
/* ------------------------------------------------------------------ */

/* TPM measured boot: extend PCR with header hash */
#ifndef WOLFMODEL_TPM_MEASURE
#define WOLFMODEL_TPM_MEASURE(hash, hashSz)    do { (void)(hash); \
                                                     (void)(hashSz); } while(0)
#endif

/* DICE attestation */
#ifndef WOLFMODEL_DICE_ATTEST
#define WOLFMODEL_DICE_ATTEST(hash, hashSz)    do { (void)(hash); \
                                                     (void)(hashSz); } while(0)
#endif

/* Anti-rollback: return 0 to allow, non-zero to reject */
#ifndef WOLFMODEL_CHECK_MIN_VERSION
#define WOLFMODEL_CHECK_MIN_VERSION(ver)        0
#endif

/* RAM sufficiency: return 0 if enough RAM, non-zero to reject */
#ifndef WOLFMODEL_CHECK_RAM_REQ
#define WOLFMODEL_CHECK_RAM_REQ(bytes)          0
#endif

/* ------------------------------------------------------------------ */
/* Context Structure                                                  */
/* ------------------------------------------------------------------ */

/*
 * WARNING: ecc_key is ~400-600 bytes.  This struct MUST be declared as a
 * global static or in .bss, NEVER on the stack of an RTOS thread with
 * limited stack space.
 */
typedef struct WOLFMODEL_CTX {
    /* Parsed header fields */
    uint32_t  payload_size;
    uint32_t  version;
    uint32_t  ram_req;          /* from TAG_RAM_REQ, 0 if absent */
    uint16_t  model_type;

    /*
     * Pointers INTO the caller's image buffer (zero-copy, no alloc).
     * Lifetime: valid only while the original image buffer is valid and
     * unmodified.
     */
    const uint8_t *sha256_digest;     /* -> 32 bytes in header       */
    const uint8_t *signature;         /* -> sig bytes in header       */
    uint16_t       signature_size;
    uint16_t       sig_offset;        /* byte offset of sig TLV type
                                         field from image[0]          */
    const uint8_t *payload;           /* -> first byte after header   */
    const uint8_t *pubkey_hint;       /* -> 32 bytes in header (NULL if absent) */

    const uint8_t *aibom_url;         /* -> AIBOM URL in header       */
    uint16_t       aibom_url_size;    /* (NULL + 0 if absent)         */

    /* wolfCrypt ECC-256 public key */
    ecc_key   ecc;
    uint8_t   key_set;          /* has a public key been loaded?      */

    /* Verification status flags */
    uint8_t   hdr_ok  : 1;
    uint8_t   hash_ok : 1;
    uint8_t   sig_ok  : 1;
} WOLFMODEL_CTX;

/* ------------------------------------------------------------------ */
/* Public API                                                         */
/* ------------------------------------------------------------------ */

/*
 * wolfModel_Init - Zero-initialise a WOLFMODEL_CTX.
 *   ctx must point to a global/static instance.
 *   Returns WOLFMODEL_SUCCESS or WOLFMODEL_BAD_ARG.
 */
int wolfModel_Init(WOLFMODEL_CTX *ctx);

/*
 * wolfModel_SetPubKey - Load an ECC-256 public key.
 *   Accepts raw format: qx (32B) + qy (32B) = 64 bytes total.
 *   Same format as wolfBoot key files.
 *   Calls wc_ecc_init() + wc_ecc_import_unsigned().
 *   Returns WOLFMODEL_SUCCESS or WOLFMODEL_KEY_ERROR.
 */
int wolfModel_SetPubKey(WOLFMODEL_CTX *ctx, const uint8_t *pubkey,
                        uint32_t pubkeySz);

/*
 * wolfModel_Verify - Parse header, verify integrity + authenticity.
 *
 *   image    pointer to the complete .wmdl file (header + payload)
 *   imageSz  total size of the image in bytes
 *
 *   Stack usage: ~700 bytes.  Do NOT build wolfSSL with --enable-smallstack.
 *
 *   Returns WOLFMODEL_SUCCESS on full verification, or a negative error code.
 */
int wolfModel_Verify(WOLFMODEL_CTX *ctx, const uint8_t *image, uint32_t imageSz);

/*
 * wolfModel_GetVersion - Return the parsed model version.
 *   Valid after a successful wolfModel_Verify().
 */
uint32_t wolfModel_GetVersion(const WOLFMODEL_CTX *ctx);

/*
 * wolfModel_GetPayload - Return a pointer to the verified payload.
 *
 *   Returns NULL if verification has not succeeded.
 *   The returned pointer aliases the caller's image buffer.  It is valid
 *   only while the original image buffer remains valid and unmodified.
 */
const uint8_t* wolfModel_GetPayload(const WOLFMODEL_CTX *ctx,
                                    uint32_t *payloadSz);

/*
 * wolfModel_GetAIBOMUrl - Return the AIBOM URL string (if present).
 *   Sets *urlSz to the string length.  Returns NULL + 0 if absent.
 */
const uint8_t* wolfModel_GetAIBOMUrl(const WOLFMODEL_CTX *ctx,
                                     uint16_t *urlSz);

/*
 * wolfModel_Free - Release wolfCrypt resources and zero status flags.
 *   Calls wc_ecc_free().  No heap deallocation.
 */
void wolfModel_Free(WOLFMODEL_CTX *ctx);

#ifdef __cplusplus
}
#endif

#endif /* WOLFMODEL_H */
