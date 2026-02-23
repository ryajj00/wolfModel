/* wolfmodel.c
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

/* wolfSSL / wolfCrypt headers */
#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

/* ConstantCompare() - standard wolfSSL embedded pattern */
#define WOLFSSL_MISC_INCLUDED
#include <wolfcrypt/src/misc.c>

/* wolfModel public header */
#include <wolfmodel/wolfmodel.h>

/* ------------------------------------------------------------------ */
/* Internal: TLV tag search (modeled on wolfBoot_find_header)         */
/* ------------------------------------------------------------------ */

/*
 * Walk the TLV area of the header starting at `haystack`, searching for a tag
 * whose type field equals `tag`.  On match, *ptr is set to the value area and
 * the value length is returned.  Returns 0 if not found.
 *
 * `sig_off` is optional: if non-NULL and the tag is TAG_SIGNATURE, *sig_off is
 * set to the byte offset of the tag's TYPE field relative to `base`.
 *
 * All multi-byte reads use WOLFMODEL_LOAD_LE16 to avoid unaligned faults.
 */
static uint16_t wolfModel_find_tag(const uint8_t *base,
                                   const uint8_t *haystack,
                                   uint16_t       max_bytes,
                                   uint16_t       tag,
                                   const uint8_t **ptr,
                                   uint16_t       *sig_off)
{
    uint16_t off = 0;

    while (off < max_bytes) {
        uint16_t t;
        uint16_t len;

        /* Skip runs of 0xFF padding bytes */
        if (haystack[off] == WOLFMODEL_TAG_PADDING) {
            off++;
            continue;
        }

        /* Need at least 2 bytes for tag type */
        if (off + 2 > max_bytes)
            break;

        t = WOLFMODEL_LOAD_LE16(haystack + off);

        /* End-of-tags marker */
        if (t == WOLFMODEL_TAG_END)
            break;

        /* Need 2 more bytes for length */
        if (off + 4 > max_bytes)
            break;

        len = WOLFMODEL_LOAD_LE16(haystack + off + 2);

        /* Bounds check: value must fit within remaining header space */
        if (off + 4 + len > max_bytes)
            break;

        if (t == tag) {
            *ptr = haystack + off + 4;
            /* Record signature TLV offset relative to image start */
            if (sig_off != NULL)
                *sig_off = (uint16_t)(haystack + off - base);
            return len;
        }

        off += 4 + len;
    }

    *ptr = NULL;
    return 0;
}

/* ------------------------------------------------------------------ */
/* wolfModel_Init                                                     */
/* ------------------------------------------------------------------ */

int wolfModel_Init(WOLFMODEL_CTX *ctx)
{
    if (ctx == NULL)
        return WOLFMODEL_BAD_ARG;

    XMEMSET(ctx, 0, sizeof(*ctx));
    return WOLFMODEL_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* wolfModel_SetPubKey                                                */
/* ------------------------------------------------------------------ */

int wolfModel_SetPubKey(WOLFMODEL_CTX *ctx, const uint8_t *pubkey,
                        uint32_t pubkeySz)
{
    int ret;

    if (ctx == NULL || pubkey == NULL)
        return WOLFMODEL_BAD_ARG;
    if (pubkeySz != 2 * WOLFMODEL_ECC_KEY_SIZE)
        return WOLFMODEL_BAD_ARG;

    ret = wc_ecc_init(&ctx->ecc);
    if (ret != 0)
        return WOLFMODEL_KEY_ERROR;

    /* Import raw unsigned public key: qx (32B) || qy (32B)
     * Same format as wolfBoot key files. */
    ret = wc_ecc_import_unsigned(&ctx->ecc,
                                 (byte *)pubkey,                         /* qx */
                                 (byte *)(pubkey + WOLFMODEL_ECC_KEY_SIZE), /* qy */
                                 NULL,                                   /* d (NULL = pub only) */
                                 ECC_SECP256R1);
    if (ret != 0) {
        wc_ecc_free(&ctx->ecc);
        return WOLFMODEL_KEY_ERROR;
    }

    ctx->key_set = 1;
    return WOLFMODEL_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* wolfModel_Verify                                                   */
/* ------------------------------------------------------------------ */

int wolfModel_Verify(WOLFMODEL_CTX *ctx, const uint8_t *image, uint32_t imageSz)
{
    const uint8_t *tlv_start;
    uint16_t       tlv_max;
    const uint8_t *val;
    uint16_t       len;
    int            ret;

    /* Stack-allocated buffers (~700 B total) */
    uint8_t  header_copy[WOLFMODEL_HEADER_SIZE];
    uint8_t  computed_hash[WC_SHA256_DIGEST_SIZE];
    uint8_t  header_hash[WC_SHA256_DIGEST_SIZE];
    wc_Sha256 sha;

    if (ctx == NULL || image == NULL)
        return WOLFMODEL_BAD_ARG;
    if (ctx->key_set == 0)
        return WOLFMODEL_KEY_ERROR;

    /* Reset verification status */
    ctx->hdr_ok  = 0;
    ctx->hash_ok = 0;
    ctx->sig_ok  = 0;
    ctx->sha256_digest  = NULL;
    ctx->signature      = NULL;
    ctx->signature_size = 0;
    ctx->sig_offset     = 0;
    ctx->payload        = NULL;
    ctx->pubkey_hint    = NULL;
    ctx->aibom_url      = NULL;
    ctx->aibom_url_size = 0;
    ctx->ram_req        = 0;

    /* --- Step A: Validate magic --- */
    if (imageSz < WOLFMODEL_HEADER_SIZE)
        return WOLFMODEL_BAD_HEADER;

    if (WOLFMODEL_LOAD_LE32(image) != WOLFMODEL_MAGIC)
        return WOLFMODEL_BAD_MAGIC;

    /* --- Step B: Extract payload_size, bounds-check --- */
    ctx->payload_size = WOLFMODEL_LOAD_LE32(image + 4);
    if (imageSz < (uint32_t)WOLFMODEL_HEADER_SIZE + ctx->payload_size)
        return WOLFMODEL_BAD_HEADER;

    /* --- Step C: Walk TLV tags --- */
    /* TLV area starts after 8-byte fixed header (magic + payload_size) */
    tlv_start = image + 8;
    tlv_max   = WOLFMODEL_HEADER_SIZE - 8;

    /* Version (required) */
    len = wolfModel_find_tag(image, tlv_start, tlv_max,
                             WOLFMODEL_TAG_VERSION, &val, NULL);
    if (len != 4 || val == NULL)
        return WOLFMODEL_BAD_HEADER;
    ctx->version = WOLFMODEL_LOAD_LE32(val);

    /* SHA-256 digest (required) */
    len = wolfModel_find_tag(image, tlv_start, tlv_max,
                             WOLFMODEL_TAG_SHA256, &val, NULL);
    if (len != WC_SHA256_DIGEST_SIZE || val == NULL)
        return WOLFMODEL_BAD_HEADER;
    ctx->sha256_digest = val;

    /* Signature (required) — raw r||s, must be exactly 64 bytes */
    len = wolfModel_find_tag(image, tlv_start, tlv_max,
                             WOLFMODEL_TAG_SIGNATURE, &val, &ctx->sig_offset);
    if (len != WOLFMODEL_SIG_SIZE || val == NULL)
        return WOLFMODEL_BAD_HEADER;
    ctx->signature      = val;
    ctx->signature_size = len;

    /* Model type (optional) */
    len = wolfModel_find_tag(image, tlv_start, tlv_max,
                             WOLFMODEL_TAG_MODEL_TYPE, &val, NULL);
    if (len == 2 && val != NULL)
        ctx->model_type = WOLFMODEL_LOAD_LE16(val);

    /* RAM requirement (optional) */
    len = wolfModel_find_tag(image, tlv_start, tlv_max,
                             WOLFMODEL_TAG_RAM_REQ, &val, NULL);
    if (len == 4 && val != NULL)
        ctx->ram_req = WOLFMODEL_LOAD_LE32(val);

    /* AIBOM URL (optional) */
    len = wolfModel_find_tag(image, tlv_start, tlv_max,
                             WOLFMODEL_TAG_AIBOM_URL, &val, NULL);
    if (len > 0 && val != NULL && len <= WOLFMODEL_AIBOM_URL_MAX) {
        ctx->aibom_url      = val;
        ctx->aibom_url_size = len;
    }

    /* Public key hint (optional) */
    len = wolfModel_find_tag(image, tlv_start, tlv_max,
                             WOLFMODEL_TAG_PUBKEY_HINT, &val, NULL);
    if (len == WC_SHA256_DIGEST_SIZE && val != NULL)
        ctx->pubkey_hint = val;

    /* Payload pointer */
    ctx->payload = image + WOLFMODEL_HEADER_SIZE;
    ctx->hdr_ok = 1;

    /* --- Step D: Anti-rollback check --- */
    if (WOLFMODEL_CHECK_MIN_VERSION(ctx->version) != 0)
        return WOLFMODEL_BAD_VERSION;

    /* --- Step E: RAM requirement check --- */
    if (ctx->ram_req > 0) {
        if (WOLFMODEL_CHECK_RAM_REQ(ctx->ram_req) != 0)
            return WOLFMODEL_BAD_RAM_REQ;
    }

    /* --- Step F: PUBKEY_HINT check (if present) --- */
    /* Hash the raw public key (qx || qy) and compare to stored hint.
     * Same approach as wolfBoot: SHA-256(pubkey_raw). */
    if (ctx->pubkey_hint != NULL) {
        uint8_t qx[WOLFMODEL_ECC_KEY_SIZE];
        uint8_t qy[WOLFMODEL_ECC_KEY_SIZE];
        word32 qxLen = WOLFMODEL_ECC_KEY_SIZE;
        word32 qyLen = WOLFMODEL_ECC_KEY_SIZE;
        uint8_t pubkey_hash[WC_SHA256_DIGEST_SIZE];

        ret = wc_ecc_export_public_raw(&ctx->ecc, qx, &qxLen, qy, &qyLen);
        if (ret != 0)
            return WOLFMODEL_KEY_ERROR;

        ret = wc_InitSha256(&sha);
        if (ret != 0) return WOLFMODEL_VERIFY_ERROR;
        ret = wc_Sha256Update(&sha, qx, qxLen);
        if (ret != 0) return WOLFMODEL_VERIFY_ERROR;
        ret = wc_Sha256Update(&sha, qy, qyLen);
        if (ret != 0) return WOLFMODEL_VERIFY_ERROR;
        ret = wc_Sha256Final(&sha, pubkey_hash);
        if (ret != 0) return WOLFMODEL_VERIFY_ERROR;

        if (ConstantCompare(pubkey_hash, ctx->pubkey_hint,
                            WC_SHA256_DIGEST_SIZE) != 0)
            return WOLFMODEL_KEY_ERROR;
    }

    /* --- Step G: Integrity check (SHA-256 of payload) --- */
    ret = wc_InitSha256(&sha);
    if (ret != 0) return WOLFMODEL_VERIFY_ERROR;
    ret = wc_Sha256Update(&sha, ctx->payload, ctx->payload_size);
    if (ret != 0) return WOLFMODEL_VERIFY_ERROR;
    ret = wc_Sha256Final(&sha, computed_hash);
    if (ret != 0) return WOLFMODEL_VERIFY_ERROR;

    if (ConstantCompare(computed_hash, ctx->sha256_digest,
                        WC_SHA256_DIGEST_SIZE) != 0)
        return WOLFMODEL_BAD_HASH;

    ctx->hash_ok = 1;

    /* --- Step H: Authenticity check (zero-and-fill method) --- */
    /*
     * Copy header, zero the signature VALUE bytes (not the tag/len),
     * hash the entire header copy, then verify the ECDSA signature
     * over that hash.
     *
     * sig_offset = byte offset of the 0x0020 tag TYPE field from image[0]
     * Signature value starts at sig_offset + 4 (after 2B tag + 2B length)
     */
    XMEMCPY(header_copy, image, WOLFMODEL_HEADER_SIZE);
    XMEMSET(header_copy + ctx->sig_offset + 4, 0, ctx->signature_size);

    ret = wc_InitSha256(&sha);
    if (ret != 0) return WOLFMODEL_VERIFY_ERROR;
    ret = wc_Sha256Update(&sha, header_copy, WOLFMODEL_HEADER_SIZE);
    if (ret != 0) return WOLFMODEL_VERIFY_ERROR;
    ret = wc_Sha256Final(&sha, header_hash);
    if (ret != 0) return WOLFMODEL_VERIFY_ERROR;

    /* Verify raw r||s signature using mp_int, same as wolfBoot image.c */
    {
        int verify_res = 0;
        mp_int r, s;

        mp_init(&r);
        mp_init(&s);
        mp_read_unsigned_bin(&r, ctx->signature, WOLFMODEL_ECC_KEY_SIZE);
        mp_read_unsigned_bin(&s, ctx->signature + WOLFMODEL_ECC_KEY_SIZE,
                             WOLFMODEL_ECC_KEY_SIZE);
        ret = wc_ecc_verify_hash_ex(&r, &s, header_hash,
                                    WC_SHA256_DIGEST_SIZE,
                                    &verify_res, &ctx->ecc);
        mp_free(&r);
        mp_free(&s);
        if (ret != 0)
            return WOLFMODEL_VERIFY_ERROR;
        if (verify_res != 1)
            return WOLFMODEL_BAD_SIG;
    }

    ctx->sig_ok = 1;

    /* --- Step I: TPM measurement --- */
    WOLFMODEL_TPM_MEASURE(header_hash, WC_SHA256_DIGEST_SIZE);

    /* --- Step J: DICE attestation --- */
    WOLFMODEL_DICE_ATTEST(header_hash, WC_SHA256_DIGEST_SIZE);

    return WOLFMODEL_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* wolfModel_GetVersion                                               */
/* ------------------------------------------------------------------ */

uint32_t wolfModel_GetVersion(const WOLFMODEL_CTX *ctx)
{
    if (ctx == NULL)
        return 0;
    return ctx->version;
}

/* ------------------------------------------------------------------ */
/* wolfModel_GetPayload                                               */
/* ------------------------------------------------------------------ */

/*
 * The returned pointer aliases the caller's image buffer.  It is valid
 * only while the original image buffer remains valid and unmodified.
 */
const uint8_t* wolfModel_GetPayload(const WOLFMODEL_CTX *ctx,
                                    uint32_t *payloadSz)
{
    if (ctx == NULL || payloadSz == NULL)
        return NULL;

    if (ctx->hash_ok && ctx->sig_ok) {
        *payloadSz = ctx->payload_size;
        return ctx->payload;
    }

    *payloadSz = 0;
    return NULL;
}

/* ------------------------------------------------------------------ */
/* wolfModel_GetAIBOMUrl                                              */
/* ------------------------------------------------------------------ */

const uint8_t* wolfModel_GetAIBOMUrl(const WOLFMODEL_CTX *ctx,
                                     uint16_t *urlSz)
{
    if (ctx == NULL || urlSz == NULL) {
        if (urlSz != NULL) *urlSz = 0;
        return NULL;
    }

    *urlSz = ctx->aibom_url_size;
    return ctx->aibom_url;
}

/* ------------------------------------------------------------------ */
/* wolfModel_Free                                                     */
/* ------------------------------------------------------------------ */

void wolfModel_Free(WOLFMODEL_CTX *ctx)
{
    if (ctx == NULL)
        return;

    if (ctx->key_set)
        wc_ecc_free(&ctx->ecc);

    ctx->key_set = 0;
    ctx->hdr_ok  = 0;
    ctx->hash_ok = 0;
    ctx->sig_ok  = 0;
}
