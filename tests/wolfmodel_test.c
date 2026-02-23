/* wolfmodel_test.c
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include <wolfmodel/wolfmodel.h>

/* ------------------------------------------------------------------ */
/* Test macros                                                        */
/* ------------------------------------------------------------------ */

static int test_count  = 0;
static int test_passed = 0;
static int test_failed = 0;

#define TEST_ASSERT(cond, msg) do { \
    test_count++; \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d)\n", msg, __LINE__); \
        test_failed++; \
        return -1; \
    } else { \
        test_passed++; \
    } \
} while(0)

#define RUN_TEST(fn) do { \
    printf("Test: %s\n", #fn); \
    if (fn() == 0) { \
        printf("  PASS\n"); \
    } else { \
        printf("  ** FAILED **\n"); \
    } \
} while(0)

/* ------------------------------------------------------------------ */
/* Globals — large structs must not be on the stack                   */
/* ------------------------------------------------------------------ */

static WOLFMODEL_CTX ctx;
static ecc_key       test_key;
static WC_RNG        test_rng;
static wc_Sha256     test_sha;

#define ECC_KEY_SZ      32
#define TEST_PAYLOAD_SZ 128
#define HEADER_SZ       WOLFMODEL_HEADER_SIZE

/* ------------------------------------------------------------------ */
/* Helper: build a signed WMDL image using wolfCrypt directly         */
/*         (same logic as tools/sign/sign.c)                          */
/* ------------------------------------------------------------------ */

static void store_le16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
}

static void store_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
    p[2] = (uint8_t)((v >> 16) & 0xFF);
    p[3] = (uint8_t)((v >> 24) & 0xFF);
}

/*
 * Build a complete signed image into `out` (must be >= HEADER_SZ + payloadSz).
 * Uses the ecc_key `k` for signing.  Returns 0 on success.
 * pubkey_qx/qy are the raw 32-byte coordinates of the signer key (for hint).
 */
static int build_signed_image(uint8_t *out, uint32_t *outSz,
                              const uint8_t *payload, uint32_t payloadSz,
                              ecc_key *k, uint32_t version,
                              const uint8_t *pubkey_qx,
                              const uint8_t *pubkey_qy)
{
    uint32_t idx = 0;
    uint8_t payload_hash[WC_SHA256_DIGEST_SIZE];
    uint8_t pubkey_hash[WC_SHA256_DIGEST_SIZE];
    uint8_t header_hash[WC_SHA256_DIGEST_SIZE];
    uint8_t sig[WOLFMODEL_SIG_SIZE];
    uint32_t sig_off;
    uint16_t model_type = WOLFMODEL_TYPE_TFLITE;
    mp_int r, s;
    int ret;

    /* Hash payload */
    ret = wc_InitSha256(&test_sha);
    if (ret != 0) return ret;
    ret = wc_Sha256Update(&test_sha, payload, payloadSz);
    if (ret != 0) return ret;
    ret = wc_Sha256Final(&test_sha, payload_hash);
    if (ret != 0) return ret;

    /* Hash pubkey (Qx || Qy) for hint */
    ret = wc_InitSha256(&test_sha);
    if (ret != 0) return ret;
    ret = wc_Sha256Update(&test_sha, pubkey_qx, ECC_KEY_SZ);
    if (ret != 0) return ret;
    ret = wc_Sha256Update(&test_sha, pubkey_qy, ECC_KEY_SZ);
    if (ret != 0) return ret;
    ret = wc_Sha256Final(&test_sha, pubkey_hash);
    if (ret != 0) return ret;

    /* Build header */
    memset(out, 0xFF, HEADER_SZ);
    idx = 0;

    /* Magic + payload_size */
    store_le32(out + idx, WOLFMODEL_MAGIC); idx += 4;
    store_le32(out + idx, payloadSz);       idx += 4;

    /* TLV: Version */
    store_le16(out + idx, WOLFMODEL_TAG_VERSION); idx += 2;
    store_le16(out + idx, 4);                     idx += 2;
    store_le32(out + idx, version);               idx += 4;

    /* TLV: SHA-256 */
    store_le16(out + idx, WOLFMODEL_TAG_SHA256);        idx += 2;
    store_le16(out + idx, WC_SHA256_DIGEST_SIZE);       idx += 2;
    memcpy(out + idx, payload_hash, WC_SHA256_DIGEST_SIZE); idx += WC_SHA256_DIGEST_SIZE;

    /* TLV: Pubkey hint */
    store_le16(out + idx, WOLFMODEL_TAG_PUBKEY_HINT);   idx += 2;
    store_le16(out + idx, WC_SHA256_DIGEST_SIZE);       idx += 2;
    memcpy(out + idx, pubkey_hash, WC_SHA256_DIGEST_SIZE); idx += WC_SHA256_DIGEST_SIZE;

    /* TLV: Model type */
    store_le16(out + idx, WOLFMODEL_TAG_MODEL_TYPE);    idx += 2;
    store_le16(out + idx, 2);                           idx += 2;
    store_le16(out + idx, model_type);                  idx += 2;

    /* TLV: Signature (zeroed value — zero-and-fill) */
    sig_off = idx;
    store_le16(out + idx, WOLFMODEL_TAG_SIGNATURE);     idx += 2;
    store_le16(out + idx, WOLFMODEL_SIG_SIZE);          idx += 2;
    memset(out + idx, 0, WOLFMODEL_SIG_SIZE);           idx += WOLFMODEL_SIG_SIZE;

    /* TLV: End marker */
    store_le16(out + idx, WOLFMODEL_TAG_END);           idx += 2;

    /* Hash header (with zeroed sig) */
    ret = wc_InitSha256(&test_sha);
    if (ret != 0) return ret;
    ret = wc_Sha256Update(&test_sha, out, HEADER_SZ);
    if (ret != 0) return ret;
    ret = wc_Sha256Final(&test_sha, header_hash);
    if (ret != 0) return ret;

    /* Sign */
    mp_init(&r);
    mp_init(&s);
    ret = wc_ecc_sign_hash_ex(header_hash, WC_SHA256_DIGEST_SIZE,
                               &test_rng, k, &r, &s);
    if (ret != 0) { mp_clear(&r); mp_clear(&s); return ret; }

    memset(sig, 0, WOLFMODEL_SIG_SIZE);
    {
        int rSz = mp_unsigned_bin_size(&r);
        int sSz = mp_unsigned_bin_size(&s);
        mp_to_unsigned_bin(&r, &sig[ECC_KEY_SZ - rSz]);
        mp_to_unsigned_bin(&s, &sig[WOLFMODEL_SIG_SIZE - sSz]);
    }
    mp_clear(&r);
    mp_clear(&s);

    /* Drop signature into header */
    memcpy(out + sig_off + 4, sig, WOLFMODEL_SIG_SIZE);

    /* Copy payload after header */
    memcpy(out + HEADER_SZ, payload, payloadSz);
    *outSz = HEADER_SZ + payloadSz;

    return 0;
}

/* ------------------------------------------------------------------ */
/* Test 1: Self-sign round-trip                                       */
/* ------------------------------------------------------------------ */

static int test_roundtrip(void)
{
    uint8_t payload[TEST_PAYLOAD_SZ];
    uint8_t image[HEADER_SZ + TEST_PAYLOAD_SZ];
    uint32_t imageSz;
    uint8_t qx[ECC_KEY_SZ], qy[ECC_KEY_SZ];
    uint32_t qxSz = ECC_KEY_SZ, qySz = ECC_KEY_SZ;
    const uint8_t *result_payload;
    uint32_t result_sz;
    int ret;

    memset(payload, 0xAB, TEST_PAYLOAD_SZ);

    /* Export pubkey for hint and for loading */
    ret = wc_ecc_export_public_raw(&test_key, qx, &qxSz, qy, &qySz);
    TEST_ASSERT(ret == 0, "export pubkey");

    ret = build_signed_image(image, &imageSz, payload, TEST_PAYLOAD_SZ,
                             &test_key, 1, qx, qy);
    TEST_ASSERT(ret == 0, "build_signed_image");

    /* Load pubkey and verify */
    ret = wolfModel_Init(&ctx);
    TEST_ASSERT(ret == WOLFMODEL_SUCCESS, "init");

    {
        uint8_t pubkey_raw[64];
        memcpy(pubkey_raw, qx, ECC_KEY_SZ);
        memcpy(pubkey_raw + ECC_KEY_SZ, qy, ECC_KEY_SZ);
        ret = wolfModel_SetPubKey(&ctx, pubkey_raw, 64);
        TEST_ASSERT(ret == WOLFMODEL_SUCCESS, "set pubkey");
    }

    ret = wolfModel_Verify(&ctx, image, imageSz);
    TEST_ASSERT(ret == WOLFMODEL_SUCCESS, "verify");
    TEST_ASSERT(wolfModel_GetVersion(&ctx) == 1, "version");

    result_payload = wolfModel_GetPayload(&ctx, &result_sz);
    TEST_ASSERT(result_payload != NULL, "get payload not null");
    TEST_ASSERT(result_sz == TEST_PAYLOAD_SZ, "payload size");
    TEST_ASSERT(memcmp(result_payload, payload, TEST_PAYLOAD_SZ) == 0,
                "payload content");

    wolfModel_Free(&ctx);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Test 2: Tampered payload                                           */
/* ------------------------------------------------------------------ */

static int test_tampered_payload(void)
{
    uint8_t payload[TEST_PAYLOAD_SZ];
    uint8_t image[HEADER_SZ + TEST_PAYLOAD_SZ];
    uint32_t imageSz;
    uint8_t qx[ECC_KEY_SZ], qy[ECC_KEY_SZ];
    uint32_t qxSz = ECC_KEY_SZ, qySz = ECC_KEY_SZ;
    int ret;

    memset(payload, 0xAB, TEST_PAYLOAD_SZ);
    ret = wc_ecc_export_public_raw(&test_key, qx, &qxSz, qy, &qySz);
    TEST_ASSERT(ret == 0, "export pubkey");

    ret = build_signed_image(image, &imageSz, payload, TEST_PAYLOAD_SZ,
                             &test_key, 1, qx, qy);
    TEST_ASSERT(ret == 0, "build_signed_image");

    /* Tamper: flip a byte in the payload */
    image[HEADER_SZ + 10] ^= 0xFF;

    ret = wolfModel_Init(&ctx);
    TEST_ASSERT(ret == WOLFMODEL_SUCCESS, "init");

    {
        uint8_t pubkey_raw[64];
        memcpy(pubkey_raw, qx, ECC_KEY_SZ);
        memcpy(pubkey_raw + ECC_KEY_SZ, qy, ECC_KEY_SZ);
        ret = wolfModel_SetPubKey(&ctx, pubkey_raw, 64);
        TEST_ASSERT(ret == WOLFMODEL_SUCCESS, "set pubkey");
    }

    ret = wolfModel_Verify(&ctx, image, imageSz);
    TEST_ASSERT(ret == WOLFMODEL_BAD_HASH, "tampered -> BAD_HASH");

    wolfModel_Free(&ctx);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Test 3: Wrong key                                                  */
/* ------------------------------------------------------------------ */

static ecc_key wrong_key;

static int test_wrong_key(void)
{
    uint8_t payload[TEST_PAYLOAD_SZ];
    uint8_t image[HEADER_SZ + TEST_PAYLOAD_SZ];
    uint32_t imageSz;
    uint8_t qx[ECC_KEY_SZ], qy[ECC_KEY_SZ];
    uint32_t qxSz = ECC_KEY_SZ, qySz = ECC_KEY_SZ;
    uint8_t wqx[ECC_KEY_SZ], wqy[ECC_KEY_SZ];
    uint32_t wqxSz = ECC_KEY_SZ, wqySz = ECC_KEY_SZ;
    int ret;

    memset(payload, 0xCD, TEST_PAYLOAD_SZ);

    /* Sign with test_key */
    ret = wc_ecc_export_public_raw(&test_key, qx, &qxSz, qy, &qySz);
    TEST_ASSERT(ret == 0, "export pubkey");

    ret = build_signed_image(image, &imageSz, payload, TEST_PAYLOAD_SZ,
                             &test_key, 1, qx, qy);
    TEST_ASSERT(ret == 0, "build_signed_image");

    /* Generate a different key */
    ret = wc_ecc_init(&wrong_key);
    TEST_ASSERT(ret == 0, "wrong key init");
    ret = wc_ecc_make_key(&test_rng, ECC_KEY_SZ, &wrong_key);
    TEST_ASSERT(ret == 0, "wrong key make");

    ret = wc_ecc_export_public_raw(&wrong_key, wqx, &wqxSz, wqy, &wqySz);
    TEST_ASSERT(ret == 0, "export wrong pubkey");

    /* Verify with wrong key — should get KEY_ERROR (hint mismatch) or BAD_SIG */
    ret = wolfModel_Init(&ctx);
    TEST_ASSERT(ret == WOLFMODEL_SUCCESS, "init");

    {
        uint8_t pubkey_raw[64];
        memcpy(pubkey_raw, wqx, ECC_KEY_SZ);
        memcpy(pubkey_raw + ECC_KEY_SZ, wqy, ECC_KEY_SZ);
        ret = wolfModel_SetPubKey(&ctx, pubkey_raw, 64);
        TEST_ASSERT(ret == WOLFMODEL_SUCCESS, "set wrong pubkey");
    }

    ret = wolfModel_Verify(&ctx, image, imageSz);
    /* With PUBKEY_HINT present, wrong key triggers KEY_ERROR */
    TEST_ASSERT(ret == WOLFMODEL_KEY_ERROR, "wrong key -> KEY_ERROR");

    wolfModel_Free(&ctx);
    wc_ecc_free(&wrong_key);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Test 4: Truncated header                                           */
/* ------------------------------------------------------------------ */

static int test_truncated_header(void)
{
    uint8_t image[32]; /* way too small */
    int ret;

    memset(image, 0, sizeof(image));
    store_le32(image, WOLFMODEL_MAGIC);

    ret = wolfModel_Init(&ctx);
    TEST_ASSERT(ret == WOLFMODEL_SUCCESS, "init");

    {
        /* Need a key set to get past the key_set check */
        uint8_t qx[ECC_KEY_SZ], qy[ECC_KEY_SZ];
        uint32_t qxSz = ECC_KEY_SZ, qySz = ECC_KEY_SZ;
        uint8_t pubkey_raw[64];
        wc_ecc_export_public_raw(&test_key, qx, &qxSz, qy, &qySz);
        memcpy(pubkey_raw, qx, ECC_KEY_SZ);
        memcpy(pubkey_raw + ECC_KEY_SZ, qy, ECC_KEY_SZ);
        wolfModel_SetPubKey(&ctx, pubkey_raw, 64);
    }

    ret = wolfModel_Verify(&ctx, image, sizeof(image));
    TEST_ASSERT(ret == WOLFMODEL_BAD_HEADER, "truncated -> BAD_HEADER");

    wolfModel_Free(&ctx);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Test 5: Bad magic                                                  */
/* ------------------------------------------------------------------ */

static int test_bad_magic(void)
{
    uint8_t image[HEADER_SZ + TEST_PAYLOAD_SZ];
    uint32_t imageSz;
    uint8_t payload[TEST_PAYLOAD_SZ];
    uint8_t qx[ECC_KEY_SZ], qy[ECC_KEY_SZ];
    uint32_t qxSz = ECC_KEY_SZ, qySz = ECC_KEY_SZ;
    int ret;

    memset(payload, 0xEE, TEST_PAYLOAD_SZ);
    wc_ecc_export_public_raw(&test_key, qx, &qxSz, qy, &qySz);
    ret = build_signed_image(image, &imageSz, payload, TEST_PAYLOAD_SZ,
                             &test_key, 1, qx, qy);
    TEST_ASSERT(ret == 0, "build_signed_image");

    /* Corrupt magic */
    image[0] = 0x00;

    ret = wolfModel_Init(&ctx);
    TEST_ASSERT(ret == WOLFMODEL_SUCCESS, "init");

    {
        uint8_t pubkey_raw[64];
        memcpy(pubkey_raw, qx, ECC_KEY_SZ);
        memcpy(pubkey_raw + ECC_KEY_SZ, qy, ECC_KEY_SZ);
        wolfModel_SetPubKey(&ctx, pubkey_raw, 64);
    }

    ret = wolfModel_Verify(&ctx, image, imageSz);
    TEST_ASSERT(ret == WOLFMODEL_BAD_MAGIC, "bad magic -> BAD_MAGIC");

    wolfModel_Free(&ctx);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Test 6: Zero-length payload                                        */
/* ------------------------------------------------------------------ */

static int test_zero_payload(void)
{
    uint8_t image[HEADER_SZ];
    uint32_t imageSz;
    uint8_t qx[ECC_KEY_SZ], qy[ECC_KEY_SZ];
    uint32_t qxSz = ECC_KEY_SZ, qySz = ECC_KEY_SZ;
    int ret;

    wc_ecc_export_public_raw(&test_key, qx, &qxSz, qy, &qySz);

    /* Build with empty payload */
    ret = build_signed_image(image, &imageSz, (const uint8_t *)"", 0,
                             &test_key, 1, qx, qy);
    TEST_ASSERT(ret == 0, "build_signed_image (zero payload)");

    ret = wolfModel_Init(&ctx);
    TEST_ASSERT(ret == WOLFMODEL_SUCCESS, "init");

    {
        uint8_t pubkey_raw[64];
        memcpy(pubkey_raw, qx, ECC_KEY_SZ);
        memcpy(pubkey_raw + ECC_KEY_SZ, qy, ECC_KEY_SZ);
        wolfModel_SetPubKey(&ctx, pubkey_raw, 64);
    }

    ret = wolfModel_Verify(&ctx, image, imageSz);
    TEST_ASSERT(ret == WOLFMODEL_SUCCESS, "zero payload verify");

    wolfModel_Free(&ctx);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Test 7: PUBKEY_HINT mismatch                                       */
/* (Sign with key A's hint, verify with key B)                        */
/* ------------------------------------------------------------------ */

static ecc_key hint_wrong_key;

static int test_pubkey_hint_mismatch(void)
{
    uint8_t payload[TEST_PAYLOAD_SZ];
    uint8_t image[HEADER_SZ + TEST_PAYLOAD_SZ];
    uint32_t imageSz;
    uint8_t qx[ECC_KEY_SZ], qy[ECC_KEY_SZ];
    uint32_t qxSz = ECC_KEY_SZ, qySz = ECC_KEY_SZ;
    uint8_t bqx[ECC_KEY_SZ], bqy[ECC_KEY_SZ];
    uint32_t bqxSz = ECC_KEY_SZ, bqySz = ECC_KEY_SZ;
    int ret;

    memset(payload, 0x55, TEST_PAYLOAD_SZ);

    /* Sign with test_key, include test_key's hint */
    ret = wc_ecc_export_public_raw(&test_key, qx, &qxSz, qy, &qySz);
    TEST_ASSERT(ret == 0, "export key A pubkey");

    ret = build_signed_image(image, &imageSz, payload, TEST_PAYLOAD_SZ,
                             &test_key, 1, qx, qy);
    TEST_ASSERT(ret == 0, "build_signed_image");

    /* Generate key B */
    ret = wc_ecc_init(&hint_wrong_key);
    TEST_ASSERT(ret == 0, "key B init");
    ret = wc_ecc_make_key(&test_rng, ECC_KEY_SZ, &hint_wrong_key);
    TEST_ASSERT(ret == 0, "key B make");
    ret = wc_ecc_export_public_raw(&hint_wrong_key, bqx, &bqxSz, bqy, &bqySz);
    TEST_ASSERT(ret == 0, "export key B pubkey");

    /* Load key B for verification */
    ret = wolfModel_Init(&ctx);
    TEST_ASSERT(ret == WOLFMODEL_SUCCESS, "init");

    {
        uint8_t pubkey_raw[64];
        memcpy(pubkey_raw, bqx, ECC_KEY_SZ);
        memcpy(pubkey_raw + ECC_KEY_SZ, bqy, ECC_KEY_SZ);
        ret = wolfModel_SetPubKey(&ctx, pubkey_raw, 64);
        TEST_ASSERT(ret == WOLFMODEL_SUCCESS, "set key B");
    }

    /* Verify should fail — hint for key A, loaded key B */
    ret = wolfModel_Verify(&ctx, image, imageSz);
    TEST_ASSERT(ret == WOLFMODEL_KEY_ERROR, "hint mismatch -> KEY_ERROR");

    wolfModel_Free(&ctx);
    wc_ecc_free(&hint_wrong_key);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Test 8: Cross-tool validation (fixture from C signing tool)        */
/* ------------------------------------------------------------------ */

static int test_cross_tool(void)
{
    FILE *fwmdl, *fkey;
    long wmdl_sz, key_sz;
    uint8_t *wmdl_buf;
    uint8_t key_buf[64];
    int ret;

    fwmdl = fopen("tests/fixtures/dummy.wmdl", "rb");
    if (fwmdl == NULL) {
        printf("  SKIP: cross-tool test (fixture not found, run: make fixtures)\n");
        return 0;
    }

    fseek(fwmdl, 0, SEEK_END);
    wmdl_sz = ftell(fwmdl);
    fseek(fwmdl, 0, SEEK_SET);
    wmdl_buf = malloc((size_t)wmdl_sz);
    if (wmdl_buf == NULL) {
        fclose(fwmdl);
        TEST_ASSERT(0, "malloc for wmdl");
        return -1;
    }
    TEST_ASSERT(fread(wmdl_buf, 1, (size_t)wmdl_sz, fwmdl) == (size_t)wmdl_sz,
                "read wmdl");
    fclose(fwmdl);

    fkey = fopen("tests/fixtures/pubkey.der", "rb");
    TEST_ASSERT(fkey != NULL, "open pubkey.der");
    key_sz = fread(key_buf, 1, sizeof(key_buf), fkey);
    fclose(fkey);
    TEST_ASSERT(key_sz == 64, "pubkey.der is 64 bytes");

    ret = wolfModel_Init(&ctx);
    TEST_ASSERT(ret == WOLFMODEL_SUCCESS, "init");

    ret = wolfModel_SetPubKey(&ctx, key_buf, 64);
    TEST_ASSERT(ret == WOLFMODEL_SUCCESS, "set pubkey");

    ret = wolfModel_Verify(&ctx, wmdl_buf, (uint32_t)wmdl_sz);
    TEST_ASSERT(ret == WOLFMODEL_SUCCESS, "cross-tool verify");

    TEST_ASSERT(wolfModel_GetVersion(&ctx) == 1, "cross-tool version");

    {
        uint32_t payload_sz;
        const uint8_t *p = wolfModel_GetPayload(&ctx, &payload_sz);
        TEST_ASSERT(p != NULL, "cross-tool payload not null");
        TEST_ASSERT(payload_sz == 4096, "cross-tool payload size 4096");
    }

    wolfModel_Free(&ctx);
    free(wmdl_buf);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Main                                                               */
/* ------------------------------------------------------------------ */

int main(void)
{
    int ret;

    printf("wolfModel test suite\n");
    printf("====================\n\n");

    /* Initialize RNG and generate test key */
    ret = wc_InitRng(&test_rng);
    if (ret != 0) {
        printf("FATAL: wc_InitRng failed (%d)\n", ret);
        return 1;
    }
    ret = wc_ecc_init(&test_key);
    if (ret != 0) {
        printf("FATAL: wc_ecc_init failed (%d)\n", ret);
        return 1;
    }
    ret = wc_ecc_make_key(&test_rng, ECC_KEY_SZ, &test_key);
    if (ret != 0) {
        printf("FATAL: wc_ecc_make_key failed (%d)\n", ret);
        return 1;
    }

    RUN_TEST(test_roundtrip);
    RUN_TEST(test_tampered_payload);
    RUN_TEST(test_wrong_key);
    RUN_TEST(test_truncated_header);
    RUN_TEST(test_bad_magic);
    RUN_TEST(test_zero_payload);
    RUN_TEST(test_pubkey_hint_mismatch);
    RUN_TEST(test_cross_tool);

    printf("\n====================\n");
    printf("Results: %d passed, %d failed (of %d assertions)\n",
           test_passed, test_failed, test_count);

    wc_ecc_free(&test_key);
    wc_FreeRng(&test_rng);

    return (test_failed > 0) ? 1 : 0;
}
