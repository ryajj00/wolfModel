/* keygen.c
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
#include <errno.h>
#include <sys/stat.h>

#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#define ECC256_KEY_SIZE 32

static void usage(const char *pname)
{
    printf("Usage: %s <output_directory>\n", pname);
    printf("\nGenerates:\n");
    printf("  <output_directory>/ecc256.der   - Private key (Qx+Qy+d, 96 bytes)\n");
    printf("  <output_directory>/pubkey.der   - Public key  (Qx+Qy, 64 bytes)\n");
    exit(1);
}

/* Large structs in .bss, not on the stack */
static ecc_key k;
static WC_RNG  rng;

int main(int argc, char **argv)
{
    uint8_t Qx[ECC256_KEY_SIZE], Qy[ECC256_KEY_SIZE], d[ECC256_KEY_SIZE];
    uint32_t qxSz = ECC256_KEY_SIZE;
    uint32_t qySz = ECC256_KEY_SIZE;
    uint32_t dSz  = ECC256_KEY_SIZE;
    FILE *f;
    char path[512];
    const char *outdir;
    int ret;

    if (argc != 2) {
        usage(argv[0]);
    }
    outdir = argv[1];

    /* Create output directory if needed */
    (void)mkdir(outdir, 0755);

    /* Initialize RNG and generate key */
    ret = wc_InitRng(&rng);
    if (ret != 0) {
        fprintf(stderr, "Error: wc_InitRng failed (%d)\n", ret);
        return 1;
    }

    ret = wc_ecc_init(&k);
    if (ret != 0) {
        fprintf(stderr, "Error: wc_ecc_init failed (%d)\n", ret);
        wc_FreeRng(&rng);
        return 1;
    }

    ret = wc_ecc_make_key(&rng, ECC256_KEY_SIZE, &k);
    if (ret != 0) {
        fprintf(stderr, "Error: wc_ecc_make_key failed (%d)\n", ret);
        wc_ecc_free(&k);
        wc_FreeRng(&rng);
        return 1;
    }

    /* Export raw key components */
    ret = wc_ecc_export_private_raw(&k, Qx, &qxSz, Qy, &qySz, d, &dSz);
    if (ret != 0) {
        fprintf(stderr, "Error: wc_ecc_export_private_raw failed (%d)\n", ret);
        wc_ecc_free(&k);
        wc_FreeRng(&rng);
        return 1;
    }

    /* Write private key: Qx || Qy || d (96 bytes) */
    snprintf(path, sizeof(path), "%s/ecc256.der", outdir);
    f = fopen(path, "wb");
    if (f == NULL) {
        fprintf(stderr, "Error: cannot open %s: %s\n", path, strerror(errno));
        wc_ecc_free(&k);
        wc_FreeRng(&rng);
        return 1;
    }
    fwrite(Qx, 1, qxSz, f);
    fwrite(Qy, 1, qySz, f);
    fwrite(d,  1, dSz,  f);
    fclose(f);
    printf("Private key: %s (96 bytes)\n", path);

    /* Write public key: Qx || Qy (64 bytes) */
    snprintf(path, sizeof(path), "%s/pubkey.der", outdir);
    f = fopen(path, "wb");
    if (f == NULL) {
        fprintf(stderr, "Error: cannot open %s: %s\n", path, strerror(errno));
        wc_ecc_free(&k);
        wc_FreeRng(&rng);
        return 1;
    }
    fwrite(Qx, 1, qxSz, f);
    fwrite(Qy, 1, qySz, f);
    fclose(f);
    printf("Public key:  %s (64 bytes)\n", path);

    wc_ecc_free(&k);
    wc_FreeRng(&rng);
    return 0;
}
