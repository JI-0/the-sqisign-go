#include "api.h"
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#define CRYPTO_SECRETKEYBYTES  782
#define CRYPTO_PUBLICKEYBYTES   64
#define CRYPTO_BYTES           177

int sqisigngo_gen_keypair(void *pk, void *sk) {
    int res = crypto_sign_keypair((unsigned char *)pk, (unsigned char *)sk);

    return res;
}

int sqisigngo_sign(void *out, char *m, char *sk) {
    unsigned long long mlen = strlen(m);
    unsigned char *sig = (unsigned char *)malloc(CRYPTO_BYTES + mlen);
    unsigned long long siglen = CRYPTO_BYTES + mlen;

    int res = crypto_sign(sig, &siglen, (unsigned char *)m, mlen, (unsigned char *)sk);

    memcpy(out, sig, CRYPTO_BYTES);

    free(sig);

    return res;
}

int sqisigngo_verify(char *m, char *sm, char *pk) {
    unsigned long long mlen = strlen(m);
    unsigned char *sig = (unsigned char *)malloc(CRYPTO_BYTES + mlen);

    memcpy(sig, sm, CRYPTO_BYTES);
    memcpy(sig + CRYPTO_BYTES, m, mlen);

    int r = crypto_sign_open((unsigned char *)m, &mlen, sig, CRYPTO_BYTES + mlen, (unsigned char *)pk);

    free(sig);

    return r;
}