#include "api.h"
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

// #define CRYPTO_SECRETKEYBYTES  782
// #define CRYPTO_PUBLICKEYBYTES   64
// #define CRYPTO_BYTES           177

int sqisigngo_gen_keypair(void *pk, void *sk) {
    int res = sqi_sqi_crypto_sign_keypair((unsigned char *)pk, (unsigned char *)sk);

    return res;
}

int sqisigngo_sign(void *out, char *m, char *sk) {
    unsigned long long mlen = strlen(m);
    unsigned char *sig = (unsigned char *)malloc(177 + mlen);
    unsigned long long siglen = 177 + mlen;

    int res = sqi_crypto_sign(sig, &siglen, (unsigned char *)m, mlen, (unsigned char *)sk);

    memcpy(out, sig, 177);

    free(sig);

    return res;
}

int sqisigngo_verify(char *m, char *sm, char *pk) {
    unsigned long long mlen = strlen(m);
    unsigned char *sig = (unsigned char *)malloc(177 + mlen);

    memcpy(sig, sm, 177);
    memcpy(sig + 177, m, mlen);

    int r = sqi_crypto_sign_open((unsigned char *)m, &mlen, sig, 177 + mlen, (unsigned char *)pk);

    free(sig);

    return r;
}