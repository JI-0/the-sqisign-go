#include "api.h"
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#define CRYPTO_SECRETKEYBYTES  782
#define CRYPTO_PUBLICKEYBYTES   64
#define CRYPTO_BYTES           177

int sqisigngo_gen_keypair(void *pk, void *sk) {
    unsigned char *pkc  = (unsigned char *)malloc(CRYPTO_PUBLICKEYBYTES);
    unsigned char *skc  = (unsigned char *)malloc(CRYPTO_SECRETKEYBYTES);

    int res = crypto_sign_keypair(pkc, skc);

    memcpy(pk, pkc, CRYPTO_PUBLICKEYBYTES);
    memcpy(sk, skc, CRYPTO_SECRETKEYBYTES);

    free(pkc);
    free(skc);

    return res;
}

int sqisigngo_sign(void *out, char *m, char *sk) {
    unsigned long long mlen = strlen(m);
    unsigned char *sig = (unsigned char *)malloc(CRYPTO_BYTES + mlen);
    unsigned long long siglen = CRYPTO_BYTES + mlen;

    int res = crypto_sign(sig, &siglen, (const unsigned char *)m, mlen, (const unsigned char *)sk);

    memcpy(out, sig, siglen);

    free(sig);

    return res;
}

int sqisigngo_verify(char *m, char *sm, char *pk) {
    unsigned long long mlen = strlen(m);

    return crypto_sign_open((unsigned char *)m, &mlen, (const unsigned char *)sm, CRYPTO_BYTES + mlen, (const unsigned char *)pk);
}