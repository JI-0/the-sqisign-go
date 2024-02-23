#include "api.h"
// #include "sig.h"
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

int sqisigngo_sign(unsigned char *sm, unsigned long long *smlen,
            const unsigned char *m, unsigned long long mlen,
            const unsigned char *sk) {
    return crypto_sign(sm, smlen, m, mlen, sk);
}

int sqisigngo_verify(unsigned char *m, unsigned long long *mlen,
                 const unsigned char *sm, unsigned long long smlen,
                 const unsigned char *pk) {
    return crypto_sign_open(m, mlen, sm, smlen, pk);
}