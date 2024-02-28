// SPDX-License-Identifier: Apache-2.0

#ifndef api_h
#define api_h

#define SQI_CRYPTO_SECRETKEYBYTES  782
#define SQI_CRYPTO_PUBLICKEYBYTES   64
#define SQI_CRYPTO_BYTES           177

#define CRYPTO_ALGNAME "lvl1"

int
sqi_sqi_crypto_sign_keypair(unsigned char *pk, unsigned char *sk);

int
sqi_crypto_sign(unsigned char *sm, unsigned long long *smlen,
            const unsigned char *m, unsigned long long mlen,
            const unsigned char *sk);

int
sqi_crypto_sign_open(unsigned char *m, unsigned long long *mlen,
                 const unsigned char *sm, unsigned long long smlen,
                 const unsigned char *pk);

#endif /* api_h */
