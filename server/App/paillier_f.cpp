#include <iostream>
#include <cstdlib>
#include <random>
#include "Enclave_u.h"
#include <sgx_urts.h>
#include "error_print.h"

#include "paillier_s.hpp"

const uint32_t primes_ones_place[4] = {1, 3, 7, 9};

uint64_t powmod(uint64_t b, uint16_t e, uint64_t m)
{
    uint64_t res = 1;

    while (e > 0) {
        if ((e & 1) == 1) res = (res*b) % m;
        e >>= 1;
        b = (b*b) % m;
    }

    return res;
}

uint32_t gcd(uint32_t x, uint32_t y)
{
    uint32_t r;

    while ((r = x % y) != 0) {
        x = y;
        y = r;
    }

    return y;
}

uint32_t lcm(uint32_t x, uint32_t y)
{
    return (x * y / gcd(x,y));
}

void swap(int64_t* a, int64_t* b)
{
    int64_t w = *a;
    *a = *b;
    *b = w;
}

int64_t modinv(uint32_t aa, uint32_t m)
{
    if (gcd(aa, m) != 1) return 0;

    int64_t a = (int64_t)aa, b = (int64_t)m, u = 1, v = 0;

    while (b) {
        int64_t t = a / b;
        a -= t * b; swap(&a, &b);
        u -= t * v; swap(&u, &v);
    }

    u %= m;
    if (u < 0) u += m;
    return u;
}

int miller_rabin_test(uint16_t n, uint8_t k, uint16_t m)
{
    std::random_device seed_gen;
    std::mt19937 engine(seed_gen());
    std::uniform_int_distribution<uint16_t> get_rand(2, n-1);

    uint16_t a = get_rand(engine);

    uint64_t b = powmod(a, m, n);

    if (b == 1) return 1;

    for (int i = 0; i < (int)k; ++i) {
        if (b == n-1) return 1;
        b = powmod(b, 2, n);
    }

    return 0;
}

int is_prime(uint32_t n)
{
    if (n <= 1) return 0;
    if (n == 2) return 1;

    uint8_t k = 0;
    uint32_t m = n-1;

    while ((m & 1) == 0) {
        k += 1;
        m >>= 1;
    }

    for (int i = 0; i < 20; ++i) {
        if (miller_rabin_test(n, k, m) == 0) return 0;
    }

    return 1;
}

uint32_t get_random_prime()
{
    std::random_device seed;
    std::mt19937 engine(seed());
    std::uniform_int_distribution<uint32_t> rnd(128, UINT8_MAX);

    while (1) {
        uint32_t p = rnd(engine);
        int i;
        for (i = 0; i < 4; ++i) {
            if (p%(uint32_t)10 <= primes_ones_place[i]) break;
        }

        while (p%(uint32_t)10 < primes_ones_place[i]) ++p;

        while (p < UINT8_MAX) {
            if (is_prime(p)) return p;

            int j = (i+1) % 4;
            int sub = 2;
            if (j != 0) sub = primes_ones_place[j] - primes_ones_place[i];

            p += sub;
            i = j;
        }
    }
}

uint64_t L(uint64_t x, uint64_t n)
{
    return (x - 1) / n;
}

void paillier_create_keys(struct PPubKey* ppubkey, PPrvKey* pprvkey)
{
    uint32_t p, q;
    do {
        p = get_random_prime();
        q = get_random_prime();
    } while (p == q);

    ppubkey->n = p * q;
    uint64_t n = ppubkey->n;

    pprvkey->lambda = lcm(p-1, q-1);

    std::random_device seed;
    std::mt19937_64 engine(seed());
    std::uniform_int_distribution<uint64_t> rnd(2, n*n);
    

    do {
        ppubkey->g = rnd(engine);
        pprvkey->mu = modinv(L(powmod(ppubkey->g, pprvkey->lambda, n*n), n) % n, n);
    } while (pprvkey->mu == 0);
}

uint64_t paillier_encryption(int m, struct PPubKey* ppubkey)
{
    uint32_t n = ppubkey->n;
    uint64_t g = ppubkey->g;
    uint64_t nn = n * n;

    std::random_device seed;
    std::mt19937 engine(seed());
    std::uniform_int_distribution<uint32_t> rnd(2, n);
    uint32_t r;
    while (1) {
        r = rnd(engine);
        if (gcd(r, n) == 1) break;
    }

    return (powmod(g, m, nn) * powmod(r, n, nn)) % nn;
}

int paillier_decryption(uint64_t c, struct PPubKey* ppubkey, PPrvKey* pprvkey)
{
    uint32_t n = ppubkey->n;
    uint64_t nn = n*n;
    uint32_t lambda = pprvkey->lambda;
    uint32_t mu = pprvkey->mu;
    return (L(powmod(c, lambda, nn), n) * mu) % n;
}

uint64_t paillier_add(uint64_t c1, uint64_t c2, struct PPubKey* ppubkey)
{
    uint32_t n = ppubkey->n;
    uint64_t nn = n*n;
    return (c1 * c2) % nn;
}
