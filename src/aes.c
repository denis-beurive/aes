/**
 * @file This file implements the AES algorithm.
 *
 * Define "TRACE" if you want to generate test vectors.
 */

#ifdef TRACE
#include <stdio.h>
#endif
#include "aes.h"

#ifdef TRACE

/**
 * Generate the textual representation of a state.
 *
 * State, as stored in memory: 00 04 08 0C 01 05 09 0D 02 06 0A 0E 03 07 0B 0F
 * The textual representation of the state: 0004080C 0105090D 02060A0E 03070B0F
 *
 * @param state The state that we need to represent as a string.
 * @param output_buffer The buffer used to store the string of characters that represents the state.
 */

void aes_state_to_string(const uint8_t state[16], char output_buffer[33]) {
    uint8_t p = 0, decal = 0;
    for (int i=0; i<16; i++) {
        sprintf(&output_buffer[decal], "%02x", state[p++]);
        decal += 2;
    }
    output_buffer[decal] = 0;
}

/**
 * Print a state to the standard output.
 *
 * @param prefix Decription to print.
 * @param state State to print.
 */

void aes_dump_state(const char* const prefix, const uint8_t state[16]) {
    char intern[36];
    aes_state_to_string(state, intern);
    printf("%s%s", prefix, intern);
}

void aes256_dump_expanded_keys(const uint8_t keys[240]) {
    for (uint8_t ki=0; ki<240/16; ki++) {
        printf("key%u:", ki);
        for (int p=0; p<16; p++) {
            printf("%02x", keys[ki*16+p]);
        }
        printf("\n");
    }
}

void aes256_dump_key(const char* const prefix, const uint8_t key[32]) {
    printf("%s", prefix);
    for (int p=0; p<32; p++) {
        printf("%02x", key[p]);
    }
}

#endif

static const uint8_t forward_sbox[16][16] = {
    {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
    {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
    {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
    {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
    {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
    {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
    {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
    {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
    {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
    {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
    {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
    {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
    {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
    {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
    {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
    {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16},
};

static const uint8_t reverse_sbox[16][16] = {
    {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
    {0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
    {0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
    {0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},
    {0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
    {0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
    {0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},
    {0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},
    {0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
    {0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
    {0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
    {0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
    {0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
    {0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
    {0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
    {0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d},
};

static uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for(int counter = 0; counter < 8; counter++) {
        if ((b & 1) == 1) p ^= a;
        const uint8_t hi_bit_set = (a & 0x80);
        a <<= 1;
        if(hi_bit_set == 0x80) a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

static uint8_t rcon(uint8_t in) {
    uint8_t c=1;
    if (0 == in)
        return 0;
    while(in != 1) {
        c = gmul(c,2);
        in--;
    }
    return c;
}

static void rotate(uint8_t *in) {
    const uint8_t a = in[0];
    for(int c=0; c<3; c++) { in[c] = in[c + 1]; }
    in[3] = a;
}

static uint8_t aes_forward_sbox(const uint8_t value) {
    uint8_t line = (value & 0xF0) >> 4;
    uint8_t column = value & 0x0F;
    return forward_sbox[line][column];
}

static uint8_t aes_reverse_sbox(const uint8_t value) {
    uint8_t line = (value & 0xF0) >> 4;
    uint8_t column = value & 0x0F;
    return reverse_sbox[line][column];
}

static void schedule_core(uint8_t *in, const uint8_t i) {
    /* Rotate the input 8 bits to the left */
    rotate(in);
    /* Apply Rijndael's s-box on all 4 bytes */
    for(int a = 0; a < 4; a++) { in[a] = aes_forward_sbox(in[a]); }
    /* On just the first byte, add 2^i to the byte */
    in[0] ^= rcon(i);
}


/**
 * In place expansion of a 256-bit (32 bytes) key. The result is a 240-byte expanded key.
 *
 * Please note that: 240 = 15 * 16. Thus, we create 15 keys, 16-byte long each.
 *
 * 16x16-bit = 4x4-byte:
 *
 *     byte1   byte2   byte3   byte4
 *     byte5   byte6   byte7   byte8
 *     byte9   byte10  byte11  byte12
 *     byte13  byte14  byte15  byte16
 *
 * AES256 requires fifteen 128-bit (16 bytes) "round keys".
 *
 * @param key The 256-bit key to expand.
 *        WARNING: the expansion is done "in place". This means that the memory zone that contains the given 256-bit
 *        key must be long enough to store the 240-bytes expanded key.
 * @see Rijndael's key schedule (https://www.samiam.org/key-schedule.html).
 */

void aes256_expand_key(uint8_t key[240]) {
    uint8_t t[4];
    uint8_t c = 32;
    uint8_t i = 1;

    while(c < 240) {
        /* Copy the temporary variable over */
        for (uint8_t a = 0; a < 4; a++)
            t[a] = key[a + c - 4];
        /* Every eight sets, do a complex calculation */
        if(c % 32 == 0) {
            schedule_core(t,i);
            i++;
        }
        /* For 256-bit keys, we add an extra sbox to the
         * calculation */
        if (c % 32 == 16) {
            for(int a = 0; a < 4; a++) { t[a] = aes_forward_sbox(t[a]); }
        }
        for (int a = 0; a < 4; a++) {
            key[c] = key[c - 32] ^ t[a];
            c++;
        }
    }
}

/**
 * Perform the MixColumns operation on a column.
 *
 * @param column The column.
 * @see Rijndael's mix column stage (https://en.wikipedia.org/wiki/Rijndael_MixColumns)
 */

static void aes_gmix_column(uint8_t *column) {
    uint8_t a[4];
    uint8_t b[4];
    /* The array 'a' is simply a copy of the input array 'column'
     * The array 'b' is each element of the array 'a' multiplied by 2
     * in Rijndael's Galois field
     * a[n] ^ b[n] is element n multiplied by 3 in Rijndael's Galois field */
    for (int c = 0; c < 4; c++) {
        const uint8_t h = column[c] >> 7; // `h` is set to `0x01` if the high bit of `column[c]` is set, `0x00` otherwise
        a[c] = column[c];
        b[c] = column[c] << 1; // implicitly removes high bit because `b[c]` is an 8-bit char, so we xor by `0x1b` and not `0x11b` in the next line
        b[c] ^= h * 0x1B; // Rijndael's Galois field
    }
    column[0] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1]; /* 2 * a0 + a3 + a2 + 3 * a1 */
    column[1] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2]; /* 2 * a1 + a0 + a3 + 3 * a2 */
    column[2] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3]; /* 2 * a2 + a1 + a0 + 3 * a3 */
    column[3] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0]; /* 2 * a3 + a2 + a1 + 3 * a0 */
}

/**
 * Perform the MixColumns operation on a state.
 *
 * @param state The state.
 * @see Rijndael's mix column stage (https://en.wikipedia.org/wiki/Rijndael_MixColumns)
 */

void aes_mix_columns(uint8_t state[16]) {
    for (int line=0; line<4; line++) {
        aes_gmix_column(&state[line*4]);
    }
}

/**
 * Perform the round key transformation: each byte of the state is combined with a byte of the round key
 * using bitwise XOR.
 *
 * @param state 16x16-bit (4x4-byte) bloc of data to be encrypted.
 * @param round_key The round key.
 */

// TODO: add unit test
void aes_add_round_key(uint8_t state[16], const uint8_t round_key[16]) {
    for (int i=0; i<16; i++) {
        state[i] ^= round_key[i];
    }
}

/**
 * Perform the SubBytes transformation: each byte is replaced with another according to the forward S-box.
 *
 * @param state 16x16-bit (4x4-byte) bloc of data to be encrypted.
 */

// TODO: add unit test
void aes_sub_bytes(uint8_t state[16]) {
    for (int i=0; i<16; i++) {
        state[i] = aes_forward_sbox(state[i]);
    }
}

// TODO: add unit test
void aes_shift_rows(uint8_t state[16]) {
    const uint8_t v1 = state[1];
    state[1]  = state[5];
    state[5]  = state[9];
    state[9]  = state[13];
    state[13] = v1;

    const uint8_t v2 = state[2];
    const uint8_t v6 = state[6];
    state[2]  = state[10];
    state[6]  = state[14];
    state[10] = v2;
    state[14] = v6;

    const uint8_t v3 = state[3];
    const uint8_t v7 = state[7];
    const uint8_t v11 = state[11];
    state[3]  = state[15];
    state[7]  = v3;
    state[11] = v7;
    state[15] = v11;
}

void aes256_cypher(uint8_t state[16], const uint8_t keys[240]) {

#ifdef TRACE
    printf("# Round 0\n\n");

    aes_dump_state("input:", state);
    printf("\n");
#endif
    // AddRoundKey with K0.
    aes_add_round_key(state, keys);
#ifdef TRACE
    aes_dump_state("output:", state);
    printf("\n\n");
#endif

    for (int round=1; round<=13; round++) {
#ifdef TRACE
        printf("# Round %d\n\n", round);
#endif
        aes_sub_bytes(state);
#ifdef TRACE
        aes_dump_state("sub:", state);
        printf("\n");
#endif

        aes_shift_rows(state);
#ifdef TRACE
        aes_dump_state("shift:", state);
        printf("\n");
#endif

        aes_mix_columns(state);
#ifdef TRACE
        aes_dump_state("mix:", state);
        printf("\n");
#endif
        aes_add_round_key(state, keys + round*16);
#ifdef TRACE
        aes_dump_state("add key:", state);
        printf("\n\n");
#endif

    }

#ifdef TRACE
    printf("# Round 16\n\n");
#endif
    aes_sub_bytes(state);
#ifdef TRACE
    aes_dump_state("sub:", state);
    printf("\n");
#endif
    aes_shift_rows(state);
#ifdef TRACE
    aes_dump_state("shift:", state);
    printf("\n");
#endif
    aes_add_round_key(state, keys + 14*16);
#ifdef TRACE
    aes_dump_state("add key:", state);
    printf("\n");
#endif
}

