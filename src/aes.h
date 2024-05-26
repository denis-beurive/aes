#ifndef AES_H
#define AES_H

#include <stdint.h>

#ifdef TRACE
void aes_state_to_string(const uint8_t state[16], char output_buffer[33]);
void aes_dump_state(const char* const prefix, const uint8_t state[16]);
void aes256_dump_expanded_keys(const uint8_t keys[240]);
void aes256_dump_key(const char* const prefix, const uint8_t key[32]);
#endif

// Private API exported for unit tests
void aes_add_round_key(uint8_t state[16], const uint8_t round_key[16]);
void aes_sub_bytes(uint8_t state[16]);
void aes_mix_columns(uint8_t state[16]);
void aes_shift_rows(uint8_t state[16]);

// Public API
void aes256_expand_key(uint8_t key[240]);
void aes256_cypher(uint8_t state[16], const uint8_t keys[240]);

#endif //AES_H
