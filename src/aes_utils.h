#ifndef AES_UTILS_H
#define AES_UTILS_H

#include <stdint.h>

uint8_t aes_calculate_forward_sbox(const uint8_t in);
uint8_t aes_calculate_reverse_sbox(const uint8_t in);
void aes_mix_single_column(uint8_t column[4]);

#endif //AES_UTILS_H
