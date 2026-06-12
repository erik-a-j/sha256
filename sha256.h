#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>
#include <stddef.h>

void sha256(uint32_t* restrict dst, const uint8_t* restrict src, size_t len);

#endif /* #ifndef SHA256_H */
