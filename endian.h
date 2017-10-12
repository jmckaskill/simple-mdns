#pragma once

#include <stdint.h>

static inline uint16_t little_16(const uint8_t *p) {
	return ((uint16_t) p[0])
		| ((uint16_t) p[1] << 8);
}
static inline uint32_t little_32(const uint8_t *p) {
	return ((uint32_t) p[0])
		| ((uint32_t) p[1] << 8)
		| ((uint32_t) p[2] << 16)
		| ((uint32_t) p[3] << 24);
}
static inline uint64_t little_48(const uint8_t *p) {
	return ((uint64_t) p[0])
		 | ((uint64_t) p[1] << 8)
		 | ((uint64_t) p[2] << 16)
		 | ((uint64_t) p[3] << 24)
		 | ((uint64_t) p[4] << 32)
		 | ((uint64_t) p[5] << 40);
}
static inline uint64_t little_64(const uint8_t *p) {
	return ((uint64_t) p[0])
		| ((uint64_t) p[1] << 8)
		| ((uint64_t) p[2] << 16)
		| ((uint64_t) p[3] << 24)
		| ((uint64_t) p[4] << 32)
		| ((uint64_t) p[5] << 40)
		| ((uint64_t) p[6] << 48)
		| ((uint64_t) p[7] << 56);
}

static inline void write_little_16(uint8_t *p, uint16_t v) {
	p[0] = (uint8_t) (v);
	p[1] = (uint8_t) (v >> 8);
}
static inline void write_little_32(uint8_t *p, uint32_t v) {
	p[0] = (uint8_t) (v);
	p[1] = (uint8_t) (v >> 8);
	p[2] = (uint8_t) (v >> 16);
	p[3] = (uint8_t) (v >> 24);
}
static inline void write_little_48(uint8_t *p, uint64_t v) {
	p[0] = (uint8_t) (v);
	p[1] = (uint8_t) (v >> 8);
	p[2] = (uint8_t) (v >> 16);
	p[3] = (uint8_t) (v >> 24);
	p[4] = (uint8_t) (v >> 32);
	p[5] = (uint8_t) (v >> 40);
}
static inline void write_little_64(uint8_t *p, uint64_t v) {
	p[0] = (uint8_t) (v);
	p[1] = (uint8_t) (v >> 8);
	p[2] = (uint8_t) (v >> 16);
	p[3] = (uint8_t) (v >> 24);
	p[4] = (uint8_t) (v >> 32);
	p[5] = (uint8_t) (v >> 40);
	p[6] = (uint8_t) (v >> 48);
	p[7] = (uint8_t) (v >> 56);
}

static inline uint16_t big_16(const uint8_t *p) {
    return ((uint16_t) p[0] << 8) 
         | ((uint16_t) p[1]);
}
static inline uint32_t big_32(const uint8_t *p) {
    return ((uint32_t) p[0] << 24)
         | ((uint32_t) p[1] << 16)
         | ((uint32_t) p[2] << 8)
         | ((uint32_t) p[3]);
}
static inline uint64_t big_48(const uint8_t *p) {
    return ((uint64_t) p[0] << 40)
         | ((uint64_t) p[1] << 32)
         | ((uint64_t) p[2] << 24)
         | ((uint64_t) p[3] << 16)
         | ((uint64_t) p[4] << 8)
         | ((uint64_t) p[5]);
}
static inline uint64_t big_64(const uint8_t *p) {
    return ((uint64_t) p[0] << 56)
         | ((uint64_t) p[1] << 48)
         | ((uint64_t) p[2] << 40)
         | ((uint64_t) p[3] << 32)
         | ((uint64_t) p[4] << 24)
         | ((uint64_t) p[5] << 16)
         | ((uint64_t) p[6] << 8)
         | ((uint64_t) p[7]);
}
static inline void write_big_16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t) (v >> 8);
    p[1] = (uint8_t) (v);
}
static inline void write_big_32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t) (v >> 24);
    p[1] = (uint8_t) (v >> 16);
    p[2] = (uint8_t) (v >> 8);
    p[3] = (uint8_t) (v);
}
static inline void write_big_48(uint8_t *p, uint64_t v) {
    p[0] = (uint8_t) (v >> 40);
    p[1] = (uint8_t) (v >> 32);
    p[2] = (uint8_t) (v >> 24);
    p[3] = (uint8_t) (v >> 16);
    p[4] = (uint8_t) (v >> 8);
    p[5] = (uint8_t) (v);
}
static inline void write_big_64(uint8_t *p, uint64_t v) {
    p[0] = (uint8_t) (v >> 56);
    p[1] = (uint8_t) (v >> 48);
    p[2] = (uint8_t) (v >> 40);
    p[3] = (uint8_t) (v >> 32);
    p[4] = (uint8_t) (v >> 24);
    p[5] = (uint8_t) (v >> 16);
    p[6] = (uint8_t) (v >> 8);
    p[7] = (uint8_t) (v);
}


