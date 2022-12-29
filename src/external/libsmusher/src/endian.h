#ifndef _LIBSMUSHER_ENDIAN_H
#define _LIBSMUSHER_ENDIAN_H

#include <stdint.h>

static inline uint64_t getle64(const uint8_t* p)
{
    uint64_t n = p[0];

    n |= (uint64_t)p[1] << 8;
    n |= (uint64_t)p[2] << 16;
    n |= (uint64_t)p[3] << 24;
    n |= (uint64_t)p[4] << 32;
    n |= (uint64_t)p[5] << 40;
    n |= (uint64_t)p[6] << 48;
    n |= (uint64_t)p[7] << 56;
    return n;
}

static inline uint64_t getbe64(const uint8_t* p)
{
    uint64_t n = 0;

    n |= (uint64_t)p[0] << 56;
    n |= (uint64_t)p[1] << 48;
    n |= (uint64_t)p[2] << 40;
    n |= (uint64_t)p[3] << 32;
    n |= (uint64_t)p[4] << 24;
    n |= (uint64_t)p[5] << 16;
    n |= (uint64_t)p[6] << 8;
    n |= (uint64_t)p[7] << 0;
    return n;
}

static inline uint64_t getbe48(const uint8_t* p)
{
    uint64_t n = 0;

    n |= (uint64_t)p[0] << 40;
    n |= (uint64_t)p[1] << 32;
    n |= (uint64_t)p[2] << 24;
    n |= (uint64_t)p[3] << 16;
    n |= (uint64_t)p[4] << 8;
    n |= (uint64_t)p[5] << 0;
    return n;
}

static inline uint64_t getle48(const uint8_t* p)
{
    uint64_t n = p[0];

    n |= (uint64_t)p[1] << 8;
    n |= (uint64_t)p[2] << 16;
    n |= (uint64_t)p[3] << 24;
    n |= (uint64_t)p[4] << 32;
    n |= (uint64_t)p[5] << 40;
    return n;
}

static inline uint32_t getle32(const uint8_t* p)
{
    return (p[0]<<0) | (p[1]<<8) | (p[2]<<16) | (p[3]<<24);
}

static inline uint32_t getbe32(const uint8_t* p)
{
    return (p[0]<<24) | (p[1]<<16) | (p[2]<<8) | (p[3]<<0);
}

static inline uint32_t getle16(const uint8_t* p)
{
    return (p[0]<<0) | (p[1]<<8);
}

static inline int16_t getles16(const uint8_t* p)
{
    return (p[0]<<0) | (p[1]<<8);
}

static inline uint32_t getbe16(const uint8_t* p)
{
    return (p[0]<<8) | (p[1]<<0);
}

static inline void putle16(uint8_t* p, uint16_t n)
{
    p[0] = (uint8_t) n;
    p[1] = (uint8_t) (n>>8);
}

static inline void putle32(uint8_t* p, uint32_t n)
{
    p[0] = (uint8_t) n;
    p[1] = (uint8_t) (n>>8);
    p[2] = (uint8_t) (n>>16);
    p[3] = (uint8_t) (n>>24);
}

static inline void putle48(uint8_t* p, uint64_t n)
{
    p[0] = (uint8_t)n;
    p[1] = (uint8_t)(n >> 8);
    p[2] = (uint8_t)(n >> 16);
    p[3] = (uint8_t)(n >> 24);
    p[4] = (uint8_t)(n >> 32);
    p[5] = (uint8_t)(n >> 40);
}

static inline void putle64(uint8_t* p, uint64_t n)
{
    p[0] = (uint8_t) n;
    p[1] = (uint8_t) (n >> 8);
    p[2] = (uint8_t) (n >> 16);
    p[3] = (uint8_t) (n >> 24);
    p[4] = (uint8_t) (n >> 32);
    p[5] = (uint8_t) (n >> 40);
    p[6] = (uint8_t) (n >> 48);
    p[7] = (uint8_t) (n >> 56);
}

static inline void putbe16(uint8_t* p, uint16_t n)
{
    p[1] = (uint8_t) n;
    p[0] = (uint8_t) (n >> 8);
}

static inline void putbe32(uint8_t* p, uint32_t n)
{
    p[3] = (uint8_t) n;
    p[2] = (uint8_t) (n >> 8);
    p[1] = (uint8_t) (n >> 16);
    p[0] = (uint8_t) (n >> 24);
}

static inline void putbe48(uint8_t* p, uint64_t n)
{
    p[5] = (uint8_t)n;
    p[4] = (uint8_t)(n >> 8);
    p[3] = (uint8_t)(n >> 16);
    p[2] = (uint8_t)(n >> 24);
    p[1] = (uint8_t)(n >> 32);
    p[0] = (uint8_t)(n >> 40);
}

static inline void putbe64(uint8_t* p, uint64_t n)
{
    p[7] = (uint8_t) n;
    p[6] = (uint8_t) (n >> 8);
    p[5] = (uint8_t) (n >> 16);
    p[4] = (uint8_t) (n >> 24);
    p[3] = (uint8_t) (n >> 32);
    p[2] = (uint8_t) (n >> 40);
    p[1] = (uint8_t) (n >> 48);
    p[0] = (uint8_t) (n >> 56);
}

#endif // _LIBSMUSHER_ENDIAN_H