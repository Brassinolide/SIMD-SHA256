#ifndef __SIMDSHA256_H__
#define __SIMDSHA256_H__

#include <cstdint>
#include <intrin.h>

class SIMD_SHA256
{
public:
    SIMD_SHA256() { init(); }

    void init() {
        _ABEF = _mm_set_epi32(0x6a09e667, 0xbb67ae85, 0x510e527f, 0x9b05688c);
        _CDGH = _mm_set_epi32(0x3c6ef372, 0xa54ff53a, 0x1f83d9ab, 0x5be0cd19);
        _bitlen = 0;
        _buffer_size = 0;
    }

    void update(const uint8_t* data, size_t size) {
        for (size_t i = 0; i < size; ++i) {
            _buffer[_buffer_size++] = data[i];
            if (_buffer_size == 64) {
                _sha256_transform(_buffer);
                _bitlen += 512;
                _buffer_size = 0;
            }
        }
    }

    void finallize(uint32_t hash_out[8]) {
        _bitlen += _buffer_size * 8;

        _buffer[_buffer_size++] = 0x80;
        if (_buffer_size > 56) {
            while (_buffer_size < 64) {
                _buffer[_buffer_size++] = 0;
            }

            _sha256_transform(_buffer);
			
			_buffer_size = 0;
			while (_buffer_size < 64) {
                _buffer[_buffer_size++] = 0;
            }
        }
        else {
            while (_buffer_size < 64) {
                _buffer[_buffer_size++] = 0;
            }
        }

        _buffer[63] = _bitlen;
        _buffer[62] = _bitlen >> 8;
        _buffer[61] = _bitlen >> 16;
        _buffer[60] = _bitlen >> 24;
        _buffer[59] = _bitlen >> 32;
        _buffer[58] = _bitlen >> 40;
        _buffer[57] = _bitlen >> 48;
        _buffer[56] = _bitlen >> 56;

        _sha256_transform(_buffer);

        uint32_t state[8];
        _mm_storeu_si128((__m128i*)&state[0], _ABEF);
        _mm_storeu_si128((__m128i*)&state[4], _CDGH);

        hash_out[0] = _be2le(state[3]);
        hash_out[1] = _be2le(state[2]);
        hash_out[2] = _be2le(state[7]);
        hash_out[3] = _be2le(state[6]);
        hash_out[4] = _be2le(state[1]);
        hash_out[5] = _be2le(state[0]);
        hash_out[6] = _be2le(state[5]);
        hash_out[7] = _be2le(state[4]);
    }

private:
    uint32_t _be2le(uint32_t x) {
        return ((x >> 24) & 0xFF) | ((x << 8) & 0xFF0000) | ((x >> 8) & 0xFF00) | ((x << 24) & 0xFF000000);
    }

    void _sha256_transform(const uint8_t data[64]) {
        __m128i ABEF = _ABEF;
        __m128i CDGH = _CDGH;

        //加载数据，并进行重排运算将小端序转为大端序
        const __m128i MASK = _mm_set_epi64x(0x0c0d0e0f08090a0bULL, 0x0405060700010203ULL);
        // W[3:0]
        __m128i MSG0 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)(data + 0)), MASK);
        // W[7:4]
        __m128i MSG1 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)(data + 16)), MASK);
        // W[11:8]
        __m128i MSG2 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)(data + 32)), MASK);
        // W[15:12]
        __m128i MSG3 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)(data + 48)), MASK);

        //预计算：消息 + 轮常量
        __m128i MSG = _mm_add_epi32(MSG0, _mm_set_epi64x(0xE9B5DBA5B5C0FBCFULL, 0x71374491428A2F98ULL));

        //执行前两轮压缩，更新CDGH
        CDGH = _mm_sha256rnds2_epu32(CDGH, ABEF, MSG);

        //高64位重排到低64位，执行后两轮压缩，更新ABEF
        ABEF = _mm_sha256rnds2_epu32(ABEF, CDGH, _mm_shuffle_epi32(MSG, _MM_SHUFFLE(0, 0, 3, 2)));

        MSG = _mm_add_epi32(MSG1, _mm_set_epi64x(0xAB1C5ED5923F82A4ULL, 0x59F111F13956C25BULL));
        CDGH = _mm_sha256rnds2_epu32(CDGH, ABEF, MSG);
        ABEF = _mm_sha256rnds2_epu32(ABEF, CDGH, _mm_shuffle_epi32(MSG, _MM_SHUFFLE(0, 0, 3, 2)));
        MSG = _mm_add_epi32(MSG2, _mm_set_epi64x(0x550C7DC3243185BEULL, 0x12835B01D807AA98ULL));
        CDGH = _mm_sha256rnds2_epu32(CDGH, ABEF, MSG);
        ABEF = _mm_sha256rnds2_epu32(ABEF, CDGH, _mm_shuffle_epi32(MSG, _MM_SHUFFLE(0, 0, 3, 2)));
        MSG = _mm_add_epi32(MSG3, _mm_set_epi64x(0xC19BF1749BDC06A7ULL, 0x80DEB1FE72BE5D74ULL));
        CDGH = _mm_sha256rnds2_epu32(CDGH, ABEF, MSG);
        ABEF = _mm_sha256rnds2_epu32(ABEF, CDGH, _mm_shuffle_epi32(MSG, _MM_SHUFFLE(0, 0, 3, 2)));

        // W[19:16]
        MSG0 = _mm_sha256msg2_epu32(_mm_add_epi32(_mm_sha256msg1_epu32(MSG0, MSG1), _mm_alignr_epi8(MSG3, MSG2, 4)), MSG3);
        // W[23-20]
        MSG1 = _mm_sha256msg2_epu32(_mm_add_epi32(_mm_sha256msg1_epu32(MSG1, MSG2), _mm_alignr_epi8(MSG0, MSG3, 4)), MSG0);
        // W[27:24]
        MSG2 = _mm_sha256msg2_epu32(_mm_add_epi32(_mm_sha256msg1_epu32(MSG2, MSG3), _mm_alignr_epi8(MSG1, MSG0, 4)), MSG1);
        // W[31:28]
        MSG3 = _mm_sha256msg2_epu32(_mm_add_epi32(_mm_sha256msg1_epu32(MSG3, MSG0), _mm_alignr_epi8(MSG2, MSG1, 4)), MSG2);

        MSG = _mm_add_epi32(MSG0, _mm_set_epi64x(0x240CA1CC0FC19DC6ULL, 0xEFBE4786E49B69C1ULL));
        CDGH = _mm_sha256rnds2_epu32(CDGH, ABEF, MSG);
        ABEF = _mm_sha256rnds2_epu32(ABEF, CDGH, _mm_shuffle_epi32(MSG, _MM_SHUFFLE(0, 0, 3, 2)));
        MSG = _mm_add_epi32(MSG1, _mm_set_epi64x(0x76F988DA5CB0A9DCULL, 0x4A7484AA2DE92C6FULL));
        CDGH = _mm_sha256rnds2_epu32(CDGH, ABEF, MSG);
        ABEF = _mm_sha256rnds2_epu32(ABEF, CDGH, _mm_shuffle_epi32(MSG, _MM_SHUFFLE(0, 0, 3, 2)));
        MSG = _mm_add_epi32(MSG2, _mm_set_epi64x(0xBF597FC7B00327C8ULL, 0xA831C66D983E5152ULL));
        CDGH = _mm_sha256rnds2_epu32(CDGH, ABEF, MSG);
        ABEF = _mm_sha256rnds2_epu32(ABEF, CDGH, _mm_shuffle_epi32(MSG, _MM_SHUFFLE(0, 0, 3, 2)));
        MSG = _mm_add_epi32(MSG3, _mm_set_epi64x(0x1429296706CA6351ULL, 0xD5A79147C6E00BF3ULL));
        CDGH = _mm_sha256rnds2_epu32(CDGH, ABEF, MSG);
        ABEF = _mm_sha256rnds2_epu32(ABEF, CDGH, _mm_shuffle_epi32(MSG, _MM_SHUFFLE(0, 0, 3, 2)));

        // W[35:32]
        MSG0 = _mm_sha256msg2_epu32(_mm_add_epi32(_mm_sha256msg1_epu32(MSG0, MSG1), _mm_alignr_epi8(MSG3, MSG2, 4)), MSG3);
        // W[39:36]
        MSG1 = _mm_sha256msg2_epu32(_mm_add_epi32(_mm_sha256msg1_epu32(MSG1, MSG2), _mm_alignr_epi8(MSG0, MSG3, 4)), MSG0);
        // W[43:40]
        MSG2 = _mm_sha256msg2_epu32(_mm_add_epi32(_mm_sha256msg1_epu32(MSG2, MSG3), _mm_alignr_epi8(MSG1, MSG0, 4)), MSG1);
        // W[47:44]
        MSG3 = _mm_sha256msg2_epu32(_mm_add_epi32(_mm_sha256msg1_epu32(MSG3, MSG0), _mm_alignr_epi8(MSG2, MSG1, 4)), MSG2);

        MSG = _mm_add_epi32(MSG0, _mm_set_epi64x(0x53380D134D2C6DFCULL, 0x2E1B213827B70A85ULL));
        CDGH = _mm_sha256rnds2_epu32(CDGH, ABEF, MSG);
        ABEF = _mm_sha256rnds2_epu32(ABEF, CDGH, _mm_shuffle_epi32(MSG, _MM_SHUFFLE(0, 0, 3, 2)));
        MSG = _mm_add_epi32(MSG1, _mm_set_epi64x(0x92722C8581C2C92EULL, 0x766A0ABB650A7354ULL));
        CDGH = _mm_sha256rnds2_epu32(CDGH, ABEF, MSG);
        ABEF = _mm_sha256rnds2_epu32(ABEF, CDGH, _mm_shuffle_epi32(MSG, _MM_SHUFFLE(0, 0, 3, 2)));
        MSG = _mm_add_epi32(MSG2, _mm_set_epi64x(0xC76C51A3C24B8B70ULL, 0xA81A664BA2BFE8A1ULL));
        CDGH = _mm_sha256rnds2_epu32(CDGH, ABEF, MSG);
        ABEF = _mm_sha256rnds2_epu32(ABEF, CDGH, _mm_shuffle_epi32(MSG, _MM_SHUFFLE(0, 0, 3, 2)));
        MSG = _mm_add_epi32(MSG3, _mm_set_epi64x(0x106AA070F40E3585ULL, 0xD6990624D192E819ULL));
        CDGH = _mm_sha256rnds2_epu32(CDGH, ABEF, MSG);
        ABEF = _mm_sha256rnds2_epu32(ABEF, CDGH, _mm_shuffle_epi32(MSG, _MM_SHUFFLE(0, 0, 3, 2)));

        // W[51:48]
        MSG0 = _mm_sha256msg2_epu32(_mm_add_epi32(_mm_sha256msg1_epu32(MSG0, MSG1), _mm_alignr_epi8(MSG3, MSG2, 4)), MSG3);
        // W[55:52]
        MSG1 = _mm_sha256msg2_epu32(_mm_add_epi32(_mm_sha256msg1_epu32(MSG1, MSG2), _mm_alignr_epi8(MSG0, MSG3, 4)), MSG0);
        // W[59:56]
        MSG2 = _mm_sha256msg2_epu32(_mm_add_epi32(_mm_sha256msg1_epu32(MSG2, MSG3), _mm_alignr_epi8(MSG1, MSG0, 4)), MSG1);
        // W[63:60]
        MSG3 = _mm_sha256msg2_epu32(_mm_add_epi32(_mm_sha256msg1_epu32(MSG3, MSG0), _mm_alignr_epi8(MSG2, MSG1, 4)), MSG2);

        MSG = _mm_add_epi32(MSG0, _mm_set_epi64x(0x34B0BCB52748774CULL, 0x1E376C0819A4C116ULL));
        CDGH = _mm_sha256rnds2_epu32(CDGH, ABEF, MSG);
        ABEF = _mm_sha256rnds2_epu32(ABEF, CDGH, _mm_shuffle_epi32(MSG, _MM_SHUFFLE(0, 0, 3, 2)));
        MSG = _mm_add_epi32(MSG1, _mm_set_epi64x(0x682E6FF35B9CCA4FULL, 0x4ED8AA4A391C0CB3ULL));
        CDGH = _mm_sha256rnds2_epu32(CDGH, ABEF, MSG);
        ABEF = _mm_sha256rnds2_epu32(ABEF, CDGH, _mm_shuffle_epi32(MSG, _MM_SHUFFLE(0, 0, 3, 2)));
        MSG = _mm_add_epi32(MSG2, _mm_set_epi64x(0x8CC7020884C87814ULL, 0x78A5636F748F82EEULL));
        CDGH = _mm_sha256rnds2_epu32(CDGH, ABEF, MSG);
        ABEF = _mm_sha256rnds2_epu32(ABEF, CDGH, _mm_shuffle_epi32(MSG, _MM_SHUFFLE(0, 0, 3, 2)));
        MSG = _mm_add_epi32(MSG3, _mm_set_epi64x(0xC67178F2BEF9A3F7ULL, 0xA4506CEB90BEFFFAULL));
        CDGH = _mm_sha256rnds2_epu32(CDGH, ABEF, MSG);
        ABEF = _mm_sha256rnds2_epu32(ABEF, CDGH, _mm_shuffle_epi32(MSG, _MM_SHUFFLE(0, 0, 3, 2)));

        _ABEF = _mm_add_epi32(_ABEF, ABEF);
        _CDGH = _mm_add_epi32(_CDGH, CDGH);
    }

    __m128i _ABEF, _CDGH;
    uint64_t _bitlen, _buffer_size;
    uint8_t _buffer[64];
};

#endif
