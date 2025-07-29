/**
	libsmacker - A C library for decoding .smk Smacker Video files
	Copyright (C) 2012-2017 Greg Kennedy

	See smacker.h for more information.

	smk_bitstream.h
		SMK bitstream structure. Presents a block of raw bytes one
		bit at a time, and protects against over-read.
*/

#ifndef SMK_BITSTREAM_H
#define SMK_BITSTREAM_H

#include <stdint.h>

/*
	Bitstream structure
	Pointer to raw block of data and a size limit.
	Maintains internal pointers to byte_num and bit_number.
*/
struct smk_bit_t
{
	const uint8_t* buffer;
	uint32_t size;

	uint32_t byte_num;
	int8_t bit_num;
};

/* BITSTREAM Functions */
/** Initialize a bitstream */
struct smk_bit_t* smk_bs_init(const uint8_t* b, uint64_t size);
void smk_bs_reset(struct smk_bit_t* bs, const uint8_t* b, const uint64_t size);

#ifndef SMK_FAST
/** This macro checks return code from _smk_bs_read_1 and
	jumps to error label if problems occur. */
#define smk_bs_read_1(t,uc) \
{ \
	if ((char)(uc = _smk_bs_read_1(t)) < 0) \
	{ \
		fprintf(stderr, "libsmacker::smk_bs_read_1(" #t ", " #uc ") - ERROR (file: %s, line: %lu)\n", __FILE__, (uint64_t)__LINE__); \
		goto error; \
	} \
}
/** Read a single bit from the bitstream, and advance.
	Returns -1 on error. */
char _smk_bs_read_1(struct smk_bit_t* bs);

/** This macro checks return code from _smk_bs_read_8 and
	jumps to error label if problems occur. */
#define smk_bs_read_8(t,s) \
{ \
	if ((int16_t)(s = _smk_bs_read_8(t)) < 0) \
	{ \
		fprintf(stderr, "libsmacker::smk_bs_read_8(" #t ", " #s ") - ERROR (file: %s, line: %lu)\n", __FILE__, (uint64_t)__LINE__); \
		goto error; \
	} \
}
/** Read eight bits from the bitstream (one byte), and advance.
	Returns -1 on error. */
int16_t _smk_bs_read_8(struct smk_bit_t* bs);
#else
static inline char __smk_bs_read_1(struct smk_bit_t* bs)
{
	uint8_t ret = -1;

#ifndef SMK_FAST
	/* sanity check */
	smk_assert(bs);

	/* don't die when running out of bits, but signal */
	if (bs->byte_num >= bs->size)
	{
		fprintf(stderr, "libsmacker::_smk_bs_read_1(bs): ERROR: bitstream (length=%lu) exhausted.\n", bs->size);
		goto error;
	}
#endif

	/* get next bit and return */
	ret = (((bs->buffer[bs->byte_num]) & (1 << bs->bit_num)) != 0);

	/* advance to next bit */
	bs->bit_num ++;

	/* Out of bits in this byte: next! */
	bs->byte_num += (bs->bit_num>>3);
	bs->bit_num &= 7;

	/* return ret, or (default) -1 if error */
error:
	return ret;
}

#define smk_bs_read_1(t,uc) \
{ \
	(uc = __smk_bs_read_1(t)); \
}

#define smk_bs_read_8(t,s) \
{ \
	(s = _smk_bs_read_8(t)); \
}

/** Read eight bits from the bitstream (one byte), and advance.
	Returns -1 on error. */
int16_t _smk_bs_read_8(struct smk_bit_t* bs);
#endif

#endif
