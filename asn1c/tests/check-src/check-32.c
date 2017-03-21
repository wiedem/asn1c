#undef	NDEBUG
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <assert.h>

#include <Programming.h>
#include <SeqWithMandatory.h>
#include <SeqWithOptional.h>
#include <Issue123.h>
#include <constr_TYPE.h>

static void
check_issue123_n(unsigned long n, const void* buf, const size_t buf_len) {
	printf("Testing BER encode/decode of %lu (0x%.8lx)\n", n, n);
	asn_enc_rval_t erv;
	asn_dec_rval_t drv;

	assert(buf_len <= 1024);
	char tmp[1024] = {0};

	Issue123_t issue123;
	memset(&issue123, 0, sizeof issue123);
	unsigned long * pn  = malloc(sizeof(unsigned long));
	*pn = n;
	ASN_SEQUENCE_ADD(&issue123.vals, pn);

	asn_fprint(stdout, &asn_DEF_Issue123, &issue123);
	/*
	 * Encode the sequence.
	 */
	erv = der_encode_to_buffer(&asn_DEF_Issue123,
			&issue123, tmp, sizeof tmp);
	assert(erv.encoded == (ssize_t)buf_len);

	Issue123_t* res = 0;
	drv = ber_decode(0, &asn_DEF_Issue123, (void **)&res,
			buf, erv.encoded);
	assert(drv.code == RC_OK);
	assert(drv.consumed == buf_len);

	asn_fprint(stdout, &asn_DEF_Issue123, res);

	assert(res->vals.list.count == 1);
	pn = *(res->vals.list.array);
	assert(pn && *pn == n);
}

static void
check_issue123(void) {
	const uint8_t buf_00[] = {0x30, 0x5, 0xa1, 0x3, 0x2, 0x1, 0x00};
	check_issue123_n(0x00, buf_00, sizeof(buf_00));
	const uint8_t buf_7F[] = {0x30, 0x5, 0xa1, 0x3, 0x2, 0x1, 0x7f};
	check_issue123_n(0x7F, buf_7F, sizeof(buf_7F));

	const uint8_t buf_80[] = {0x30, 0x6, 0xa1, 0x4, 0x2, 0x2, 0x00, 0x80};
	check_issue123_n(0x80, buf_80, sizeof(buf_80));
	const uint8_t buf_FF[] = {0x30, 0x6, 0xa1, 0x4, 0x2, 0x2, 0x00, 0xff};
	check_issue123_n(0xFF, buf_FF, sizeof(buf_FF));
	const uint8_t buf_7FFF[] = {0x30, 0x6, 0xa1, 0x4, 0x2, 0x2, 0x7f, 0xff};
	check_issue123_n(0x7FFF, buf_7FFF, sizeof(buf_7FFF));

	const uint8_t buf_8000[] = {0x30, 0x7, 0xa1, 0x5, 0x2, 0x3, 0x00, 0x80, 0x00};
	check_issue123_n(0x8000, buf_8000, sizeof(buf_8000));
	const uint8_t buf_FFFF[] = {0x30, 0x7, 0xa1, 0x5, 0x2, 0x3, 0x00, 0xff, 0xff};
	check_issue123_n(0xFFFF, buf_FFFF, sizeof(buf_FFFF));
	const uint8_t buf_7FFFFF[] = {0x30, 0x7, 0xa1, 0x5, 0x2, 0x3, 0x7f, 0xff, 0xff};
	check_issue123_n(0x7FFFFF, buf_7FFFFF, sizeof(buf_7FFFFF));

	const uint8_t buf_800000[] = {0x30, 0x8, 0xa1, 0x6, 0x2, 0x4, 0x00, 0x80, 0x00, 0x00};
	check_issue123_n(0x800000, buf_800000, sizeof(buf_800000));
	const uint8_t buf_FFFFFF[] = {0x30, 0x8, 0xa1, 0x6, 0x2, 0x4, 0x00, 0xff, 0xff, 0xff};
	check_issue123_n(0xFFFFFF, buf_FFFFFF, sizeof(buf_FFFFFF));
	const uint8_t buf_7FFFFFFF[] = {0x30, 0x8, 0xa1, 0x6, 0x2, 0x4, 0x7f, 0xff, 0xff, 0xff};
	check_issue123_n(0x7FFFFFFF, buf_7FFFFFFF, sizeof(buf_7FFFFFFF));

	const uint8_t buf_80000000[] = {0x30, 0x9, 0xa1, 0x7, 0x2, 0x5, 0x00, 0x80, 0x00, 0x00, 0x00};
	check_issue123_n(0x80000000, buf_80000000, sizeof(buf_80000000));
	const uint8_t buf_81818181[] = {0x30, 0x9, 0xa1, 0x7, 0x2, 0x5, 0x00, 0x81, 0x81, 0x81, 0x81};
	check_issue123_n(0x81818181, buf_81818181, sizeof(buf_81818181));
	const uint8_t buf_FFFFFFFF[] = {0x30, 0x9, 0xa1, 0x7, 0x2, 0x5, 0x00, 0xff, 0xff, 0xff, 0xff};
	check_issue123_n(0xFFFFFFFF, buf_FFFFFFFF, sizeof(buf_FFFFFFFF));
}

int
main(int ac, char **av) {
	Programming_t p;
	SeqWithMandatory_t swm;
	SeqWithOptional_t *swo = 0;
	Error_t *err;
	asn_enc_rval_t erv;
	asn_dec_rval_t drv;
	char buf[128];

	(void)ac;	/* Unused argument */
	(void)av;	/* Unused argument */

	/*
	 * No plans to fill Programming_t up:
	 * just checking whether it compiles or not.
	 */
	memset(&p, 0, sizeof(p));

	/*
	 * Construct a dummy sequence:
	 * SeqWithMandatory ::= {
	 * 	seqOfMan [0] EXPLICIT SEQUENCE OF Error
	 * }
	 */
	err = calloc(1, sizeof *err);
	memset(&swm, 0, sizeof swm);
	OCTET_STRING_fromBuf(&swm.someString, "Oley", 4);
	ASN_SEQUENCE_ADD(&swm.seqOfMan, err);

	/*
	 * Encode the sequence.
	 */
	erv = der_encode_to_buffer(&asn_DEF_SeqWithMandatory,
			&swm, buf, sizeof buf);
	assert(erv.encoded > 0);
	buf[erv.encoded] = '\0';

	/*
	 * Try to decode it using a compatible type.
	 */
	drv = ber_decode(0, &asn_DEF_SeqWithOptional, (void **)&swo,
			buf, erv.encoded);
	assert(drv.code == RC_OK);
	assert((ssize_t)drv.consumed == erv.encoded);
	assert(swo->seqOfOpt != 0);

	xer_fprint(stderr, &asn_DEF_SeqWithOptional, swo);
	swo->seqOfOpt = 0;

	erv = der_encode_to_buffer(&asn_DEF_SeqWithOptional,
			swo, buf, sizeof buf);
	assert(erv.encoded > 0);
	buf[erv.encoded] = '\0';

	swo = 0;
	drv = ber_decode(0, &asn_DEF_SeqWithMandatory, (void **)&swo,
			buf, erv.encoded);
	assert(drv.code != RC_OK);
	swo = 0;
	drv = ber_decode(0, &asn_DEF_SeqWithOptional, (void **)&swo,
			buf, erv.encoded);
	assert(drv.code == RC_OK);
	assert((ssize_t)drv.consumed == erv.encoded);
	assert(swo->seqOfOpt == 0);

	xer_fprint(stderr, &asn_DEF_SeqWithOptional, swo);

	check_issue123();

	printf("Finished\n");

	return 0;
}
