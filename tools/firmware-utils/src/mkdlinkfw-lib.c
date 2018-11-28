/*
 * mkdlinkfw
 *
 * Copyright (C) 2018 Paweł Dembicki <paweldembicki@gmail.com>
 *
 * This tool is based on mktplinkfw.
 * Copyright (C) 2009 Gabor Juhos <juhosg@openwrt.org>
 * Copyright (C) 2008,2009 Wang Jian <lark@linux.net.cn>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 */

#define _GNU_SOURCE         /* See feature_test_macros(7) */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>		/* for unlink() */
#include <libgen.h>
#include <getopt.h>		/* for getopt() */
#include <stdarg.h>
#include <stdbool.h>
#ifdef __linux__
#include <endian.h>
#endif
#include <errno.h>
#include <time.h>
#include <sys/stat.h>
#include <zlib.h>		/*for crc32 */

#include "mkdlinkfw-lib.h"

extern char *progname;


uint32_t
jboot_timestamp(void)
{
	time_t rawtime;
	time(&rawtime);
	return (((uint32_t) rawtime) - TIMESTAMP_MAGIC) >> 2;
}

uint16_t
jboot_checksum(uint16_t start_val, const void *data, size_t size)
{
	uint32_t counter = start_val;
	uint8_t *ptr = (uint8_t*)data;

	while (size > 1) {
		counter += ptr[0];
		counter += (((uint16_t)ptr[1]) << 8);
		while (counter >> 16)
			counter = (uint16_t)counter + (counter >> 16);
		ptr += 2;
		size -= 2;
	}
	if (size > 0) {
		counter += ptr[0];
		counter -= 0xFF;
	}
	while (counter >> 16) {
		counter = (uint16_t)counter + (counter >> 16);
	}

	return ((uint16_t)counter);
}

int
get_file_stat(struct file_info *fdata)
{
	struct stat st;
	int res;

	if (fdata->file_name == NULL)
		return 0;

	res = stat(fdata->file_name, &st);
	if (res) {
		ERRS("stat failed on %s", fdata->file_name);
		return res;
	}

	fdata->file_size = st.st_size;
	return 0;
}

int
read_to_buf(const struct file_info *fdata, uint8_t *buf)
{
	FILE *f;
	int ret = EXIT_FAILURE;

	f = fopen(fdata->file_name, "r");
	if (f == NULL) {
		ERRS("could not open \"%s\" for reading", fdata->file_name);
		goto out;
	}

	errno = 0;
	fread(buf, fdata->file_size, 1, f);
	if (errno != 0) {
		ERRS("unable to read from file \"%s\"", fdata->file_name);
		goto out_close;
	}

	ret = EXIT_SUCCESS;

 out_close:
	fclose(f);
 out:
	return ret;
}

int
write_fw(const char *ofname, const uint8_t *data, size_t len)
{
	FILE *f;
	int ret = EXIT_FAILURE;

	f = fopen(ofname, "w");
	if (f == NULL) {
		ERRS("could not open \"%s\" for writing", ofname);
		goto out;
	}

	errno = 0;
	fwrite(data, len, 1, f);
	if (errno) {
		ERRS("unable to write output file");
		goto out_flush;
	}

	DBG("firmware file \"%s\" completed", ofname);

	ret = EXIT_SUCCESS;

 out_flush:
	fflush(f);
	fclose(f);
	if (ret != EXIT_SUCCESS)
		unlink(ofname);
 out:
	return ret;
}

static inline void *
memmem_(const void *buf, const size_t buf_size, const void *what_find,
    const size_t what_find_size) {
	register uint8_t *ptm;
	register size_t buf_size_wrk;

	if (0 == what_find_size || what_find_size > buf_size)
		return (NULL);
	if (1 == what_find_size) /* use fast memchr() */
		return ((void*)memchr(buf, (*((uint8_t*)what_find)), buf_size));
	if (what_find_size == buf_size) { /* only memcmp() */
		if (0 == memcmp(buf, what_find, what_find_size))
			return ((void*)buf);
		return (NULL);
	}

	ptm = ((uint8_t*)buf);
	buf_size_wrk = (buf_size - (what_find_size - 1));
	for (;;) {
		ptm = (uint8_t*)memchr(ptm, (*((uint8_t*)what_find)),
		    (buf_size_wrk - (ptm - ((uint8_t*)buf))));
		if (NULL == ptm)
			return (NULL);
		if (0 == memcmp(ptm, what_find, what_find_size))
			return (ptm);
		ptm ++;
	}
	return (NULL);
}

void *
mem_find_ptr(const void *ptr, const void *buf, const size_t buf_size,
    const void *what_find, const size_t what_find_size) {
	size_t offset;

	if (NULL == buf || buf > ptr ||
	    NULL == what_find || 0 == what_find_size)
		return (NULL);
	offset = (size_t)(((const uint8_t*)ptr) - ((const uint8_t*)buf));
	if (offset >= buf_size)
		return (NULL);
	return (memmem_(ptr, (buf_size - offset), what_find, what_find_size));
}
