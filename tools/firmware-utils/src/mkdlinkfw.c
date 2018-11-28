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
#include <unistd.h>		/* for unlink() */
#include <libgen.h>
#include <getopt.h>		/* for getopt() */
#include <stdarg.h>
#include <stdbool.h>
#ifdef __linux__
#include <endian.h>
#endif
#include <errno.h>
#include <sys/stat.h>
#include <zlib.h>		/*for crc32 */

#include "mkdlinkfw-lib.h"

/* ARM update hdr 2.0
 * used only in factory images to erase and flash selected area
 */
struct auh_header {
	uint8_t rom_id[12];	/* 12-bit rom-id unique per router type */
	uint16_t derange;	/* used for scramble hdr */
	uint16_t image_checksum;	/* jboot_checksum of flashed data */

	uint32_t space1;	/* zeros */
	uint32_t space2;	/* zeros */
	uint16_t space3;	/* zerosu */
	uint8_t lpvs;		/* must be 0x01 */
	uint8_t mbz;		/* bust be 0 */
	uint32_t time_stamp;	/* timestamp calculated in jboot way */

	uint32_t erase_start;	/* erase start address */
	uint32_t erase_length;	/* erase length address */
	uint32_t data_offset;	/* data start address */
	uint32_t data_length;	/* data length address */

	uint32_t space4;	/* zeros */
	uint32_t space5;	/* zeros */
	uint32_t space6;	/* zeros */
	uint32_t space7;	/* zeros */

	uint16_t header_id;	/* magic 0x4842 */
	uint16_t header_version;	/* 0x02 for 2.0 */
	uint16_t space8;	/* zeros */
	uint8_t section_id;	/* section id */
	uint8_t image_info_type;	/* (?) 0x04 in factory images */
	uint32_t image_info_offset;	/* (?) zeros in factory images */
	uint16_t family_member;	/* unique per router type */
	uint16_t header_checksum;	/* negated jboot_checksum of hdr data */
} __attribute__((__packed__));

struct stag_header {		/* used only of sch2 wrapped kernel data */
	uint8_t cmark;		/* in factory 0xFF ,in sysuograde must be the same as id */
	uint8_t id;		/* 0x04 */
	uint16_t magic;		/* magic 0x2B24 */
	uint32_t time_stamp;	/* timestamp calculated in jboot way */
	uint32_t image_length;	/* lentgh of kernel + sch2 hdr */
	uint16_t image_checksum;	/* negated jboot_checksum of sch2 + kernel */
	uint16_t tag_checksum;	/* negated jboot_checksum of stag hdr data */
} __attribute__((__packed__));

struct sch2_header {		/* used only in kernel partitions */
	uint16_t magic;		/* magic 0x2124 */
	uint8_t cp_type;	/* 0x00 for flat, 0x01 for jz, 0x02 for gzip, 0x03 for lzma */
	uint8_t version;	/* 0x02 for sch2 */
	uint32_t ram_addr;	/* ram entry address */
	uint32_t image_len;	/* kernel image length */
	uint32_t image_crc32;	/* kernel image crc */
	uint32_t start_addr;	/* ram start address */
	uint32_t rootfs_addr;	/* rootfs flash address */
	uint32_t rootfs_len;	/* rootfls length */
	uint32_t rootfs_crc32;	/* rootfs crc32 */
	uint32_t header_crc32;	/* sch2 hdr crc32, durring calculation this area is replaced by zero */
	uint16_t header_length;	/* sch2 hdr length: 0x28 */
	uint16_t cmd_line_length;	/* cmd line length, known zeros */
} __attribute__((__packed__));

/* globals */
static struct file_info inspect_info;
static struct file_info kernel_info;
static struct file_info rootfs_info;
static struct file_info image_info;

static char *ofname;
char *progname;


static void
usage(int status)
{
	fprintf(stderr, "Usage: %s [OPTIONS...]\n", progname);
	fprintf(stderr,
		"\n"
		"Options:\n"
		"  -i <file>       inspect given firmware file <file>\n"
		"  -f              set family member id (hexval prefixed with 0x)\n"
		"  -F <file>       read image and convert it to FACTORY\n"
		"  -k <file>       read kernel image from the file <file>\n"
		"  -r <file>       read rootfs image from the file <file>\n"
		"  -o <file>       write output to the file <file>\n"
		"  -O <size>       write flash offset, used in case mem hole in original MTD\n"
		"  -s <size>       set firmware partition size\n"
		"  -m <version>    set rom id to <version> (12-bit string val: \"DLK*********\")\n"
		"  -h              show this screen\n");

	exit(status);
}

static void
auh_header_print(const void *buf)
{
	struct auh_header hdr;

	memcpy(&hdr, buf, sizeof(struct auh_header));
	printf("\trom_id: %s\n"
	       "\tderange: 0x%04X\n"
	       "\timage_checksum: 0x%04X\n"
	       "\tspace1: 0x%08X\n"
	       "\tspace2: 0x%08X\n"
	       "\tspace3: 0x%04X\n"
	       "\tlpvs: 0x%02X\n"
	       "\tmbz: 0x%02X\n"
	       "\ttime_stamp: 0x%08X\n"
	       "\terase_start: 0x%08X\n"
	       "\terase_length: 0x%08X\n"
	       "\tdata_offset: 0x%08X\n"
	       "\tdata_length: 0x%08X\n"
	       "\tspace4: 0x%08X\n"
	       "\tspace5: 0x%08X\n"
	       "\tspace6: 0x%08X\n"
	       "\tspace7: 0x%08X\n"
	       "\theader_id: 0x%04X\n"
	       "\theader_version: 0x%02X\n"
	       "\tspace8: 0x%04X\n"
	       "\tsection_id: 0x%02X\n"
	       "\timage_info_type: 0x%02X\n"
	       "\timage_info_offset 0x%08X\n"
	       "\tfamily_member: 0x%04X\n"
	       "\theader_checksum: 0x%04X\n",
	       hdr.rom_id,
	       hdr.derange,
	       hdr.image_checksum,
	       hdr.space1,
	       hdr.space2,
	       hdr.space3,
	       hdr.lpvs,
	       hdr.mbz,
	       hdr.time_stamp,
	       hdr.erase_start,
	       hdr.erase_length,
	       hdr.data_offset,
	       hdr.data_length,
	       hdr.space4,
	       hdr.space5,
	       hdr.space6,
	       hdr.space7,
	       hdr.header_id,
	       hdr.header_version,
	       hdr.space8,
	       hdr.section_id,
	       hdr.image_info_type,
	       hdr.image_info_offset,
	       hdr.family_member, hdr.header_checksum);
}

static int
auh_header_fill(uint8_t *auh, const uint8_t *rom_id,
    uint32_t erase_start, uint32_t erase_length,
    uint32_t data_offset, uint32_t data_length,
    uint16_t family_member)
{
	struct auh_header hdr;

	memset(&hdr, 0x00, sizeof(struct auh_header));
	memcpy(hdr.rom_id, rom_id, 12);
	hdr.derange = 0;
	hdr.image_checksum = jboot_checksum(0, (auh + AUH_SIZE), data_length);
	hdr.space1 = 0;
	hdr.space2 = 0;
	hdr.space3 = 0;
	hdr.lpvs = AUH_LVPS;
	hdr.mbz = 0;
	hdr.time_stamp = jboot_timestamp();
	hdr.erase_start = erase_start;
	hdr.erase_length = erase_length;
	hdr.data_offset = data_offset;
	hdr.data_length = data_length;
	hdr.space4 = 0;
	hdr.space5 = 0;
	hdr.space6 = 0;
	hdr.space7 = 0;
	hdr.header_id = AUH_HDR_ID;
	hdr.header_version = AUH_HDR_VER;
	hdr.space8 = 0;
	hdr.section_id = AUH_SEC_ID;
	hdr.image_info_type = AUH_INFO_TYPE;
	hdr.image_info_offset = 0;
	hdr.family_member = family_member;
	hdr.header_checksum = ~jboot_checksum(0, &hdr, (AUH_SIZE - 2));
	memcpy(auh, &hdr, AUH_SIZE);

	return (EXIT_SUCCESS);
}

static int
auh_header_check(const uint8_t *buf, size_t buf_size)
{
	struct auh_header hdr;
	uint16_t checksum;

	if (AUH_SIZE > buf_size) {
		ERR("AUH buf to small.");
		return (EXIT_FAILURE);
	}
	memcpy(&hdr, buf, AUH_SIZE);
	if (0 != memcmp(hdr.rom_id, AUH_MAGIC, 3))
		return (EXIT_FAILURE);

	checksum = ~jboot_checksum(0, &hdr, (AUH_SIZE - 2));
	if (hdr.header_checksum != checksum) {
		ERR("AUH hdr checksum incorrect!");
		return (EXIT_FAILURE);
	}
	/* Check data size. */
	if ((AUH_SIZE + hdr.data_length) > buf_size) {
		ERR("AUH data_length too big.");
		return (EXIT_FAILURE);
	}
	checksum = jboot_checksum(0, (buf + AUH_SIZE),
	    hdr.data_length);
	if (hdr.image_checksum != checksum) {
		ERR("Image checksum incorrect! Stored: 0x%X Calculated: 0x%X",
		    hdr.image_checksum, checksum);
		return (EXIT_FAILURE);
	}

	return (EXIT_SUCCESS);
}

static void
stag_header_print(const void *buf)
{
	struct stag_header hdr;

	memcpy(&hdr, buf, sizeof(struct stag_header));
	printf("\tcmark: 0x%02X\n"
	       "\tid: 0x%02X\n"
	       "\tmagic: 0x%04X\n"
	       "\ttime_stamp: 0x%08X\n"
	       "\timage_length: 0x%04X\n"
	       "\timage_checksum: 0x%04X\n"
	       "\ttag_checksum: 0x%04X\n",
	       hdr.cmark,
	       hdr.id,
	       hdr.magic,
	       hdr.time_stamp,
	       hdr.image_length,
	       hdr.image_checksum, hdr.tag_checksum);
}

static int
stag_header_fill(uint8_t *stag, int image_type, uint32_t length)
{
	struct stag_header hdr;

	memset(&hdr, 0x00, sizeof(struct stag_header));
	hdr.cmark = STAG_ID;
	hdr.id = STAG_ID;
	hdr.magic = STAG_MAGIC;
	hdr.time_stamp = jboot_timestamp();
	hdr.image_length = length;
	hdr.image_checksum = jboot_checksum(0, (stag + STAG_SIZE), length);
	hdr.tag_checksum = ~jboot_checksum(0, &hdr, (STAG_SIZE - 2));
	if (image_type == FACTORY) {
		hdr.cmark = STAG_CMARK_FACTORY;
	}
	memcpy(stag, &hdr, STAG_SIZE);

	return (EXIT_SUCCESS);
}

static int
stag_header_check(const uint8_t *buf, size_t buf_size)
{
	struct stag_header hdr;
	uint16_t checksum;

	if (STAG_SIZE > buf_size) {
		ERR("STAG buf to small.");
		return (EXIT_FAILURE);
	}
	memcpy(&hdr, buf, STAG_SIZE);
	if (STAG_MAGIC != hdr.magic)
		return (EXIT_FAILURE);

	hdr.cmark = hdr.id;
	checksum = ~jboot_checksum(0, &hdr, (STAG_SIZE - 2));
	if (hdr.tag_checksum != checksum) {
		ERR("STAG hdr checksum incorrect!");
		return (EXIT_FAILURE);
	}

	if ((STAG_SIZE + hdr.image_length) > buf_size) {
		ERR("STAG image_length too big.");
		return (EXIT_FAILURE);
	}
	checksum = jboot_checksum(0, (buf + STAG_SIZE),
	    hdr.image_length);
	if (hdr.image_checksum != checksum) {
		ERR("Image checksum incorrect! Stored: 0x%X Calculated: 0x%X",
		    hdr.image_checksum, checksum);
		return (EXIT_FAILURE);
	}

	return (EXIT_SUCCESS);
}


static void
sch2_header_print(const void *buf)
{
	struct sch2_header hdr;

	memcpy(&hdr, buf, sizeof(struct sch2_header));
	printf("\tmagic: 0x%04X\n"
	       "\tcp_type: 0x%02X\n"
	       "\tversion: 0x%02X\n"
	       "\tram_addr: 0x%08X\n"
	       "\timage_len: 0x%08X\n"
	       "\timage_crc32: 0x%08X\n"
	       "\tstart_addr: 0x%08X\n"
	       "\trootfs_addr: 0x%08X\n"
	       "\trootfs_len: 0x%08X\n"
	       "\trootfs_crc32: 0x%08X\n"
	       "\theader_crc32: 0x%08X\n"
	       "\theader_length: 0x%04X\n"
	       "\tcmd_line_length: 0x%04X\n",
	       hdr.magic,
	       hdr.cp_type,
	       hdr.version,
	       hdr.ram_addr,
	       hdr.image_len,
	       hdr.image_crc32,
	       hdr.start_addr,
	       hdr.rootfs_addr,
	       hdr.rootfs_len,
	       hdr.rootfs_crc32,
	       hdr.header_crc32,
	       hdr.header_length, hdr.cmd_line_length);
}

static int
sch2_header_fill(uint8_t *sch2, const uint8_t *kernel, uint32_t kernel_size,
    const uint8_t *rootfs, uint32_t rootfs_size, uint32_t image_offset)
{
	struct sch2_header hdr;

	memset(&hdr, 0x00, sizeof(struct sch2_header));
	hdr.magic = SCH2_MAGIC;
	hdr.cp_type = LZMA;
	hdr.version = SCH2_VER;
	hdr.ram_addr = RAM_LOAD_ADDR;
	hdr.image_len = kernel_size;
	hdr.image_crc32 = (uint32_t)crc32(0, kernel, kernel_size);
	hdr.start_addr = RAM_ENTRY_ADDR;
	hdr.rootfs_addr =
	    (image_offset + STAG_SIZE + SCH2_SIZE + hdr.image_len);
	hdr.rootfs_len = rootfs_size;
	hdr.rootfs_crc32 = (uint32_t)crc32(0, rootfs, rootfs_size);
	hdr.header_crc32 = 0;
	hdr.header_length = SCH2_SIZE;
	hdr.cmd_line_length = 0;

	hdr.header_crc32 = (uint32_t)crc32(0, (uint8_t*)&hdr, hdr.header_length);
	memcpy(sch2, &hdr, SCH2_SIZE);

	return (EXIT_SUCCESS);
}

static int
sch2_header_check(const uint8_t *buf, size_t buf_size)
{
	struct sch2_header hdr;
	uint32_t crc32_val;

	if (SCH2_SIZE > buf_size) {
		ERR("SCH2 buf to small.");
		return (EXIT_FAILURE);
	}
	memcpy(&hdr, buf, SCH2_SIZE);
	if (SCH2_MAGIC != hdr.magic)
		return (EXIT_FAILURE);

	crc32_val = hdr.header_crc32;
	hdr.header_crc32 = 0;
	if ((uint32_t)crc32(0, (uint8_t*)&hdr, hdr.header_length) != crc32_val) {
		ERR("SCH2 hdr crc32 incorrect!");
		return (EXIT_FAILURE);
	}

	if ((hdr.header_length + hdr.image_len) > buf_size) {
		ERR("STAG header_length + image_len too big.");
		return (EXIT_FAILURE);
	}
	crc32_val = (uint32_t)crc32(0, (buf + hdr.header_length),
	    hdr.image_len);
	if (hdr.image_crc32 != crc32_val) {
		ERR("Kernel crc32 incorrect! Stored: 0x%X Calculated: 0x%X",
		    hdr.image_crc32, crc32_val);
		return (EXIT_FAILURE);
	}

	return (EXIT_SUCCESS);
}



static int
dump_auh_headers(const uint8_t *buf, size_t buf_size)
{
	uint8_t *cur_pos, *cur_hdr, *sub_hdr;
	const uint8_t *buf_end = (buf + buf_size);
	size_t hdr_cnt = 0, offset;
	uint32_t auh_data_length;

	for (cur_pos = buf; hdr_cnt < MAX_HEADER_COUNTER; cur_pos ++) {
		cur_pos = mem_find_ptr(cur_pos, buf, buf_size, AUH_MAGIC, 3);
		if (NULL == cur_pos)
			break;
		/* Header probably found, check is checksum correct? */
		if ((buf_end - cur_pos) < AUH_SIZE)
			break;
		cur_hdr = cur_pos;
		/* Check and print AUH header. */
		offset = (size_t)(cur_hdr - buf);
		if (EXIT_SUCCESS != auh_header_check(cur_hdr, (buf_size - offset)))
			continue;
		printf("Find proper AUH hdr at: 0x%lX!\n", (cur_hdr - buf));
		printf("Image checksum ok.\n");
		auh_header_print(cur_hdr);
		hdr_cnt ++;
		/* AUH header ok, move to next header. */
		memcpy(&auh_data_length,
		    &((struct auh_header*)cur_hdr)->data_length,
		    sizeof(uint32_t));
		cur_pos += ((AUH_SIZE - 1) + auh_data_length);

		/* Check and print STAG header. */
		sub_hdr = (cur_hdr + AUH_SIZE);
		if (sub_hdr > buf_end)
			continue;
		offset = (size_t)(sub_hdr - buf);
		if (EXIT_SUCCESS != stag_header_check(sub_hdr, (buf_size - offset)))
			continue;
		printf("Find proper STAG hdr at: 0x%zX!\n", offset);
		printf("Image checksum ok.\n");
		stag_header_print(sub_hdr);

		/* Check and print SCH2 header. */
		sub_hdr = (cur_hdr + AUH_SIZE + STAG_SIZE);
		if (sub_hdr > buf_end)
			continue;
		offset = (size_t)(sub_hdr - buf);
		if (EXIT_SUCCESS != sch2_header_check(sub_hdr, (buf_size - offset)))
			continue;
		printf("Find proper SCH2 hdr at: 0x%zX!\n", offset);
		printf("Kernel checksum ok.\n");
		sch2_header_print(sub_hdr);
	}

	if (hdr_cnt == 0) {
		ERR("Can't find proper AUH hdr!");
	} else if (hdr_cnt > MAX_HEADER_COUNTER) {
		ERR("To many AUH headers!");
	} else {
		return (EXIT_SUCCESS);
	}

	return (EXIT_FAILURE);
}

static int
inspect_fw(void)
{
	int ret;
	uint8_t *buf;

	buf = malloc(inspect_info.file_size);
	if (!buf) {
		ERR("no memory for buffer!");
		return (EXIT_FAILURE);
	}

	ret = read_to_buf(&inspect_info, buf);
	if (EXIT_SUCCESS == ret) {
		ret = dump_auh_headers(buf, inspect_info.file_size);
	}

	free(buf);

	return (ret);
}

static int
check_options(void)
{
	int ret;

	if (inspect_info.file_name) {
		ret = get_file_stat(&inspect_info);
		if (ret)
			return ret;

		return 0;
	}

	return 0;
}

static int
build_fw(int image_type, uint32_t image_offset, uint32_t firmware_size)
{
	uint8_t *buf, *kernel_ptr, *rootfs_ptr, *stag, *sch2;
	size_t writelen;
	int ret;

	if (!kernel_info.file_name || !rootfs_info.file_name)
		return (EXIT_FAILURE);

	ret = get_file_stat(&kernel_info);
	if (ret)
		return (EXIT_FAILURE);
	ret = get_file_stat(&rootfs_info);
	if (ret)
		return (EXIT_FAILURE);

	if ((rootfs_info.file_size + kernel_info.file_size + ALL_HEADERS_SIZE) >
	    firmware_size) {
		ERR("data is bigger than firmware_size!");
		return (EXIT_FAILURE);
	}

	buf = malloc(firmware_size);
	if (!buf) {
		ERR("no memory for buffer");
		return (EXIT_FAILURE);
	}
	memset(buf, 0xff, firmware_size);

	stag = buf;
	sch2 = (buf + STAG_SIZE);
	kernel_ptr = (buf + STAG_SIZE + SCH2_SIZE);
	rootfs_ptr = (kernel_ptr + kernel_info.file_size);
	writelen = (STAG_SIZE + SCH2_SIZE + kernel_info.file_size +
	    rootfs_info.file_size);

	ret = read_to_buf(&kernel_info, kernel_ptr);
	if (ret) {
		ret = EXIT_FAILURE;
		goto out_free_buf;
	}

	ret = read_to_buf(&rootfs_info, rootfs_ptr);
	if (ret) {
		ret = EXIT_FAILURE;
		goto out_free_buf;
	}

	sch2_header_fill(sch2, kernel_ptr, kernel_info.file_size,
	    rootfs_ptr, rootfs_info.file_size, image_offset);
	stag_header_fill(stag, image_type, (kernel_info.file_size + SCH2_SIZE));

	ret = write_fw(ofname, buf, writelen);

out_free_buf:
	free(buf);

	return (ret);
}

static int
wrap_fw(const uint8_t *rom_id, uint16_t family_member,
    uint32_t image_offset, uint32_t firmware_size)
{
	uint8_t *buf;
	uint8_t *image_ptr;
	size_t writelen;
	int ret;

	if (!image_info.file_name)
		return (EXIT_FAILURE);

	ret = get_file_stat(&image_info);
	if (ret)
		return (EXIT_FAILURE);

	if ((image_info.file_size + AUH_SIZE) > firmware_size) {
		ERR("data is bigger than firmware_size!");
		return (EXIT_FAILURE);
	}
	if (!family_member) {
		ERR("No family_member!");
		return (EXIT_FAILURE);
	}
	if (!(rom_id[0])) {
		ERR("No rom_id!\n");
		return (EXIT_FAILURE);
	}

	buf = malloc(firmware_size);
	if (!buf) {
		ERR("no memory for buffer");
		return (EXIT_FAILURE);
	}
	memset(buf, 0xff, firmware_size);

	image_ptr = (buf + AUH_SIZE);
	ret = read_to_buf(&image_info, image_ptr);
	if (ret) {
		ret = EXIT_FAILURE;
		goto out_free_buf;
	}

	writelen = (AUH_SIZE + image_info.file_size);
	auh_header_fill(buf, rom_id,
	    image_offset, firmware_size,
	    image_offset, (uint32_t)(writelen - AUH_SIZE),
	    family_member);

	ret = write_fw(ofname, buf, writelen);

out_free_buf:
	free(buf);

	return (ret);
}


int
main(int argc, char *argv[])
{
	int ret = EXIT_FAILURE;
	int image_type = SYSUPGRADE;
	uint16_t family_member = 0;
	uint32_t image_offset = JBOOT_SIZE, firmware_size = 0;
	uint8_t *rom_id[12] = { 0 };

	progname = basename(argv[0]);

	while (1) {
		int c;

		c = getopt(argc, argv, "f:F:i:hk:m:o:O:r:s:");
		if (c == -1)
			break;

		switch (c) {
		case 'f':
			sscanf(optarg, "0x%hx", &family_member);
			break;
		case 'F':
			image_info.file_name = optarg;
			image_type = FACTORY;
			break;
		case 'i':
			inspect_info.file_name = optarg;
			break;
		case 'k':
			kernel_info.file_name = optarg;
			break;
		case 'm':
			if (strlen(optarg) == 12)
				memcpy(rom_id, optarg, 12);
			break;
		case 'r':
			rootfs_info.file_name = optarg;
			break;
		case 'O':
			sscanf(optarg, "0x%x", &image_offset);
			if ((JBOOT_SIZE + SCH2_SIZE) > image_offset) {
				ERR("Minimum image offset is: %zu, you set: %zu",
				    (size_t)(JBOOT_SIZE + SCH2_SIZE),
				    (size_t)image_offset);
				return (EXIT_FAILURE);
			}
			break;
		case 'o':
			ofname = optarg;
			break;
		case 's':
			sscanf(optarg, "0x%x", &firmware_size);
			break;
		default:
			usage(EXIT_FAILURE);
			break;
		}
	}

	ret = check_options();
	if (ret)
		goto out;

	if (!inspect_info.file_name) {
		if (image_type == FACTORY)
			ret = wrap_fw((uint8_t*)rom_id, family_member,
			    image_offset, firmware_size);
		else
			ret = build_fw(image_type, image_offset,
			    firmware_size);
		}
	else
		ret = inspect_fw();

 out:
	return ret;

}
