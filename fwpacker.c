/*
 *  Copyright (c) 2012-2013, evilwombat
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <inttypes.h>

#include "crc32.h"

typedef struct {
	/* 0x00 */ uint32_t crc32;
	/* 0x04 */ uint32_t version;
	/* 0x08 */ uint8_t build_date_day;
	/* 0x09 */ uint8_t build_date_month;
	/* 0x10 */ uint16_t build_date_year;
	/* 0x12 */ uint32_t length;
	/* 0x16 */ uint32_t loading_address;
	/* 0x20 */ uint32_t flags;
	/* 0x24 */ uint32_t magic;
	/* The image starts 0x100 bytes after the beginning of the header. */
} section_header; 

#define GLOBAL_HDR_SIZE 224

/* Magic is 0xA3 0x24 0xEB 0x90 */

static int find_magic(FILE *fp);
static int find_magic(FILE *fp)
{
	int c;
	int state = 0;
	
	while (!feof(fp)) {
		c = fgetc(fp);
		if (c < 0)
			return -1;

		switch (state) {
			case 0:
				if (c == 0x90)
					state = 1;
				else
					state = 0;

				break;
			case 1:
				if (c == 0xEB)
					state = 2;
				else
					state = 0;

				break;

			case 2:
				if (c == 0x24)
					state = 3;
				else
					state = 0;
				break;

			case 3:
				if (c == 0xA3) {
					return 0;

				} else
					state = 0;
				break;

			default:
				fprintf(stderr, "Unexpected state %u in find_magic", state);
				return -1;
		}

		if (c == 0x90)
			state = 1;
	}

	return -1;
}

/*
 * FW header appears to be big-endian ?
 */
static uint32_t read_word_le(unsigned char *buf, int offset);
static uint32_t read_word_le(unsigned char *buf, int offset)
{
	return (buf[offset+0] << 0) |
	       (buf[offset+1] << 8) |
	       (buf[offset+2] << 16) |
	       (buf[offset+3] << 24);
}

static void write_word_le(unsigned char *buf, int offset, uint32_t word);
static void write_word_le(unsigned char *buf, int offset, uint32_t word)
{
	buf[offset+0] = word >> 0;
	buf[offset+1] = word >> 8;
	buf[offset+2] = word >> 16;
	buf[offset+3] = word >> 24;
}

static unsigned int read_word(FILE *fd);
static unsigned int read_word(FILE *fd)
{
	unsigned int r = 0;
	r |= fgetc(fd) <<  0;
	r |= fgetc(fd) <<  8;
	r |= fgetc(fd) << 16;
	r |= fgetc(fd) << 24;
	return r;
}

static int read_file(FILE *fd, unsigned char *buf, int size);
static int read_file(FILE *fd, unsigned char *buf, int size)
{
        int ret;
        ret = fread(buf, size, 1, fd);
        return ret == 1 ? 0 : -1;
}

/*
 * Thanks to this guy for info on the header format:
 * https://gist.github.com/2394361
 */
int main(int argc, char **argv)
{
	int verbose = 1;
	int ret = 0;

	int num;

	FILE *ifd; /* original firmware file */
	uint32_t version;
	uint32_t build_date;
	uint32_t flags;
	uint32_t magic;
	uint32_t fcrc;
	uint32_t icrc;
	uint32_t laddr;
	int length;
	long int section_offset;
	unsigned char global_hdr[GLOBAL_HDR_SIZE];
	uint32_t global_crc;
	unsigned char *fw_content;
	struct stat ist;
	int isize;

	unsigned char test[4];

	FILE *ofd; /* repacked firmware file */
	char zero_buf[0x100];

	char *sfname;
	FILE *sfd; /* section file */
	uint32_t scrc;
	unsigned char *buf;
	struct stat sst;
	int ssize;
	section_header sh;

	if (argc != 3) {
		printf("Usage: %s [original_firmware_image] [repacked_firmware_image]\n", argv[0]);
		return -1;
	}

	/* open original firmware */

	stat(argv[1],&ist);
	isize = ist.st_size;

	ifd = fopen(argv[1], "rb");
	if (!ifd) {
		printf("Could not open firmware image %s\n", argv[1]);
		return -1;
	}
	
	read_file(ifd, global_hdr, GLOBAL_HDR_SIZE);
	// TODO: check for errors
	global_crc = read_word_le(global_hdr, 0);
	fw_content = malloc(isize);
	read_file(ifd, fw_content, isize-GLOBAL_HDR_SIZE);
	// TODO: check for errors
	icrc = crc32(fw_content, isize-GLOBAL_HDR_SIZE);
	write_word_le(test, 0, icrc);
	free(fw_content);
	rewind(ifd);

	if (verbose) {
		fprintf(stderr, "Original firmware image: %s\n", argv[1]);
		fprintf(stderr, "\tSize: %d (%d without top header)\n", isize, isize-GLOBAL_HDR_SIZE);
		fprintf(stderr, "\tStored CRC: %08x\n", global_crc);
		fprintf(stderr, "\tCalculated CRC: %08x\n", icrc);
		fprintf(stderr, "\tCalculated CRC (le): %08x\n", test);
	}
	// TODO: this global CRC shenanigan is not working

	ofd = fopen(argv[2], "w+");
	if (!ifd) {
		printf("Could not open output firmware file %s\n", argv[2]);
		return -1;
	}

	sfname = malloc(sizeof("section_")+3);
	memset(zero_buf, 0, sizeof(zero_buf));

	/* go through firmware image looking for sections */

	num = 0;

	while (1) {
		ret = find_magic(ifd);
		if (ret < 0) {
			printf("End of file reached.\n");
			break;
		}

		fseek(ifd, -28, SEEK_CUR);
		section_offset = ftell(ifd);
		
		fcrc = read_word(ifd);
		version = read_word(ifd);
		build_date = read_word(ifd);
		length = read_word(ifd);
		laddr = read_word(ifd);
		flags = read_word(ifd);
		magic = read_word(ifd);
		fseek(ifd, 0x100-28, SEEK_CUR);

		fseek(ifd, length, SEEK_CUR);

		if (length < 0)
			continue;

		/* look for and process section file */

		snprintf(sfname,sizeof("section_")+2,"section_%d",num);
		sfd = fopen(sfname,"rb");
		if (!sfd) {
			printf("Could not open section file %s\n", sfname);
			num++;
			continue; /* skip to next section */
		}

		stat(sfname,&sst);
		ssize = sst.st_size;

		buf = malloc(ssize);
		ret = read_file(sfd, buf, ssize);

		if (ret) {
			printf("Could not read section file %s (%d)\n", sfname, ret);
			num++;
			continue;
		}
		scrc = crc32(buf, ssize);

		if (verbose)
		{
			fprintf(stderr, "\n");
			fprintf(stderr, "Section %d:\n",num);
			fprintf(stderr, "\t\tFirmware\t\tSection file\n");
			fprintf(stderr, "File\t\t%s\t\t%s\n", argv[1], sfname);
			fprintf(stderr, "Offset (w/hdr)\t%ld\n", section_offset);
			fprintf(stderr, "CRC\t\t0x%08x\t\t0x%08x\n", fcrc, scrc);
			fprintf(stderr, "Version\t\t0x%08x\n", version);	
			fprintf(stderr, "Build\t\t0x%08x\n", build_date);
			fprintf(stderr, "Length\t\t0x%08x\t\t0x%08x\n", length, ssize);
			fprintf(stderr, "Load address\t0x%08x\n",laddr);
			fprintf(stderr, "Flags\t\t0x%08x\n", flags);
			fprintf(stderr, "Magic\t\t0x%08x\n", magic);
		}

		/* prepare header structure */
		sh.crc32 = scrc;
		sh.version = version;
		memcpy(&(sh.build_date_day),&build_date,1);
		memcpy(&(sh.build_date_month),&build_date+1,1);
		memcpy(&(sh.build_date_month),&build_date+2,2);
		sh.length = length;
		sh.loading_address = laddr;
		sh.flags = flags;
		sh.magic = magic;

		/* write section to output firmware image */
		fwrite(&sh,1,sizeof(section_header),ofd);
		// TODO: check for errors
		fwrite(zero_buf,1,sizeof(zero_buf)-sizeof(section_header),ofd);
		// TODO: check for errors
		fwrite(buf,1,ssize,ofd); 		
		// TODO: check for errors

		free(buf);
		fclose(sfd);
		num++;
	}

	fclose(ifd);
	fclose(ofd);
	free(sfname);

	return ret;
}
