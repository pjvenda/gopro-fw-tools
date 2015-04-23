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

#define SECTION_COUNT 9

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

static int save_section(const char *output_name, int length,FILE *fd);
static int save_section(const char *output_name, int length,FILE *fd)
{
	FILE *ofd;
	int i;
	char t;
	ofd = fopen(output_name, "wb+");

	if (!ofd) {
		printf("Could not write to %s\n", output_name);
		return -1;
	}

	for (i = 0; i < length; i++) {
		fread(&t, 1, 1, fd);
		fwrite(&t, 1, 1, ofd);
	}
	fclose(ofd);
	return 0;
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
	unsigned int version, build_date, flags, magic;
	unsigned int section_offset;
	int length;

	int i;
	char *prefix;
	char *section_fname[SECTION_COUNT];
	FILE *section_fp;
	char *str;
	int size;
	struct stat st;
	unsigned char *buf;
	uint32_t crc;
	FILE *orig;

	if (argc != 4) {
		printf("Usage: %s [original] [prefix] [output]\n", argv[0]);
		return -1;
	}




	orig = fopen(argv[1], "rb");
	if (!orig) {
		printf("Could not open %s\n", argv[1]);
		return -1;
	}

	ret = find_magic(orig);
	if (ret < 0) {
		printf("End of file reached.\n");
		fclose(orig);
		return 0;
	}

	fseek(orig, -28, SEEK_CUR);
	crc = read_word(orig);
	version = read_word(orig);
	build_date = read_word(orig);
	length = read_word(orig);
	read_word(orig);
	flags = read_word(orig);
	magic = read_word(orig);
	fseek(orig, 0x100-28, SEEK_CUR);
	section_offset = ftell(orig);

	if (verbose)
	{
		fprintf(stderr, "Section found\n");
		fprintf(stderr, "\tCRC\t= %08x\n", crc);
		fprintf(stderr, "\tVersion = %08x\n", version);
		fprintf(stderr, "\tBuild\t= %08x\n", build_date);
		fprintf(stderr, "\tLength\t= %08x\n", length);
		fprintf(stderr, "\tFlags\t= %08x\n", flags);
		fprintf(stderr, "\tMagic\t= %08x\n", magic);
	}

	fclose(orig);





	prefix = argv[2];

	for (i=0;i<SECTION_COUNT;i++) {
		str=(char *)malloc(strlen(prefix+3));
		ret=snprintf(str,strlen(prefix)+3,"%s_%d",prefix,i);
		// TODO: should really check this return value
		section_fname[i]=str;
	}


	for (i=0;i<SECTION_COUNT;i++) {
		section_fp = fopen(section_fname[i],"rb");
		if (!section_fp) {
			printf("Could not open %s\n", section_fname[i]);
			ret=-1;
			goto cleanup; // o_O
		}

		stat(section_fname[i],&st);
		size = st.st_size;

		buf = malloc(size);
		ret = read_file(section_fp, buf, size);
		// TODO: check for errors
		crc = crc32(buf, size);

		printf("section file: %s; size: %d; crc: 0x%08x\n",section_fname[i],size,crc);





		free(buf);
		fclose(section_fp);	
	}


	cleanup:

	// cleanup: clear section file names
	for (i=0;i<SECTION_COUNT;i++) {
		free(section_fname[i]);
	}

	return ret;
}
