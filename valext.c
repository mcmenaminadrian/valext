#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <regex.h>

#define PAGESHIFT 12
#define MEMBLOCK 512

struct blocklist {
	long address;
	struct blocklist *nextblock;
};

/* recursively free the list */
void cleanblocklist(struct blocklist *bl)
{
	struct blocklist *nextblock;
	if (bl == NULL)
		return;
	nextblock = bl->nextblock;
	free(bl);
	cleanblocklist(nextblock);
}

/* set up a list */
struct blocklist* getnextblock(struct blocklist** lastblock,
	struct blocklist** header, char* buf)
{
	int match;
	int startaddr;
	int endaddr;
	struct blocklist* block;
	int i;
	const char* pattern;
	regex_t reg;
	regmatch_t addresses[3];

	pattern = "^([0-9a-f]+)-([0-9a-f]+)";
	if (regcomp(&reg, pattern, REG_EXTENDED) != 0)
		return *lastblock;
	match = regexec(&reg, buf, (size_t)3, addresses, 0);
	if (match == REG_NOMATCH || match == REG_ESPACE)
		return *lastblock;
	startaddr = strtoul(&buf[addresses[1].rm_so], NULL, 16) >> PAGESHIFT;
	endaddr = strtoul(&buf[addresses[2].rm_so], NULL, 16) >> PAGESHIFT;
	for (i = startaddr; i < endaddr; i++)
	{
		block = malloc(sizeof (struct blocklist));
		block->address = i;
		block->nextblock = NULL;
		if (*lastblock == NULL){
			*lastblock = block;
			*header = block;
		} else {
			(*lastblock)->nextblock = block;
			*lastblock = block;
		}
	}	
	regfree(&reg);
	return *lastblock;
} 

struct blocklist* getblocks(char* pid)
{
	/* open /proc/pid/maps */
	char st1[MEMBLOCK] = "/proc/";
	strcat(st1, pid);
	strcat(st1, "/maps");
	printf("%s\n", st1);
	struct blocklist *head = NULL;
	struct blocklist *lastblock = NULL;
	
	FILE *ret = fopen(st1, "r");
	if (ret == NULL) {
		printf("Could not open %s\n", st1);
		goto ret;
	}
	char buf[512];
	int i = 0;
	while (!feof(ret)){
		fgets(buf, MEMBLOCK, ret);
		lastblock = getnextblock(&lastblock, &head, buf);
		if (!lastblock)
			goto close;
		printf("Line %d is:%s\n", i, buf);
		i++;
	}
close:
	fclose(ret); 
ret:
	return head;
}

int main(int argc, char* argv[])
{
	if (argc < 2)
		return 0; /* must supply a pid */
	struct blocklist *blocks = getblocks((char *)argv[1]);
	while (blocks) {
		printf("Block at page %d\n", blocks->address);
		blocks= blocks->nextblock;
	}
	cleanblocklist(blocks);
	return 1;
}
	
