#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <regex.h>
#include <unistd.h>
#include <sys/ptrace.h>

#define PAGESHIFT 12
#define MEMBLOCK 512

struct blocklist {
	uint64_t address;
	struct blocklist *nextblock;
};

struct workingsetstats {
	uint64_t secs;
	double present;
	double swapped;
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
	uint64_t startaddr;
	uint64_t endaddr;
	struct blocklist* block;
	uint64_t i;
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

/* query /proc filesystem */
struct blocklist* getblocks(char* pid)
{
	FILE *ret;
	struct blocklist *head = NULL;
	struct blocklist *lastblock = NULL;
	/* open /proc/pid/maps */
	char st1[MEMBLOCK] = "/proc/";
	strcat(st1, pid);
	strcat(st1, "/maps");
	
	ret = fopen(st1, "r");
	if (ret == NULL) {
		printf("Could not open %s\n", st1);
		goto ret;
	}
	char buf[MEMBLOCK];
	int i = 0;
	while (!feof(ret)){
		fgets(buf, MEMBLOCK, ret);
		lastblock = getnextblock(&lastblock, &head, buf);
		if (!lastblock)
			goto close;
		i++;
	}
close:
	fclose(ret); 
ret:
	return head;
}

/* now read the status of each page */
int getblockstatus(char* pid, struct blocklist *blocks)
{
	FILE *ret;
	int fd;
	int presentcnt = 0;
	int swappedcnt = 0;
	int notpresentcnt = 0;
	char *buf;
	/* open /proc/pid/pagemap */
	char st1[MEMBLOCK] = "/proc/";
	strcat(st1, pid);
	strcat(st1, "/pagemap");
	ret = fopen(st1, "r");
	if (ret == NULL) {
		printf("Could not open %s\n", st1);
		goto ret;
	}
	fd = fileno(ret);
	if (fd == -1) {
		printf("Could not get file descriptor for %s\n", st1);
		goto clean;
	}
	
	buf = malloc(8);
	if (!buf) {
		printf("Could not allocate memory\n");
		goto clean;
	}
	while (blocks) {
		uint64_t swapped = 0x4000000000000000;
		uint64_t present = 0x8000000000000000;
		uint64_t pfnmask = 0x007fffffffffffff;
		int64_t lres = lseek(fd, blocks->address << 3, SEEK_SET);
		if (lres == -1) {
			printf("Could not seek to %llX\n", blocks->address);
			goto freebuf;
		}
		char *buf = malloc(8);
		read(fd, buf, 8);
		uint64_t *pgstatus = (uint64_t *)buf;

		if (*pgstatus & swapped) {
			swappedcnt++;
		} else if (*pgstatus & present) {
			presentcnt++;
		} else {
			//page is mapped but unused
			notpresentcnt++;		
		}
		blocks = blocks->nextblock;
	}
	printf("%u pages present, %u pages swapped\n",
		presentcnt, swappedcnt);

freebuf:
	free(buf);
clean:
	fclose(ret);
ret:
	return presentcnt;
}

/* run the child */
struct workingsetstats *getWSS(pid_t forked)
{
	struct workingsetstats *wss = NULL;
	int i;
	int killrep;
	int waitrep;
	int status;
	/*create a string representation of pid */
	char pid[MEMBLOCK];
	sprintf(pid, "%llu", forked);
	/* zero out starting stats */
	wss = malloc(sizeof(struct workingsetstats));
	if (!wss)
		goto ret;
	wss->secs = 0;
	wss->present = 0;
	wss->swapped = 0;
	/* loop while signalling child */
	for (i = 0; i < 0x1000; i++)
	{
		//dummy signal
		killrep = kill(forked, SIG_DFL);
		if (killrep != 0) {
			printf("Run %d: Could not signal child process %s\n",
				i, pid);
			goto ret;
		}
		waitrep = wait(forked, &status, 0);
		if (status == WIFCONTINUED) {
			printf("Continued\n");
			continue;
		}
		
		struct blocklist *blocks = getblocks(pid);
		if (blocks)
			getblockstatus(pid, blocks);
		cleanblocklist(blocks);
		killrep = kill(forked, SIGCONT);
		if (killrep != 0) {
			printf("Run %d: Could not continue child process %s\n",
				i, pid);
			goto ret;
	}
ret:
	return wss;

int main(int argc, char* argv[])
{
	int i;
	if (argc < 2)
		return 0; /* must supply a file to execute */
	pid_t forker = fork();
	if (forker == 0) {
		//in the child process
		if (argc > 2) {
			char* childargs[argc - 2];
			for (i = 2; i < argc; i++) 
				childargs[i - 1] = argv[i];	
			ptrace(PTRACE_TRACEME, 0, NULL, NULL);
			execvp(childargs[0], childargs);
		} else {
			ptrace(PTRACE_TRACEME, 0, NULL, NULL);
			execvp(argv[1], NULL);
		}
		return 0;
	}
	//in the original process
	if (forker < 0) {
		printf("Could not get %s to run\n", argv[1]);
		return 0;
	}
	struct workingsetstats procWSS = *getWSS(forker);	
	char pid[MEMBLOCK];
	sprintf(pid, "%d", forker); 
	struct blocklist *blocks = getblocks(pid);
	if (blocks)
		getblockstatus(pid, blocks);
	cleanblocklist(blocks);
	return 1;
}
	
