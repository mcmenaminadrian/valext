#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <regex.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <signal.h>
#include <sys/wait.h>
#include <time.h>

#define PAGESHIFT 12
#define MEMBLOCK 512

struct blockchain {
	int size;
	uint64_t *head;
	struct blockchain *tail;
};

uint64_t* blockalloc(int size)
{	
	uint64_t *buf = calloc(size, sizeof(uint64_t));
	return buf;
}

struct blockchain *newchain(int size)
{
	struct blockchain *chain = NULL;
	chain = malloc(sizeof(struct blockchain));
	if (!chain)
		return NULL;
	chain->head = blockalloc(size);
	if (chain->head == NULL) {
		free(chain);
		return NULL;
	}
	chain->size = size;
	return chain;
}

/* recursively free the list */
void cleanchain(struct blockchain *chain)
{
	if (chain == NULL)
		return;
	struct blockchain *head = chain;
	if (chain->tail)
		cleanchain(chain->tail);
	free(head);
	head = NULL;
	free(chain);
	chain = NULL;
	return;
}

/* set up a list */
struct blockchain* getnextblock(struct blockchain** chain,
	struct blockchain** header, char* buf)
{
	int match, t = 0;
	uint64_t startaddr;
	uint64_t endaddr;
	uint64_t i;
	const char* pattern;
	regex_t reg;
	regmatch_t addresses[3];

	pattern = "^([0-9a-f]+)-([0-9a-f]+)";
	if (regcomp(&reg, pattern, REG_EXTENDED) != 0)
		goto ret;
	match = regexec(&reg, buf, (size_t)3, addresses, 0);
	if (match == REG_NOMATCH || match == REG_ESPACE)
		goto cleanup;
	startaddr = strtoul(&buf[addresses[1].rm_so], NULL, 16) >> PAGESHIFT;
	endaddr = strtoul(&buf[addresses[2].rm_so], NULL, 16) >> PAGESHIFT;
	if (chain == NULL) {
		*chain = newchain(MEMBLOCK);
		if (!chain)
			goto cleanup;
		*header = *chain;
	}
	for (i = startaddr; i < endaddr; i++)
	{
		if (t >=  MEMBLOCK) {
			struct blockchain *nxtchain = newchain(MEMBLOCK);
			if (!nxtchain)
				goto cleanup;
			(*chain)->tail = nxtchain;
			*chain = nxtchain;
			t = 0;
		}
		(*chain)->head[t] = i;
		t++;
	}
cleanup:
	regfree(&reg);
ret:
	return *chain;
} 

/* query /proc filesystem */
struct blockchain* getblocks(char* pid)
{
	FILE *ret;
	struct blockchain *chain = NULL;
	struct blockchain *header = NULL;
	char buf[MEMBLOCK];
	/* open /proc/pid/maps */
	char st1[MEMBLOCK] = "/proc/";
	strcat(st1, pid);
	strcat(st1, "/maps");
	
	ret = fopen(st1, "r");
	if (ret == NULL) {
		printf("Could not open %s\n", st1);
		goto ret;
	}
	while (!feof(ret)){
		fgets(buf, MEMBLOCK, ret);
		chain = getnextblock(&chain, &header, buf);
		if (!chain)
			goto close;
	}
close:
	fclose(ret); 
ret:
	return header;
}

/* now read the status of each page */
int getblockstatus(char* pid, struct blockchain *chain,
	FILE* xmlout, int size, int cnt)
{
	FILE *ret;
	int fd, i = 0;
	int presentcnt = 0;
	int swappedcnt = 0;
	int notpresentcnt = 0;
	char *buf;
	uint64_t swapped = 0x4000000000000000;
	uint64_t present = 0x8000000000000000;
	uint64_t pfnmask = 0x007fffffffffffff;
	char traceline[MEMBLOCK];
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
	while (chain && chain->head[i]) {
		uint64_t *pgstatus;
		int64_t lres = lseek(fd, chain->head[i] << 3, SEEK_SET);
		if (lres == -1) {
			printf("Could not seek to %llX\n", chain->head[i]);
			goto freebuf;
		}
		read(fd, buf, 8);
		pgstatus = (uint64_t *)buf;

		if (*pgstatus & swapped) {
			swappedcnt++;
		} else if (*pgstatus & present) {
			presentcnt++;
		} else {
			//page is mapped but unused
			notpresentcnt++;		
		}
		i++;
		if (i >= size){
			chain = chain->tail;
			i = 0;
		}
	}
	sprintf(traceline,
		"<trace steps=\"%u\" present=\"%u\" swapped=\"%u\"/>\n",
		cnt, presentcnt, swappedcnt);
	fputs(traceline, xmlout);

freebuf:
	free(buf);
clean:
	fclose(ret);
ret:
	return presentcnt;
}

/* run the child */
void getWSS(pid_t forked, FILE* xmlout)
{
	int i = 0, status;
	struct blockchain *chain = NULL;
	/*create a string representation of pid */
	char pid[MEMBLOCK];
	sprintf(pid, "%u", forked);
	/* loop while signalling child */
	while(1)
	{
		wait(&status);
		ptrace(PTRACE_SINGLESTEP, forked, 0, 0);
		if (WIFEXITED(status))
			break;
		chain = getblocks(pid);
		if (chain)
			getblockstatus(pid, chain, xmlout, MEMBLOCK, i++);
		cleanchain(chain);
	}
}

int main(int argc, char* argv[])
{
	FILE* outXML;
	char filename[MEMBLOCK];
	if (argc < 2)
		return 0; /* must supply a file to execute */
	srand(time(NULL));
	pid_t forker = fork();
	if (forker == 0) {
		//in the child process
		if (argc == 3) {
			ptrace(PTRACE_TRACEME, 0, 0, 0);
			execlp(argv[1], argv[2], NULL);
		} else {
			ptrace(PTRACE_TRACEME, 0, 0, 0);
			execvp(argv[1], NULL);
		}
		return 0;
	}
	//in the original process
	if (forker < 0) {
		printf("Could not get %s to run\n", argv[1]);
		return 0;
	}
	/* Open XML file */
	sprintf(filename, "XMLtrace%d_%d.xml", forker, rand());
	outXML = fopen(filename, "a");
	if (!outXML) {
		printf("Could not open %s\n", filename);
		return 0;
	}
	fputs("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n", outXML);
	fputs("<!DOCTYPE ptracexml [\n", outXML);
	fputs("<!ELEMENT ptracexml (trace)*>\n", outXML);
	fputs("<!ELEMENT trace EMPTY>\n", outXML);
	fputs("<!ATTLIST trace step CDATA #REQUIRED>\n", outXML);
	fputs("<!ATTLIST trace present CDATA #REQUIRED>\n", outXML);
	fputs("<!ATTLIST trace swapped CDATA #REQUIRED>\n", outXML);
	fputs("]>\n", outXML);
	fputs("<ptracexml>\n", outXML);
	getWSS(forker, outXML);
	fputs("</ptracexml>\n", outXML);
	fclose(outXML);
	return 1;
}

