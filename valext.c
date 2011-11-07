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
#define CHAINSIZE 170

struct blockchain {
	int size;
	uint64_t *head;
	struct blockchain *tail;
};

//#define CHAINSIZE 4096/sizeof(struct blockchain)

uint64_t* blockalloc(int size)
{	
	uint64_t *buf = calloc(size, sizeof(uint64_t));
	return buf;
}

struct blockchain *newchain(int size)
{
	struct blockchain *chain = NULL;
	chain = calloc(1, sizeof(struct blockchain));
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
	if (!chain)
		return;
	cleanchain(chain->tail);
	free(chain->head);
	free(chain);
	return;
}

/* set up a list */
int getnextblock(struct blockchain *header, char *buf, int size, int *t)
{
	int match;
	uint64_t startaddr;
	uint64_t endaddr;
	uint64_t i;
	struct blockchain* chain = header;
	const char* pattern;
	int retval = 0;
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
	for (i = startaddr; i < endaddr; i++)
	{
		chain->head[*t]  = i;
		(*t)++;
		if (*t == size) {
			if (chain->tail == 0) {
				struct blockchain *nxtchain = 
					newchain(size);
				if (!nxtchain)
					goto cleanup;
				chain->tail = nxtchain;
			}
			chain = chain->tail;
			*t = 0;
		}
		chain->head[*t] = 0; //guard
	}
	retval = 1;

cleanup:
	regfree(&reg);
ret:
	return retval;
} 

/* query /proc filesystem */
void getblocks(char* pid, struct blockchain* header, int size)
{
	FILE *ret;
	int t = 0;
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
		if (!getnextblock(header, buf, size, &t)) {
			goto close;
		}
	}
close:
	fclose(ret); 
ret:
	return;
}

/* now read the status of each page */
int getblockstatus(char* pid, struct blockchain *chain,
	FILE* xmlout, int cnt, int size)
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
			//page is present but not in page table
			notpresentcnt++;		
		}
		i++;
		if (i >= size){
			chain = chain->tail;
			i = 0;
		}
	}
	sprintf(traceline,
	"<trace steps=\"%u\" present=\"%u\" swapped=\"%u\" presonly=\"%u\"/>\n",
	cnt, presentcnt, swappedcnt, notpresentcnt);
	fputs(traceline, xmlout);

freebuf:
	free(buf);
clean:
	fclose(ret);
ret:
	return presentcnt;
}

/* run the child */
void getWSS(pid_t forked, FILE* xmlout, int size)
{
	int i = 0, status;
	struct blockchain *header = newchain(size);
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
		getblocks(pid, header, size);
		if (header->head[0])
			getblockstatus(pid, header, xmlout, i++, size);
	}
	cleanchain(header);
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
	fputs("<!ELEMENT ptracexml (trace,faults?)*>\n", outXML);
	fputs("<!ELEMENT trace EMPTY>\n", outXML);
	fputs("<!ATTLIST trace step CDATA #REQUIRED>\n", outXML);
	fputs("<!ATTLIST trace present CDATA #REQUIRED>\n", outXML);
	fputs("<!ATTLIST trace swapped CDATA #REQUIRED>\n", outXML);
	fputs("<!ATTLIST trace presonly CDATA #REQUIRED>\n", outXML);
	fputs("<!ELEMENT faults EMPTY>\n", outXML);
	fputs("<!ATTLIST faults soft CDATA #REQUIRED>\n", outXML);
	fputs("<!ATTLIST faults hard CDATA #REQUIRED>\n", outXML);
	fputs("]>\n", outXML);
	fputs("<ptracexml>\n", outXML);
	getWSS(forker, outXML, CHAINSIZE);
	fputs("</ptracexml>\n", outXML);
	fclose(outXML);
	return 1;
}
