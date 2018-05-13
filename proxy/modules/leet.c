#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <hashmap.h>
#include <proxy.h>

static char *modname = "leet";
void module_init();
int (leet_payload)(int, int, char*);
int replacechar(char*, char, char);

void module_init() {
	printf("Loading module: %s\n",modname);
	uint16_t opcode = 0xAAAB;
	add_operation(opcode, &leet_payload, modname);
}

int leet_payload(int params, int size, char *message)
{
//	printf("this is LEET with size %d and message %s\n", size, message);

    if (size == 0)
        return 1;

	replacechar(message, 'e', '3');
	replacechar(message, 'a', '@');
	replacechar(message, 'i', '1');
	replacechar(message, 'o', '0');
	replacechar(message, 'S', '5');
	replacechar(message, 's', '5');
	replacechar(message, 't', '7');

    return 0;
}

int replacechar(char *str, char orig, char rep) 
{
    char *ix = str;
    int n = 0;
    while((ix = strchr(ix, orig)) != NULL) {
        *ix++ = rep;
        n++;
    }
    return n;
}
