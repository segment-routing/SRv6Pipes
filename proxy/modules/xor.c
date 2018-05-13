#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <hashmap.h>
#include <proxy.h>

static char *modname = "xor";
void module_init();
int (xor_payload)(int, int, char*);

void module_init() {
	printf("Loading module: %s\n", modname);
	uint16_t opcode = 0xAAAA;
	add_operation(opcode, &xor_payload, modname);
}

int xor_payload(int params, int size, char *payload)
{
	printf("this is XOR with params %004X\n", params);
    int i,j;
    for (j=1; j<=1; j++) {
        for (i=0; i < size; i++) {
            payload[i] = payload[i] ^ 0x80;
        }
        for (i=0; i < size; i++) {
            payload[i] = payload[i] ^ 0x80;
        }
    } 
}

