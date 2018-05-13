#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <hashmap.h>
#include <proxy.h>

/* Module name, must be unique */
static char *modname = "example";
/* Init function */
void module_init();
/* Functions of your module */
int (process_payload)(int, int, char*);

/* Called when the module is loaded */
void module_init() {
	printf("Loading module: %s\n", modname);
    /* Use this function to associate a function code contained
       in the IPv6 address with your functions */
	uint16_t opcode = 0xBBBB;
	add_operation(opcode, &process_payload, modname);
}

/* Process the recived payload
 * params : the parameters contained in the IPv6 address 
 * size : number of bytes received
 * payload : payload received
*/
int process_payload(int params, int size, char *payload)
{
    return 0;
}

