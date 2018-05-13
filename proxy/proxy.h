#ifndef PROXY_H
#define PROXY_H

#include <sys/queue.h>
#include <dlfcn.h>
#include <stdint.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>

#define BUFSIZE	8192
#define MAXFD	1024
#define MAX_EPOLL_EVENTS 10
#define SPLICE_LEN 65536
#define COPY_BUF_SIZE 32768


struct ipv6_sr_hdr {
	uint8_t		nexthdr;
	uint8_t		hdrlen;
	uint8_t		type;
	uint8_t		segments_left;
	uint8_t		first_segment;
	uint8_t		flags;
	uint16_t	reserved;

	struct in6_addr segments[0];
};

struct sr6_tlv {
        uint8_t type;
        uint8_t len;
        uint8_t data[0];
};

struct sr6_tlv_retpath {
        struct sr6_tlv  tlvhdr;
        uint8_t         reserved[5];
        uint8_t         segments_left;
        struct in6_addr segments[0];
};

struct hashmap *flows_map;
struct hashmap *fds_map;

struct tcp_flow {
	struct in6_addr saddr;
	struct in6_addr daddr;
	uint16_t sport;
	uint16_t dport;
};

static unsigned int hash_tcp_flow(void *key)
{
	struct tcp_flow *tfl = key;
	unsigned int h;

	h = hash_in6(&tfl->saddr) ^ hash_int((void *)(uintptr_t)tfl->sport) ^
	    hash_in6(&tfl->daddr) ^ hash_int((void *)(uintptr_t)tfl->dport);

	return h;
}

static int compare_tcp_flow(void *k1, void *k2)
{
	struct tcp_flow *tfl1, *tfl2;
	int ret;

	tfl1 = k1;
	tfl2 = k2;

	ret =	(memcmp(&tfl1->saddr, &tfl2->saddr, sizeof(struct in6_addr)) == 0) &&
		(memcmp(&tfl1->daddr, &tfl2->daddr, sizeof(struct in6_addr)) == 0) &&
		(tfl1->sport == tfl2->sport) && (tfl1->dport == tfl2->dport);

	return !ret;
}

/* Connections states */
enum{
    CONN_AVAILABLE=0,
    CONN_CLOSED,
};
typedef uint8_t conn_state_t;


struct module {
	char modname[50+1];
	void *handle;

	TAILQ_ENTRY(module) module_ptrs;
};
typedef struct module module_t;

TAILQ_HEAD(modulehead, module);
extern struct modulehead modules_list;

struct operation {
	uint16_t opcode;
	int (*function)(int, int, char*);
	char modname[50+1];

	TAILQ_ENTRY(operation) operation_ptrs;
};
typedef struct operation operation_t;

TAILQ_HEAD(operationhead, operation);
extern struct operationhead operations_list;

operation_t *find_operation (uint16_t opcode)
{
	operation_t *item;
	
	TAILQ_FOREACH(item, &operations_list, operation_ptrs) {
		if (item->opcode == opcode)
			return item;
	}
	return NULL;
}

int add_operation(uint16_t opcode, int (*fptr)(int, int, char*), char *name)
{

	operation_t *op;

	if ((op = find_operation(opcode))) {
		fprintf(stderr,"Error: trying to link operation %04X to module %s: already linked to %s\n",opcode,name,op->modname);
		return 0;
	}

	op = (operation_t *)malloc(sizeof(operation_t));
	op->opcode = opcode;
	strncpy(op->modname,name,50);
	op->modname[50] = '\0';
	op->function = fptr; /* saving operation function */
	
	TAILQ_INSERT_HEAD(&operations_list, op, operation_ptrs);
	return 1;
}
struct tproxy_conn{
    int local_fd; // Connection to host on local network
    int remote_fd; // Connection to remote host
    conn_state_t state;
    uint16_t opcode; // Function to apply to the payload
    uint32_t params; // Parameters of the function
    operation_t *operation;

    //Create the struct which contains ptrs to next/prev element
    TAILQ_ENTRY(tproxy_conn) conn_ptrs;
};
typedef struct tproxy_conn tproxy_conn_t;

TAILQ_HEAD(tailhead, tproxy_conn);
#endif
