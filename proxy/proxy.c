/*
 * SRv6Pipes, enabling in-network bytestream functions
 * Copyright (C) 2005-2009  Fabien Duchene (fabien.duchene@uclouvain.be)
 *                          David Lebrun (david.lebrun@uclouvain.be)
 *
 * TPROXY inspired by https://github.com/kristrev/tproxy-example
 *
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <pthread.h>
#include <poll.h>
#include <sys/queue.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>

#include "hashmap.h"
#include "proxy.h"

struct operationhead operations_list;
struct modulehead modules_list;

int exec_payload_function(uint16_t opcode, uint32_t params, int size, char *payload)
{
	int ret=0;
	operation_t *operation = find_operation(opcode);
	if (operation) {
		ret = operation->function(params, size, payload);
		return ret;
	}
	return 1;
}

void free_conn(tproxy_conn_t *conn)
{
	close(conn->local_fd);
	close(conn->remote_fd);

	free(conn);
}

void close_tcp_conn(tproxy_conn_t *conn, struct tailhead *conn_list, struct tailhead *close_list)
{
    conn->state = CONN_CLOSED;
    TAILQ_REMOVE(conn_list, conn, conn_ptrs);
    TAILQ_INSERT_TAIL(close_list, conn, conn_ptrs);
}

int8_t block_sigpipe()
{
	sigset_t sigset;
	memset(&sigset, 0, sizeof(sigset));

	if(sigprocmask(SIG_BLOCK, NULL, &sigset) == -1){
		perror("sigprocmask (get)");
		return -1;
	}

	if(sigaddset(&sigset, SIGPIPE) == -1){
		perror("sigaddset");
		return -1;
	}

	if(sigprocmask(SIG_BLOCK, &sigset, NULL) == -1){
		perror("sigprocmask (set)");
		return -1;
	}

	return 0;
}

int handle_event_copy(tproxy_conn_t *conn, char *buffer) 
{
	int bytesleft = 0, numbytes, totalbytes = 0, n, err;

	if (ioctl(conn->local_fd, FIONREAD, &numbytes) != -1 && numbytes > 0) {
		bytesleft = numbytes;
	
		while(bytesleft > 0) {
            int m = 0;

			n = recv(conn->local_fd, buffer, COPY_BUF_SIZE, 0);
            if (conn->operation)
                conn->operation->function(conn->params, n, buffer);

            while (m < n) {
    			err = send(conn->remote_fd, buffer + m, n - m, 0);
    			if (err < 0) {
                    if (m > 0)
        				perror("send remote");
    				return -1;
    			}
                if (m > 0)
                    printf("filling partial buffer from %u/%u to %u/%u\n", m, n, m+err, n);
                m += err;
                if (m < n)
                    printf("%u < %u (+ %u)\n", m, n, err);
            }

			totalbytes += n;
			bytesleft-=n;
		}
	} else if (ioctl(conn->remote_fd, FIONREAD, &numbytes) != -1 && numbytes > 0) {
		bytesleft = numbytes;

		while(bytesleft > 0) {
            int m = 0;

			n = recv(conn->remote_fd, buffer, COPY_BUF_SIZE, 0);
            if (conn->operation)
                conn->operation->function(conn->params, n, buffer);

            while (m < n) {
    			err = send(conn->local_fd, buffer + m, n - m, 0);
    			if (err < 0) {
                    if (m > 0)
        				perror("send local");
    				return -1;
    			}
                if (m > 0)
                    printf("filling partial buffer from %u/%u to %u/%u\n", m, n, m+err, n);

                m += err;
                if (m < n)
                    printf("%u < %u (+ %u)\n", m, n, err);

            }

			totalbytes += n;
			bytesleft-=n;
		}
	}

	return totalbytes;
}

void remove_closed_connections(struct tailhead *close_list, char *buffer)
{
	tproxy_conn_t *conn = NULL;

	while(close_list->tqh_first != NULL){
		conn = (tproxy_conn_t*) close_list->tqh_first;
		handle_event_copy(conn, buffer);
		TAILQ_REMOVE(close_list, close_list->tqh_first, conn_ptrs);
		free_conn(conn);
	}
}

int8_t check_connection_attempt(tproxy_conn_t *conn, int efd)
{
	struct epoll_event ev;
	int conn_success = 0;
	int fd_flags = 0;
	socklen_t optlen = sizeof(conn_success);
	
	if(getsockopt(conn->remote_fd, SOL_SOCKET, SO_ERROR, &conn_success, &optlen) == -1){
		perror("getsockopt (SO_ERROR)");
		return -1;
	}

	if(conn_success == 0) {

		if((fd_flags = fcntl(conn->remote_fd, F_GETFL)) == -1){
			perror("fcntl (F_GETFL)");
			return -1;
		}

		if(fcntl(conn->remote_fd, F_SETFL, fd_flags & ~O_NONBLOCK) == -1){
		    perror("fcntl (F_SETFL)");
		    return -1;
		}

		memset(&ev, 0, sizeof(ev));
		ev.events = EPOLLIN | EPOLLRDHUP;
		ev.data.ptr = (void*) conn;

		if(epoll_ctl(efd, EPOLL_CTL_MOD, conn->remote_fd, &ev) == -1 ||
			epoll_ctl(efd, EPOLL_CTL_MOD, conn->local_fd, &ev) == -1){
			perror("epoll_ctl (check_connection_attempt)");
			return -1;
		} else {
			return 0;
		}
	}

	return -1;
}
tproxy_conn_t* add_tcp_connection(int efd, struct tailhead *conn_list, int client_fd, struct sockaddr_in6 sin6_client)
{   
	struct sockaddr_in6 sin6_local, sin6_bind, sin6_dst;
	struct ipv6_sr_hdr *srh; /* SRH that we got */
	struct tcp_flow *tfl; /* Current tcp flow */
	tproxy_conn_t *conn = NULL;
	char sa[INET6_ADDRSTRLEN];
	char da[INET6_ADDRSTRLEN];
	char da_seg[INET6_ADDRSTRLEN];
	struct sr6_tlv_retpath *rt_tlv;
	struct epoll_event ev;
	int dst_fd;
	socklen_t slen;
	int v = 1;
	int err = 0;
    uint16_t opcode_rcv = 0;
    uint32_t params_rcv = 0;

	inet_ntop(AF_INET6, &sin6_client.sin6_addr, sa, INET6_ADDRSTRLEN);

	slen = sizeof(struct sockaddr_in6);
	getsockname(client_fd, (struct sockaddr *)&sin6_local, &slen);
	inet_ntop(AF_INET6, &sin6_local.sin6_addr, da, INET6_ADDRSTRLEN);

	/* Create a TCP flow to match the hashmap */
	tfl = malloc(sizeof(*tfl));
	tfl->saddr = sin6_client.sin6_addr;
	tfl->daddr = sin6_local.sin6_addr;
	tfl->sport = ntohs(sin6_client.sin6_port);
	tfl->dport = ntohs(sin6_local.sin6_port);

	/* Getting the SRH associated with this flow */
	hmap_read_lock(flows_map);
	srh = hmap_get(flows_map, tfl);
	hmap_unlock(flows_map);

	free(tfl);

    /* FIXME: yes please! */
    opcode_rcv = (srh->segments[srh->segments_left].s6_addr[10] << 8) | srh->segments[srh->segments_left].s6_addr[11]; 
    params_rcv = (srh->segments[srh->segments_left].s6_addr[12] << 24) | (srh->segments[srh->segments_left].s6_addr[13] << 16) | (srh->segments[srh->segments_left].s6_addr[14] << 8) | (srh->segments[srh->segments_left].s6_addr[15]); 

	/* Decreasing the number of segments left */
	srh->segments_left--;

	/* hack: consider only RETPATH TLV is present */
	rt_tlv = (struct sr6_tlv_retpath *)((unsigned char *)srh + sizeof(*srh) + ((srh->first_segment + 1) << 4));
	rt_tlv->segments_left++;

	inet_ntop(AF_INET6, &srh->segments[0], da_seg, INET6_ADDRSTRLEN);

	/* Create a socket to remote end */
	dst_fd = socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
	if (dst_fd < 0) {
		perror("socket");
		goto error;
	}
	
	if (setsockopt(dst_fd, SOL_SOCKET, SO_REUSEADDR, &v, sizeof(v)) < 0) {
		perror("setsockopt_reuseaddr");
		goto error;
	}

	/* Binding on the client address */
	memset(&sin6_bind, 0, sizeof(sin6_bind));
	sin6_bind.sin6_family = AF_INET6;
	sin6_bind.sin6_addr = sin6_client.sin6_addr;

	if (setsockopt(dst_fd, SOL_IP, IP_FREEBIND, &v, sizeof(v)) < 0) {
		perror("client: setsockopt_tproxy");
		goto error;
	}

	err = bind(dst_fd, (struct sockaddr *)&sin6_bind, sizeof(sin6_bind));
	if (err < 0) {
		perror("bind client ip");
		goto error;
	}

	/* Insert the modified SRH */
	err = setsockopt(dst_fd, IPPROTO_IPV6, IPV6_RTHDR, srh, ((srh->hdrlen + 1) << 3));
	if (err < 0) {
		perror("setsockopt RTHDR");
		goto error;
	}

	/* Connect to the remote end */
	memset(&sin6_dst, 0, sizeof(sin6_dst));
	sin6_dst.sin6_family = AF_INET6;
	sin6_dst.sin6_port = sin6_local.sin6_port;
	inet_pton(AF_INET6, da_seg, &sin6_dst.sin6_addr);

	err = connect(dst_fd, (struct sockaddr *)&sin6_dst, sizeof(sin6_dst));
	if (err < 0 && errno != EINPROGRESS) {
		perror("connect to dst");
		goto error;
	}

	/* Create the connection infos */
	if((conn = (tproxy_conn_t*) malloc(sizeof(tproxy_conn_t))) == NULL){
		fprintf(stderr, "Could not allocate memory for connection\n");
		goto error;
	}

	memset(conn, 0, sizeof(tproxy_conn_t));
	conn->state = CONN_AVAILABLE;
	conn->remote_fd = dst_fd;
	conn->local_fd = client_fd;
    conn->opcode = opcode_rcv;
    conn->params = params_rcv;
    conn->operation = find_operation(opcode_rcv);
	TAILQ_INSERT_HEAD(conn_list, conn, conn_ptrs);

	/* Monitor the connection to the server*/
	memset(&ev, 0, sizeof(ev));
	ev.events = EPOLLIN | EPOLLOUT;
	ev.data.ptr = (void*) conn;

	if(epoll_ctl(efd, EPOLL_CTL_ADD, dst_fd, &ev) == -1){
		perror("epoll_ctl (dst_fd)");
		free_conn(conn);
		return NULL;
	}	

	/* Monitor our connection with the client i
	 * We don't want to receive any data before
	 * the connection to the server is established 
	 */
	ev.events = EPOLLRDHUP;

	if(epoll_ctl(efd, EPOLL_CTL_ADD, client_fd, &ev) == -1){
		perror("epoll_ctl (client_fd)");
		free_conn(conn);
		return NULL;
	}

    hmap_write_lock(flows_map);
	hmap_delete(flows_map, tfl);
    hmap_unlock(flows_map);
	return conn;

error:
	close(dst_fd);
	close(client_fd);
	return NULL;

}
void *thread_sock(void *arg)
{
	struct sockaddr_in6 sin6, sin6_client;
	int fd, nfd;
	socklen_t slen;
	int v = 1;

	struct epoll_event ev, events[MAX_EPOLL_EVENTS];
	struct tailhead conn_list, close_list;
	tproxy_conn_t *conn = NULL;
	int efd; /* Epoll FD */
	int i;
	uint8_t check_close = 0;
	int num_events = 0;
	int n = 0;
    char *databuf = NULL;

    if (posix_memalign((void **)&databuf, getpagesize(), COPY_BUF_SIZE) < 0) {
        perror("posix_memalign");
        return NULL;
    }

	/* Initialize connections lists */
	TAILQ_INIT(&conn_list);
	TAILQ_INIT(&close_list);

	/* Initialize epoll */
	if((efd = epoll_create(1)) == -1){
		perror("epoll_create");
		return NULL;
	}
	
	/* Creating the listening  socket */
	fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	if (fd < 0) {
		perror("socket");
		return NULL;
	}

	if (setsockopt(fd, SOL_IP, IP_TRANSPARENT, &v, sizeof(v)) < 0) {
		perror("setsockopt_tproxy");
		return NULL;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &v, sizeof(v)) < 0) {
		perror("setsockopt_reuseaddr");
		return NULL;
	}

	memset(&sin6, 0, sizeof(sin6));

	sin6.sin6_family = AF_INET6;
	sin6.sin6_port = htons((uintptr_t)arg);

	if (bind(fd, (struct sockaddr *)&sin6, sizeof(sin6)) < 0) {
		perror("bind");
		return NULL;
	}

	if (listen(fd, 8192) < 0) {
		perror("listen");
		return NULL;
	}

	/* Monitoring the listening socket */
	memset(&ev, 0, sizeof(ev));
	ev.events = EPOLLIN;
	ev.data.ptr = NULL; /* Only for the listening sock */

	if(epoll_ctl(efd, EPOLL_CTL_ADD, fd, &ev) == -1){
		perror("epoll_ctl (listen socket)");
		return NULL;
	}
	
	/* Splice might SIGPIPE, be expecting it to fail and return -1 */
	if(block_sigpipe() == -1){
		fprintf(stderr, "Could not block SIGPIPE signal\n");
		close(fd);
		exit(EXIT_FAILURE);
	}

	/* Main loop */
	while(1) {
		/* Waiting for an event on one of the monitored fds */
		if((num_events = epoll_wait(efd, events, MAX_EPOLL_EVENTS, -1)) == -1){
			perror("epoll_wait");
			break;
		}
		/* Event(s) received, process */
		for (i = 0; i < num_events; i++) {
			/* If ptr is NULL, we have to accept a new conn */
			if (events[i].data.ptr == NULL){
				slen = sizeof(struct sockaddr_in6);
				nfd = accept(fd, (struct sockaddr *)&sin6_client, &slen);
				if (nfd < 0) {
					perror("accept");
					return NULL;
				}
				if((conn = add_tcp_connection(efd, &conn_list, nfd, sin6_client)) == NULL){
					fprintf(stderr, "Failed to add connection\n");
					close(nfd);
				}
			} else {
				conn = (tproxy_conn_t*) events[i].data.ptr;

				/* Check if the connection to the server succeeded */
				if(events[i].events & EPOLLOUT){
					if(check_connection_attempt(conn, efd) == -1){
						fprintf(stderr, "Connection attempt failed for %d\n", conn->remote_fd);
						check_close = 1;
						close_tcp_conn(conn, &conn_list, &close_list);
					}
					continue;
				/* If we have an error on the socket, close the conn */
				} else if(conn->state != CONN_CLOSED && 
					(events[i].events & EPOLLRDHUP || 
					events[i].events & EPOLLHUP ||
					events[i].events & EPOLLERR)) {
					check_close = 1;
					close_tcp_conn(conn, &conn_list, &close_list);
					continue;
				}

				/* If the connection has been closed, no need to process it */
				if(conn->state == CONN_CLOSED){
					continue;
				}

				n = handle_event_copy(conn, databuf);

				if (n <= 0) {
					close_tcp_conn(conn, &conn_list, &close_list);
					check_close = 1;
				}
			}
		}

		if(check_close)
			remove_closed_connections(&close_list, databuf);

		check_close = 0;
	}

	close(fd);
	return NULL;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	struct nfqnl_msg_packet_hdr *ph;
	struct ipv6_sr_hdr *srh, *srh_data;
	unsigned char *payload;
	int verdict = NF_DROP;
	struct tcp_flow *tfl;
	struct tcphdr *tcph;
	struct ipv6hdr *hdr;
	uint32_t id;
	int srhlen;
	int ret;

	char sa[INET6_ADDRSTRLEN];
	char da[INET6_ADDRSTRLEN];
	char orig_da[INET6_ADDRSTRLEN];

	ph = nfq_get_msg_packet_hdr(nfa);
	id = ntohl(ph->packet_id);

	ret = nfq_get_payload(nfa, &payload);
	if (!ret)
		goto out;

	hdr = (struct ipv6hdr *)payload;
	if (hdr->nexthdr != IPPROTO_ROUTING)
		goto out;

	srh = (struct ipv6_sr_hdr *)(hdr + 1);
	if (srh->type != 4)
		goto out;

	if (srh->nexthdr != IPPROTO_TCP)
		goto out;

	srhlen = (srh->hdrlen + 1) << 3;
	tcph = (struct tcphdr *)((char *)srh + srhlen);

	inet_ntop(AF_INET6, &hdr->saddr, sa, INET6_ADDRSTRLEN);
	inet_ntop(AF_INET6, &hdr->daddr, da, INET6_ADDRSTRLEN);
	inet_ntop(AF_INET6, &srh->segments[0], orig_da, INET6_ADDRSTRLEN);

	tfl = malloc(sizeof(*tfl));
	tfl->saddr = hdr->saddr;
	tfl->daddr = srh->segments[0];
	tfl->sport = ntohs(tcph->source);
	tfl->dport = ntohs(tcph->dest);

	srh_data = malloc(srhlen);
	memcpy(srh_data, srh, srhlen);

    hmap_write_lock(flows_map);
	hmap_set(flows_map, tfl, srh_data);
    hmap_unlock(flows_map);

	verdict = NF_ACCEPT;

out:
	return nfq_set_verdict(qh, id, verdict, 0, NULL);
}

static void *thread_nfqueue(void *arg)
{
	char buf[4096] __attribute__((aligned));
	struct nfq_q_handle *qh;
	struct nfq_handle *h;
	int fd, rv;

	h = nfq_open();
	if (!h) {
		perror("nfq_open");
		return NULL;
	}

	if (nfq_unbind_pf(h, AF_INET6) < 0) {
		perror("nfq_unbind_pf");
		return NULL;
	}

	if (nfq_bind_pf(h, AF_INET6) < 0) {
		perror("nfq_bind_bf");
		return NULL;
	}

	qh = nfq_create_queue(h, (uintptr_t)arg, &cb, NULL);
	if (!qh) {
		perror("nfq_create_queue");
		return NULL;
	}

	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		perror("nfq_set_mode");
		return NULL;
	}

	fd = nfq_fd(h);

	while ((rv = recv(fd, buf, sizeof(buf), 0)))
		nfq_handle_packet(h, buf, rv);

	nfq_destroy_queue(qh);

	nfq_unbind_pf(h, AF_INET6);

	nfq_close(h);

	return NULL;
}

module_t *find_module (char *name)
{
	module_t *item;
	
	TAILQ_FOREACH(item, &modules_list, module_ptrs) {
		if (!strcmp(item->modname,name))
			return item;
	}
	return NULL;
}

module_t *loadmodule(char *name)
{
	char n[60];
	bzero(n,60);
	void *handle;
	void (*func)();
	const char *err = NULL;

	if (find_module(name)) {
		fprintf(stderr,"Error: trying to load module %s: already loaded\n",name);
		return NULL;
	}

	module_t *mod;
	sprintf(n,"./modules/%s.so",name);

	handle = dlopen(n,RTLD_NOW|RTLD_GLOBAL); /* opening the mod */
	if (!handle) {
		printf("HANDLE ERROR: %s\n",dlerror());
		return NULL;
	}

	func = dlsym(handle,"module_init"); /* retrieving module_init() function */
	if (((err = dlerror()) != NULL) && !func) {
		fprintf(stderr,"ERROR LOADING MODULE %s: %s\n",name,err);
		dlclose(handle);
		return NULL;
	}

	mod = (module_t *)malloc(sizeof(module_t));
	strncpy(mod->modname,name,50);
	mod->modname[50] = '\0';
	mod->handle = handle; /* saving module handle */

	TAILQ_INSERT_HEAD(&modules_list, mod, module_ptrs);

	func(mod);

	return mod;
}

int main(int ac, char **av)
{
	pthread_t *thr_sock;
	pthread_t thr_nfq;
	int nthr_sock, i;
	extern struct operationhead operations_list;

	if (ac != 4) {
		fprintf(stderr, "Usage: %s bindport nfq_channel sock_threads\n", av[0]);
		return -1;
	}

	nthr_sock = atoi(av[3]);
	if (nthr_sock < 1) {
		fprintf(stderr, "sock_threads must be >= 1.\n");
		return -1;
	}

	/* Init the list storing the modules */
	TAILQ_INIT(&modules_list);
	/* Init the list storing the functions to be applied */
	TAILQ_INIT(&operations_list);

	/* Loading modules 
	 * TODO: parse modules list 
	 */
	loadmodule("xor");
	loadmodule("leet");

	thr_sock = malloc(nthr_sock*sizeof(pthread_t));

	flows_map = hmap_new(hash_tcp_flow, compare_tcp_flow);
	fds_map = hmap_new(hash_int, compare_int);

	pthread_create(&thr_nfq, NULL, thread_nfqueue,
		       (void *)(uintptr_t)atoi(av[2]));

	for (i = 0; i < nthr_sock; i++) {
		pthread_create(&thr_sock[i], NULL, thread_sock,
		       (void *)(uintptr_t)atoi(av[1]));
	}

	pthread_join(thr_nfq, NULL);

	for (i = 0; i < nthr_sock; i++)
		pthread_join(thr_sock[i], NULL);

	return 0;
}
