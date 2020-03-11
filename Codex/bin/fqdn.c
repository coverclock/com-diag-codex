/* vi: set ts=4 expandtab shiftwidth=4: */
/**
 * @file
 *
 * Copyright 2018 Digital Aggregates Corporation, Colorado, USA<BR>
 * Licensed under the terms in LICENSE.txt<BR>
 * Chip Overclock <coverclock@diag.com><BR>
 * https://github.com/coverclock/com-diag-codex<BR>
 */

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char * argv[])
{
	int xc = 1;
	int rc = -1;
	char buffer[512];
	struct addrinfo * list = (struct addrinfo *)0;
	struct addrinfo * here = (struct addrinfo *)0;
	int ii = -1;
	int jj = -1;

	do {

		rc = gethostname(buffer, sizeof(buffer));
		if (rc < 0) {
			perror("gethostname");
			break;
		}
		buffer[sizeof(buffer) - 1] = '\0';

		printf("hostname:     \"%s\" [%zu]\n", buffer, strlen(buffer));

		rc = getaddrinfo(buffer, (char *)0, (struct addrinfo *)0, &list);
		if (rc != 0) {
			fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rc));
			break;
		}

		if (list == (struct addrinfo *)0) {
			break;
		}

		for (ii = 0, here = list; here != (struct addrinfo *)0; ++ii) {

			printf("flags[%d]:      %u\n", ii, here->ai_flags);
			printf("family[%d]:     %u\n", ii, here->ai_family);
			printf("socktype[%d]:   %u\n", ii, here->ai_socktype);
			printf("protocol[%d]:   %u\n", ii, here->ai_protocol);
			printf("addrlen[%d]:    %u\n", ii, here->ai_addrlen);
			if (here->ai_addr != (struct sockaddr *)0) {
				printf("addrfamily[%d]: %u\n", ii, here->ai_addr->sa_family);
				printf("addr[%d]:      ", ii);
				for (jj = 0; (jj < here->ai_addrlen) && (jj < sizeof(here->ai_addr->sa_data)); ++jj) {
					printf(" %u", here->ai_addr->sa_data[jj] & 0xff);
				}
				putchar('\n');
			} else {
				printf("addr[%d]:       %p\n", ii, here->ai_addr);
			}
			if (here->ai_canonname != (char *)0) {
				printf("canonname[%d]:  \"%s\" [%zu]\n", ii, here->ai_canonname, strlen(here->ai_canonname));
			} else {
				printf("canonname[%d]:  %p\n", ii, here->ai_canonname);
			}

			here = here->ai_next;

		}

		freeaddrinfo(list);

		xc = 0;

	} while (0);

	exit(xc);
}
