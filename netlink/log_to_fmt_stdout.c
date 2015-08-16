/*
 * (c) 2008-2011 Daniel Halperin <dhalperi@cs.washington.edu>
 * updated by Zdenek Chaloupka for feedgnuplot or similar
 */
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/socket.h>
#include <linux/netlink.h>
#include <linux/connector.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <stdarg.h>
#include <math.h>

//#pragma GCC diagnostic ignored "W-unused-but-set-parameter"

#define MAX_PAYLOAD 2048
#define SLOW_MSG_CNT 1

int sock_fd = -1;							// the socket
FILE* out = NULL;

void check_usage(int argc, char** argv);

FILE* open_file(char* filename, char* spec);

void caught_signal(int sig);

void exit_program(int code);
void exit_program_err(int code, char* func);

void printDataToStdout(void *data);
void printToStdout(char *msg, ...);

int main(int argc, char** argv)
{
	/* Local variables */
	struct sockaddr_nl proc_addr, kern_addr;	// addrs for recv, send, bind
	struct cn_msg *cmsg;
	char buf[4096];
	int ret;
	int count = 0;

	/* Make sure usage is correct */
	//check_usage(argc, argv);


	/* Setup the socket */
	sock_fd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
	if (sock_fd == -1)
		exit_program_err(-1, "socket");

	/* Initialize the address structs */
	memset(&proc_addr, 0, sizeof(struct sockaddr_nl));
	proc_addr.nl_family = AF_NETLINK;
	proc_addr.nl_pid = getpid();			// this process' PID
	proc_addr.nl_groups = CN_IDX_IWLAGN;
	memset(&kern_addr, 0, sizeof(struct sockaddr_nl));
	kern_addr.nl_family = AF_NETLINK;
	kern_addr.nl_pid = 0;					// kernel
	kern_addr.nl_groups = CN_IDX_IWLAGN;

	/* Now bind the socket */
	if (bind(sock_fd, (struct sockaddr *)&proc_addr, sizeof(struct sockaddr_nl)) == -1)
		exit_program_err(-1, "bind");

	/* And subscribe to netlink group */
	{
		int on = proc_addr.nl_groups;
		ret = setsockopt(sock_fd, 270, NETLINK_ADD_MEMBERSHIP, &on, sizeof(on));
		if (ret)
			exit_program_err(-1, "setsockopt");
	}

	/* Set up the "caught_signal" function as this program's sig handler */
	signal(SIGINT, caught_signal);

	/* Poll socket forever waiting for a message */
	while (1)
	{
		/* Receive from socket with infinite timeout */
		ret = recv(sock_fd, buf, sizeof(buf), 0);
		if (ret == -1)
			exit_program_err(-1, "recv");
		
		/* Pull out the message portion and print some stats */
		cmsg = NLMSG_DATA(buf);
		if (count % SLOW_MSG_CNT == 0)
			printf("## received %d bytes: id: %d val: %d seq: %d clen: %d\n", ret, cmsg->id.idx, cmsg->id.val, cmsg->seq, cmsg->len);
		
		/* Log the data to stdout */
		printDataToStdout((void *)(cmsg->data));
		++count;
	}

	exit_program(0);
	return 0;
}


void printDataToStdout(void *data)
{
	unsigned short code;
	unsigned char *inBytes = ((char *)data)+1;
	
	unsigned long timestamp_low;
	unsigned int Nrx, Ntx, rssi_a, rssi_b, rssi_c, agc, antenna_sel,
		len, fake_rate_n_flags, calc_len, i, j, index = 0, remainder, ret;
	unsigned short bfee_count;
	unsigned char *payload;
	char tmpR, tmpI, noise, buffer[1024], *tmp;
	double absVal;
	
	code = *((unsigned char *)data);
	
	if (code != 187) //not a beamforming data, so ignore
		return;
		
	timestamp_low = inBytes[0] + (inBytes[1] << 8) +
		(inBytes[2] << 16) + (inBytes[3] << 24);
	bfee_count = inBytes[4] + (inBytes[5] << 8);
	Nrx = inBytes[8];
	Ntx = inBytes[9];
	rssi_a = inBytes[10];
	rssi_b = inBytes[11];
	rssi_c = inBytes[12];
	noise = inBytes[13];
	agc = inBytes[14];
	antenna_sel = inBytes[15];
	len = inBytes[16] + (inBytes[17] << 8);
	fake_rate_n_flags = inBytes[18] + (inBytes[19] << 8);
	calc_len = (30 * (Nrx * Ntx * 8 * 2 + 3) + 7) / 8;
	
	payload = (unsigned char *)(inBytes+20);
	//int size[] = {Ntx, Nrx, 30};

	/* Check that length matches what it should */
	if (len != calc_len)
		exit_program_err(-1, "MIMOToolbox:read_bfee_new:size, Wrong beamforming matrix size.");

	/* Compute CSI from all this crap :) */
	printf("clear\n");
	for (i = 0; i < 30; ++i)
	{
		index += 3;
		remainder = index % 8;
		//printf("%d", i);
		ret = sprintf(buffer, "%d", i);
		tmp = buffer + ret;
		for (j = 0; j < Nrx * Ntx; ++j)
		{
			//printf("\t");
			ret = sprintf(tmp, "\t");
			tmp += ret;
			tmpR = (payload[index / 8] >> remainder) |
				(payload[index/8+1] << (8-remainder));
			
			//printf("%d\t", tmp);
			tmpI = (payload[index / 8+1] >> remainder) |
				(payload[index/8+2] << (8-remainder));
			
			absVal = sqrt(((float)tmpR)*((float)tmpR) + ((float)tmpI)*((float)tmpI));
			
			//printf("%e", absVal);
			ret = sprintf(tmp, "%e", absVal);
			tmp += ret;
			
			index += 16;
		}
		*tmp = 0;
		printf("%s\n", buffer);
	}
	printf("replot\n");

	/* Compute the permutation array */
	//ptrR[0] = ((antenna_sel) & 0x3) + 1;
	//ptrR[1] = ((antenna_sel >> 2) & 0x3) + 1;
	//ptrR[2] = ((antenna_sel >> 4) & 0x3) + 1;
}

void check_usage(int argc, char** argv)
{
	if (argc != 2)
	{
		fprintf(stderr, "Usage: log_to_file <output_file>\n");
		exit_program(1);
	}
}

FILE* open_file(char* filename, char* spec)
{
	FILE* fp = fopen(filename, spec);
	if (!fp)
	{
		perror("fopen");
		exit_program(1);
	}
	return fp;
}

void caught_signal(int sig)
{
	fprintf(stderr, "Caught signal %d\n", sig);
	exit_program(0);
}

void exit_program(int code)
{
	if (out)
	{
		fclose(out);
		out = NULL;
	}
	if (sock_fd != -1)
	{
		close(sock_fd);
		sock_fd = -1;
	}
	exit(code);
}

void exit_program_err(int code, char* func)
{
	perror(func);
	exit_program(code);
}

void printToStdout(char *msg, ...)
{
	va_list args;
    va_start(args, msg);
    printf("## ");
    printf(msg, args);
    va_end(args);
}
