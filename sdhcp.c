#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <net/route.h>
#include <signal.h>
#include <poll.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "util.h"

typedef struct bootp {
	unsigned char op      [1];
	unsigned char htype   [1];
	unsigned char hlen    [1];
	unsigned char hops    [1];
	unsigned char xid     [4];
	unsigned char secs    [2];
	unsigned char flags   [2];
	unsigned char ciaddr  [4];
	unsigned char yiaddr  [4];
	unsigned char siaddr  [4];
	unsigned char giaddr  [4];
	unsigned char chaddr  [16];
	unsigned char sname   [64];
	unsigned char file    [128];
	unsigned char magic   [4];
	unsigned char optdata [312-4];
} Bootp;

enum {
	DHCPdiscover =       1,
	DHCPoffer,
	DHCPrequest,
	DHCPdecline,
	DHCPack,
	DHCPnak,
	DHCPrelease,
	DHCPinform,
	Timeout =          200,

	Bootrequest =        1,
	Bootreply =          2,
	/* bootp flags */
	Fbroadcast =   1 << 15,

	OBpad =              0,
	OBmask =             1,
	OBrouter =           3,
	OBnameserver =       5,
	OBdnsserver =        6,
	OBbaddr =           28,
	ODipaddr =          50, /* 0x32 */
	ODlease =           51,
	ODoverload =        52,
	ODtype =            53, /* 0x35 */
	ODserverid =        54, /* 0x36 */
	ODparams =          55, /* 0x37 */
	ODmessage =         56,
	ODmaxmsg =          57,
	ODrenewaltime =     58,
	ODrebindingtime =   59,
	ODvendorclass =     60,
	ODclientid =        61, /* 0x3d */
	ODtftpserver =      66,
	ODbootfile =        67,
	OBend =            255,
};

enum { Broadcast, Unicast};

Bootp bp;
unsigned char magic[] = {99, 130, 83, 99};

/* conf */
static unsigned char xid[sizeof bp.xid];
static unsigned char hwaddr[16];
static time_t starttime;
static char *ifname = "eth0";
static char *cid = "vaio.12340";
static int sock;
/* sav */
static unsigned char server[4];
static unsigned char client[4];
static unsigned char mask[4];
static unsigned char router[4];
static unsigned char dns[4];
static unsigned long t1;

#define IP(...) (unsigned char[4]){__VA_ARGS__}

static void
die(char *str)
{
	perror(str);
	exit(EXIT_FAILURE);
}

static void
hnput(unsigned char *dst, unsigned long long src, int n)
{
	int i;

	for(i = 0; n--; i++) /* TODO: --n ? */
		dst[i] = (src >> (n * 8)) & 0xff;
}

static struct sockaddr
iptoaddr(unsigned char ip[4], int port)
{
	struct sockaddr_in ifaddr;

	ifaddr.sin_family = AF_INET;
	ifaddr.sin_port = htons(port);
	memcpy(&ifaddr.sin_addr, ip, sizeof ifaddr.sin_addr);
	return *(struct sockaddr*)&ifaddr;
}

#define UDPWRAPPER(name, func, port, hack) \
static int name(unsigned char ip[4], int fd, void *data, size_t n){\
	struct sockaddr addr = iptoaddr(ip, port);\
	int x, y = sizeof addr;\
	if((x=func(fd, data, n, 0, &addr, hack y))==-1)\
		die(#func);\
	return x;\
}
UDPWRAPPER(udpsend, sendto, 67, )
UDPWRAPPER(udprecv, recvfrom, 68, &)

static void
setip(unsigned char ip[4], unsigned char mask[4], unsigned char gateway[4])
{
	int fd, x;
	struct ifreq ifreq = {0,};
	struct rtentry rtreq = {0,};

	fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	strcpy(ifreq.ifr_name, ifname); /*TODO: strlcpy */
	ifreq.ifr_addr = iptoaddr(ip, 0);
	ioctl(fd, SIOCSIFADDR , &ifreq);
	ifreq.ifr_netmask = iptoaddr(mask, 0);
	ioctl(fd, SIOCSIFNETMASK , &ifreq);
	ifreq.ifr_flags = IFF_UP|IFF_RUNNING|IFF_BROADCAST|IFF_MULTICAST;
	ioctl(fd, SIOCSIFFLAGS , &ifreq);

	rtreq.rt_flags = (RTF_UP | RTF_GATEWAY);
	rtreq.rt_gateway = iptoaddr(gateway, 0);
	rtreq.rt_genmask = iptoaddr(IP(0,0,0,0), 0);
	rtreq.rt_dst = iptoaddr(IP(0,0,0,0), 0);
	ioctl(fd, SIOCADDRT , &rtreq);

	close(fd);
}

static void
cat(int dfd, char *src)
{
	char buf[4096]; /* TODO: use BUFSIZ ? */
	int n, sfd = open(src, O_RDONLY);

	while((n = read(sfd, buf, sizeof buf))>0)
		write(dfd, buf, n);
	close(sfd);

}

/* use itoa not sprintf to make dietlibc happy. */
/* TODO: use snprintf(), fuck dietlibc */
char *
itoa(char * str, int x)
{
	int k = 1;
	char *ep = str;

	if(x == 0) {
		*str='0';
		return str+1;
	}
	while(x / k > 0)
		k *= 10;
	while((k /= 10) >= 1)
		*ep++ = '0' + ((x / k) % 10);
	*ep = '\0';
	return str + strlen(str);
}

static void
setdns(unsigned char dns[4])
{
	char buf[128], *bp = buf;
	int fd = creat("/etc/resolv.conf", 0644);

	cat(fd, "/etc/resolv.conf.head");
	memcpy(buf, "\nnameserver ", 12), bp+=11;
	*(bp = itoa(bp+1, dns[0])) = '.';
	*(bp = itoa(bp+1, dns[1])) = '.';
	*(bp = itoa(bp+1, dns[2])) = '.';
	*(bp = itoa(bp+1, dns[3])) = '\n';
	*++bp = '\0';
	write(fd, buf, strlen(buf));
	cat(fd, "/etc/resolv.conf.tail");
	close(fd);
}

static unsigned char *
optget(Bootp *bp, void *data, int opt, int n)
{
	unsigned char *p = bp->optdata;
	unsigned char *top = ((unsigned char *)bp) + sizeof *bp;
	int code;
	int len;

	while(p < top) {
		code = *p++;
		if(code == OBpad)
			continue;
		if(code == OBend || p == top)
			break;
		len = *p++;
		if(len > top-p)
			break;
		if(code == opt) {
			memcpy(data, p, MIN(len, n));
			return p;
		}
		p += len;
	}
}

static unsigned char *
optput(unsigned char *p, int opt, unsigned char *data, int len)
{
	*p++ = opt;
	*p++ = (unsigned char)len;
	memcpy(p, data, len);
	return p + len;
}

static unsigned char *
hnoptput(unsigned char *p, int opt, long long data, int len)
{
	*p++ = opt;
	*p++ = (unsigned char)len;
	hnput(p, data, len);
	return p+len;
}

static void
dhcpsend(int type, int how)
{
	unsigned char *ip;
	unsigned char *p;

	memset(&bp, 0, sizeof bp);
	hnput(bp.op, Bootrequest, 1);
	hnput(bp.htype, 1, 1);
	hnput(bp.hlen, 6, 1);
	memcpy(bp.xid, xid, sizeof xid);
	hnput(bp.flags, Fbroadcast, sizeof bp.flags);
	hnput(bp.secs, time(NULL)-starttime, sizeof bp.secs);
	memcpy(bp.magic, magic, sizeof bp.magic);
	memcpy(bp.chaddr, hwaddr, sizeof bp.chaddr);
	p = bp.optdata;
	p = hnoptput(p, ODtype, type, 1);
	p = optput(p, ODclientid, cid, strlen(cid));

	switch(type) {
	case DHCPdiscover:
		break;
	case DHCPrequest:
		/* memcpy(bp.ciaddr, client, sizeof bp.ciaddr); */
		p = hnoptput(p, ODlease, t1, sizeof t1);
		p = optput(p, ODipaddr, client, sizeof client);
		p = optput(p, ODserverid, server, sizeof server);
		break;
	case DHCPrelease:
		memcpy(bp.ciaddr, client, sizeof client);
		p = optput(p, ODipaddr, client, sizeof client);
		p = optput(p, ODserverid, server, sizeof server);
		break;
	}
	*p++ = OBend;
	/* debug */
	/*bpdump((void*)&bp, p - (unsigned char *)&bp);*/

	ip = (how == Broadcast) ? IP(255,255,255,255) : server;
	udpsend(ip, sock, &bp, p - (unsigned char *)&bp);
}

static int
dhcprecv(void)
{
	unsigned char type;
	int x;

	memset(&bp, 0, sizeof bp);
	struct pollfd pfd = {sock, POLLIN}; /* TODO: not inline */
	if(poll(&pfd, 1, -1) == -1) {
		if(errno != EINTR)
			die("poll");
		else 
			return Timeout;
	}
	x = udprecv(IP(255,255,255,255), sock, &bp, sizeof bp);
	/* debug */
	/* bpdump((void*)&bp, x);*/
	optget(&bp, &type, ODtype, sizeof type);
	return type;
}

static void
acceptlease(void)
{
	setip(client, mask, router);
	setdns(dns);
	alarm(t1);
}

static void
run(void)
{
#if 0
InitReboot:
	/* send DHCPrequest to old server */
	dhcpsend(DHCPrequest, Broadcasr);
	goto Rebooting;
Rebooting:
	switch (dhcprecv()) {
	case DHCPnak:
		goto Init;
	case DHCPack:
		acceptoffer();
		goto Bound;
	}
#endif
Init:
	dhcpsend(DHCPdiscover, Broadcast);
	alarm(1);
	goto Selecting;
Selecting:
	switch(dhcprecv()) {
	case DHCPoffer:
		alarm(0);
		memcpy(client, bp.yiaddr, sizeof client);
		optget(&bp, server, ODserverid, sizeof server);
		optget(&bp, mask, OBmask, sizeof mask);
		optget(&bp, router, OBrouter, sizeof router);
		optget(&bp, dns, OBdnsserver, sizeof dns);
		optget(&bp, &t1, ODlease, sizeof t1);
		t1 = ntohl(t1);
		dhcpsend(DHCPrequest, Broadcast);
		goto Requesting;
	case Timeout:
		goto Init;
	default:
		goto Selecting;
	}
Requesting:
	switch(dhcprecv()) {
	case DHCPoffer:
		goto Requesting; /* ignore other offers. */
#if 0
	case DHCPack: /* (and you don't want it) ? */
		dhcpsend(DHCPdecline, Unicast);
		goto Init;
#endif
	case DHCPack:
		acceptlease();
		goto Bound;
	}
Bound:
	fputs("Congrats! You should be on the 'net.\n", stdout);
	if(fork())
		exit(EXIT_SUCCESS);
	switch (dhcprecv()) {
	case DHCPoffer:
	case DHCPack:
	case DHCPnak:
		goto Bound; /* discard offer, ack, or nak */
	case Timeout:
		dhcpsend(DHCPrequest, Unicast);
		goto Renewing;
	}
Renewing:
	switch(dhcprecv()) {
	case DHCPack:
		acceptlease();
		goto Bound;
	case DHCPnak:
		/* halt network; */
		goto Init;
	case Timeout: /* t2 expires: */
		dhcpsend(DHCPrequest, Broadcast);
		goto Rebinding;
	}
Rebinding:
	switch(dhcprecv()) {
	case DHCPnak: /* lease expired */
		/* halt network; */
		goto Init;
	case DHCPack:
		acceptlease();
		goto Bound;
	}
}

static void nop(int unused) {
}

static void cleanexit(int unused) {
	dhcpsend(DHCPrelease, Unicast);
	exit(EXIT_SUCCESS);
}

static void
usage(void) {
	fputs("usage: sdhcp [interface]\n", stderr);
	exit(EXIT_FAILURE);
}

int
main(int argc, char *argv[])
{
	int bcast = 1;
	struct ifreq ifreq = {0,};
	struct sockaddr addr;
	int rnd;

	if(argc > 2)
		usage();
	else if(argc == 2)
		ifname = argv[1];

	signal(SIGALRM, nop);
	signal(SIGTERM, cleanexit);

	if((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		die("socket");
	if(setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &bcast, sizeof bcast) == -1)
		die("setsockopt");

	strcpy(ifreq.ifr_name, ifname); /* TODO: strlcpy */
	ioctl(sock, SIOCGIFINDEX, &ifreq);
	if(setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, &ifreq, sizeof ifreq) == -1)
		die("setsockopt");
	addr = iptoaddr(IP(255,255,255,255), 68);
	if(bind(sock, (void*)&addr, sizeof addr)!=0)
		die("bind");
	ioctl(sock, SIOCGIFHWADDR, &ifreq);
	memcpy(hwaddr, ifreq.ifr_hwaddr.sa_data, sizeof ifreq.ifr_hwaddr.sa_data);
	rnd = open("/dev/urandom", O_RDONLY);
	read(rnd, xid, sizeof xid);
	close(rnd);

	starttime = time(NULL);
	run();
	return EXIT_SUCCESS;
}
