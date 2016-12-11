#include <sys/ioctl.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <net/if.h>
#include <net/route.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "arg.h"
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

enum { Broadcast, Unicast };

Bootp bp;
unsigned char magic[] = { 99, 130, 83, 99 };

/* conf */
static unsigned char xid[sizeof(bp.xid)];
static unsigned char hwaddr[16];
static time_t starttime;
static char *ifname = "eth0";
static unsigned char cid[16];
static char *program = "";
static int sock;
/* sav */
static unsigned char server[4];
static unsigned char client[4];
static unsigned char mask[4];
static unsigned char router[4];
static unsigned char dns[4];
static uint32_t t1;

static int dflag = 1; /* change DNS in /etc/resolv.conf ? */
static int iflag = 1; /* set IP ? */
static int fflag = 0; /* run in foreground */

#define IP(a, b, c, d) (unsigned char[4]){ a, b, c, d }

static void
hnput(unsigned char *dst, uint32_t src, size_t n)
{
	unsigned int i;

	for (i = 0; n--; i++)
		dst[i] = (src >> (n * 8)) & 0xff;
}

static struct sockaddr *
iptoaddr(struct sockaddr *ifaddr, unsigned char ip[4], int port)
{
	struct sockaddr_in *in = (struct sockaddr_in *)ifaddr;

	in->sin_family = AF_INET;
	in->sin_port = htons(port);
	memcpy(&(in->sin_addr), ip, sizeof(in->sin_addr));

	return ifaddr;
}

/* sendto UDP wrapper */
static ssize_t
udpsend(unsigned char ip[4], int fd, void *data, size_t n)
{
	struct sockaddr addr;
	socklen_t addrlen = sizeof(addr);
	ssize_t sent;

	iptoaddr(&addr, ip, 67); /* bootp server */
	if ((sent = sendto(fd, data, n, 0, &addr, addrlen)) == -1)
		eprintf("sendto:");

	return sent;
}

/* recvfrom UDP wrapper */
static ssize_t
udprecv(unsigned char ip[4], int fd, void *data, size_t n)
{
	struct sockaddr addr;
	socklen_t addrlen = sizeof(addr);
	ssize_t r;

	iptoaddr(&addr, ip, 68); /* bootp client */
	if ((r = recvfrom(fd, data, n, 0, &addr, &addrlen)) == -1)
		eprintf("recvfrom:");

	return r;
}

static void
setip(unsigned char ip[4], unsigned char mask[4], unsigned char gateway[4])
{
	struct ifreq ifreq;
	struct rtentry rtreq;
	int fd;

	memset(&ifreq, 0, sizeof(ifreq));
	memset(&rtreq, 0, sizeof(rtreq));

	strlcpy(ifreq.ifr_name, ifname, IF_NAMESIZE);
	iptoaddr(&(ifreq.ifr_addr), ip, 0);
	if ((fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP)) == -1)
		eprintf("can't set ip, socket:");
	ioctl(fd, SIOCSIFADDR, &ifreq);
	iptoaddr(&(ifreq.ifr_netmask), mask, 0);
	ioctl(fd, SIOCSIFNETMASK, &ifreq);
	ifreq.ifr_flags = IFF_UP | IFF_RUNNING | IFF_BROADCAST | IFF_MULTICAST;
	ioctl(fd, SIOCSIFFLAGS, &ifreq);
	/* gw */
	rtreq.rt_flags = (RTF_UP | RTF_GATEWAY);
	iptoaddr(&(rtreq.rt_gateway), gateway, 0);
	iptoaddr(&(rtreq.rt_genmask), IP(0, 0, 0, 0), 0);
	iptoaddr(&(rtreq.rt_dst), IP(0, 0, 0, 0), 0);
	ioctl(fd, SIOCADDRT, &rtreq);

	close(fd);
}

static void
cat(int dfd, char *src)
{
	char buf[BUFSIZ];
	int n, fd;

	if ((fd = open(src, O_RDONLY)) == -1)
		return; /* can't read, but don't error out */
	while ((n = read(fd, buf, sizeof(buf))) > 0)
		write(dfd, buf, n);
	close(fd);
}

static void
setdns(unsigned char dns[4])
{
	char buf[128];
	int fd;

	if ((fd = creat("/etc/resolv.conf", 0644)) == -1) {
		weprintf("can't change /etc/resolv.conf:");
		return;
	}
	cat(fd, "/etc/resolv.conf.head");
	if (snprintf(buf, sizeof(buf) - 1, "\nnameserver %d.%d.%d.%d\n",
	         dns[0], dns[1], dns[2], dns[3]) > 0)
		write(fd, buf, strlen(buf));
	cat(fd, "/etc/resolv.conf.tail");
	close(fd);
}

static void
optget(Bootp *bp, void *data, int opt, int n)
{
	unsigned char *p = bp->optdata;
	unsigned char *top = ((unsigned char *)bp) + sizeof(*bp);
	int code, len;

	while (p < top) {
		code = *p++;
		if (code == OBpad)
			continue;
		if (code == OBend || p == top)
			break;
		len = *p++;
		if (len > top - p)
			break;
		if (code == opt) {
			memcpy(data, p, MIN(len, n));
			break;
		}
		p += len;
	}
}

static unsigned char *
optput(unsigned char *p, int opt, unsigned char *data, size_t len)
{
	*p++ = opt;
	*p++ = (unsigned char)len;
	memcpy(p, data, len);

	return p + len;
}

static unsigned char *
hnoptput(unsigned char *p, int opt, uint32_t data, size_t len)
{
	*p++ = opt;
	*p++ = (unsigned char)len;
	hnput(p, data, len);

	return p + len;
}

static void
dhcpsend(int type, int how)
{
	unsigned char *ip, *p;

	memset(&bp, 0, sizeof(bp));
	hnput(bp.op, Bootrequest, 1);
	hnput(bp.htype, 1, 1);
	hnput(bp.hlen, 6, 1);
	memcpy(bp.xid, xid, sizeof(xid));
	hnput(bp.flags, Fbroadcast, sizeof(bp.flags));
	hnput(bp.secs, time(NULL) - starttime, sizeof(bp.secs));
	memcpy(bp.magic, magic, sizeof(bp.magic));
	memcpy(bp.chaddr, hwaddr, sizeof(bp.chaddr));
	p = bp.optdata;
	p = hnoptput(p, ODtype, type, 1);
	p = optput(p, ODclientid, cid, sizeof(cid));

	switch (type) {
	case DHCPdiscover:
		break;
	case DHCPrequest:
		/* memcpy(bp.ciaddr, client, sizeof bp.ciaddr); */
		p = hnoptput(p, ODlease, t1, sizeof(t1));
		p = optput(p, ODipaddr, client, sizeof(client));
		p = optput(p, ODserverid, server, sizeof(server));
		break;
	case DHCPrelease:
		memcpy(bp.ciaddr, client, sizeof(client));
		p = optput(p, ODipaddr, client, sizeof(client));
		p = optput(p, ODserverid, server, sizeof(server));
		break;
	}
	*p++ = OBend;

	ip = (how == Broadcast) ? IP(255, 255, 255, 255) : server;
	udpsend(ip, sock, &bp, p - (unsigned char *)&bp);
}

static int
dhcprecv(void)
{
	unsigned char type;
	struct pollfd pfd;

	memset(&pfd, 0, sizeof(pfd));
	pfd.fd = sock;
	pfd.events = POLLIN;

	memset(&bp, 0, sizeof(bp));
	if (poll(&pfd, 1, -1) == -1) {
		if (errno != EINTR)
			eprintf("poll:");
		else
			return Timeout;
	}
	udprecv(IP(255, 255, 255, 255), sock, &bp, sizeof(bp));
	optget(&bp, &type, ODtype, sizeof(type));

	return type;
}

static void
acceptlease(void)
{
	char buf[128];

	if (iflag)
		setip(client, mask, router);
	if (dflag)
		setdns(dns);
	if (*program) {
		snprintf(buf, sizeof(buf), "%d.%d.%d.%d", server[0], server[1], server[2], server[3]);
		setenv("SERVER", buf, 1);
		snprintf(buf, sizeof(buf), "%d.%d.%d.%d", client[0], client[1], client[2], client[3]);
		setenv("CLIENT", buf, 1);
		snprintf(buf, sizeof(buf), "%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3]);
		setenv("MASK", buf, 1);
		snprintf(buf, sizeof(buf), "%d.%d.%d.%d", router[0], router[1], router[2], router[3]);
		setenv("ROUTER", buf, 1);
		snprintf(buf, sizeof(buf), "%d.%d.%d.%d", dns[0], dns[1], dns[2], dns[3]);
		setenv("DNS", buf, 1);
		system(program);
	}
	alarm(t1);
}

static void
run(void)
{
	int forked = 0;

Init:
	dhcpsend(DHCPdiscover, Broadcast);
	alarm(1);
	goto Selecting;
Selecting:
	switch (dhcprecv()) {
	case DHCPoffer:
		alarm(0);
		memcpy(client, bp.yiaddr, sizeof(client));
		optget(&bp, server, ODserverid, sizeof(server));
		optget(&bp, mask, OBmask, sizeof(mask));
		optget(&bp, router, OBrouter, sizeof(router));
		optget(&bp, dns, OBdnsserver, sizeof(dns));
		optget(&bp, &t1, ODlease, sizeof(t1));
		t1 = ntohl(t1);
		dhcpsend(DHCPrequest, Broadcast);
		goto Requesting;
	case Timeout:
		goto Init;
	default:
		goto Selecting;
	}
Requesting:
	switch (dhcprecv()) {
	case DHCPoffer:
		goto Requesting; /* ignore other offers. */
	case DHCPack:
		acceptlease();
		goto Bound;
	}
Bound:
	fputs("Congrats! You should be on the 'net.\n", stdout);
	if (!fflag && !forked) {
		if (fork())
			exit(0);
		forked = 1;
	}
	switch (dhcprecv()) {
	case DHCPoffer:
	case DHCPack:
	case DHCPnak:
		goto Bound; /* discard offer, ACK or NAK */
	case Timeout:
		dhcpsend(DHCPrequest, Unicast);
		goto Renewing;
	}
Renewing:
	switch (dhcprecv()) {
	case DHCPack:
		acceptlease();
		goto Bound;
	case DHCPnak:
		goto Init;
	case Timeout:
		dhcpsend(DHCPrequest, Broadcast);
		goto Rebinding;
	}
Rebinding:
	switch (dhcprecv()) {
	case DHCPnak: /* lease expired */
		goto Init;
	case DHCPack:
		acceptlease();
		goto Bound;
	}
}

static void
nop(int unused)
{
	(void)unused;
}

static void
cleanexit(int unused)
{
	(void)unused;
	dhcpsend(DHCPrelease, Unicast);
	_exit(0);
}

static void
usage(void)
{
	eprintf("usage: %s [-d] [-e program] [-f] [-i] [ifname] [clientid]\n", argv0);
}

int
main(int argc, char *argv[])
{
	int bcast = 1;
	struct ifreq ifreq;
	struct sockaddr addr;
	int rnd;

	ARGBEGIN {
	case 'd': /* don't update DNS in /etc/resolv.conf */
		dflag = 0;
		break;
	case 'e': /* run program */
		program = EARGF(usage());
		break;
	case 'f': /* run in foreground */
		fflag = 1;
		break;
	case 'i': /* don't set ip */
		iflag = 0;
		break;
	default:
		usage();
		break;
	} ARGEND;

	if (argc)
		ifname = argv[0]; /* interface name */
	if (argc >= 2)
		strlcpy((char *)cid, argv[1], sizeof(cid)); /* client-id */

	memset(&ifreq, 0, sizeof(ifreq));
	signal(SIGALRM, nop);
	signal(SIGTERM, cleanexit);

	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		eprintf("socket:");
	if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &bcast, sizeof(bcast)) == -1)
		eprintf("setsockopt:");

	strlcpy(ifreq.ifr_name, ifname, IF_NAMESIZE);
	ioctl(sock, SIOCGIFINDEX, &ifreq);
	if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, &ifreq, sizeof(ifreq)) == -1)
		eprintf("setsockopt:");
	iptoaddr(&addr, IP(255, 255, 255, 255), 68);
	if (bind(sock, (void*)&addr, sizeof(addr)) != 0)
		eprintf("bind:");
	ioctl(sock, SIOCGIFHWADDR, &ifreq);
	memcpy(hwaddr, ifreq.ifr_hwaddr.sa_data, sizeof(ifreq.ifr_hwaddr.sa_data));
	if (!cid[0])
		memcpy(cid, hwaddr, sizeof(cid));

	if ((rnd = open("/dev/urandom", O_RDONLY)) == -1)
		eprintf("can't open /dev/urandom to generate unique transaction identifier:");
	read(rnd, xid, sizeof(xid));
	close(rnd);

	starttime = time(NULL);
	run();

	return 0;
}
