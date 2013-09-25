#include<sys/socket.h>
#include<sys/ioctl.h>
#include<netinet/in.h>
#include<net/if.h>
#include<net/route.h>
#include<signal.h>
#include<sys/poll.h>
#include<errno.h>
#include<fcntl.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>

#define MIN(a,b) (((a)<(b))?(a):(b))

typedef unsigned char uchar;
typedef struct Bootp Bootp;
struct Bootp {
	uchar op      [1];
	uchar htype   [1];
	uchar hlen    [1];
	uchar hops    [1];
	uchar xid     [4];
	uchar secs    [2];
	uchar flags   [2];
	uchar ciaddr  [4];
	uchar yiaddr  [4];
	uchar siaddr  [4];
	uchar giaddr  [4];
	uchar chaddr  [16];
	uchar sname   [64];
	uchar file    [128];
	uchar magic   [4];
	uchar optdata [312-4];
};

void bpdump(uchar *p, int n);
enum {  
	DHCPdiscover = 1,  DHCPoffer, DHCPrequest,
	DHCPdecline, DHCPack, DHCPnak, DHCPrelease, 
	DHCPinform, Timeout=200,

	Bootrequest=   1,
	Bootreply=     2,
	/* bootp flags */
	Fbroadcast=    1<<15,

	OBpad=			0,
	OBmask=			1,
	OBrouter=           3,
	OBnameserver=       5,
	OBdnsserver=        6,
	OBbaddr=            28,
	ODipaddr=           50,  /* 0x32 */
	ODlease=            51,
	ODoverload=         52,
	ODtype=             53,  /* 0x35 */
	ODserverid=         54,  /* 0x36 */
	ODparams=           55,  /* 0x37 */
	ODmessage=          56,
	ODmaxmsg=           57,
	ODrenewaltime=      58,
	ODrebindingtime=    59,
	ODvendorclass=      60,
	ODclientid=         61,  /* 0x3d */
	ODtftpserver=       66,
	ODbootfile=         67,
	OBend=              255,
};

enum{ Broadcast, Unicast};

Bootp bp;
uchar magic[] = {99, 130, 83, 99};

//struct conf{
	uchar xid[sizeof bp.xid];
	uchar hwaddr[16];
	time_t starttime;
	char *ifname = "eth0";
	char *cid = "vaio.12340";
	int sock;
//} var;
//struct sav{
	uchar server[4];
	uchar client[4];
	uchar mask[4];
	uchar router[4];
	uchar dns[4];
	unsigned long t1;
	unsigned long t2;
//} sav;

#define IP(...) (uchar[4]){__VA_ARGS__}

static void
die(char *str)
{
	perror(str);
	exit(EXIT_FAILURE);
}

static void
hnput(uchar *dst, unsigned long long src, int n)
{
	int x;
	for(x=0; n--; x++)
		dst[x] = (src>>(n*8))&0xff;
}

static struct sockaddr
iptoaddr(uchar ip[4], int port)
{
	struct sockaddr_in ifaddr;
	ifaddr.sin_family=AF_INET;
	ifaddr.sin_port = htons(port);
	memcpy(&ifaddr.sin_addr, ip, sizeof ifaddr.sin_addr);
	return *(struct sockaddr*)&ifaddr;
}

#define UDPWRAPPER(name, func, port, hack) \
static int name(uchar ip[4], int fd, void *data, size_t n){\
	struct sockaddr addr = iptoaddr(ip, port);\
	int x, y = sizeof addr;\
	if((x=func(fd, data, n, 0, &addr, hack y))==-1)\
		die(#func);\
	return x;\
}
UDPWRAPPER(udpsend, sendto, 67, )
UDPWRAPPER(udprecv, recvfrom, 68, &)

static void
setip(uchar ip[4], uchar mask[4], uchar gateway[4])
{
	int fd, x;
	struct ifreq ifreq = {0,};
	struct rtentry rtreq = {0,};

	fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	strcpy(ifreq.ifr_name, ifname);
	ifreq.ifr_addr = iptoaddr(ip, 0);
	ioctl(fd, SIOCSIFADDR , &ifreq);
	ifreq.ifr_netmask = iptoaddr(mask, 0);
	ioctl(fd, SIOCSIFNETMASK , &ifreq);
	ifreq.ifr_flags=IFF_UP|IFF_RUNNING|IFF_BROADCAST|IFF_MULTICAST;
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
	char buf[4096];
	int n, sfd = open(src, O_RDONLY);
	while((n=read(sfd, buf, sizeof buf))>0)
		write(dfd, buf, n);
	close(sfd);

}
//use itoa not sprintf to make dietlibc happy.
char* itoa(char * str, int x) 
{
	if(x==0){
		*str='0';
		return str+1;
	}
     int k = 1;
     char *ep = str;
     while(x/k >  0)
          k*=10;
     while((k/=10)>=1)
          *ep++ = '0'+((x/k)%10);
     *ep = '\0';
     return str+strlen(str);
}
static void
setdns(uchar dns[4])
{
	char buf[128], *bp = buf;
	int fd = creat("/etc/resolv.conf", 0644);
	cat(fd, "/etc/resolv.conf.head");
	memcpy(buf, "\nnameserver ", 12), bp+=11;
	*(bp=itoa(bp+1, dns[0])) = '.';
	*(bp=itoa(bp+1, dns[1])) = '.';
	*(bp=itoa(bp+1, dns[2])) = '.';
	*(bp=itoa(bp+1, dns[3])) = '\n';
	*++bp = '\0';
	write(fd, buf, strlen(buf));
	cat(fd, "/etc/resolv.conf.tail");
	close(fd);
}

static uchar *
optget(Bootp *bp, void *data, int opt, int n)
{
	uchar *p = bp->optdata;
	uchar *top = ((uchar*)bp)+sizeof *bp;
	while(p<top){
		int code = *p++;
		if(code==OBpad)
			continue;
		if(code==OBend || p==top)
			break;
		int len = *p++;
		if(len > top-p)
			break;
		if(code==opt){
			memcpy(data, p, MIN(len, n));
			return p;
		}
		p+=len;
	}
}

static uchar *
optput(uchar *p, int opt, uchar *data, int len)
{
	*p++ = opt;
	*p++ = (uchar)len;
	memcpy(p, data, len);
	return p+len;
}
static uchar*
hnoptput(uchar *p, int opt, long long data, int len)
{
	*p++=opt;
	*p++ = (uchar)len;
	hnput(p, data, len);
	return p+len;
}
#include "debug.c"

static void
dhcpsend(int type, int how)
{
	dbgprintf("\nSending ");
	memset(&bp, 0, sizeof bp);
	hnput(bp.op, Bootrequest, 1);
	hnput(bp.htype, 1, 1);
	hnput(bp.hlen, 6, 1);
	memcpy(bp.xid, xid, sizeof xid);
	hnput(bp.flags, Fbroadcast, sizeof bp.flags);
	hnput(bp.secs, time(NULL)-starttime, sizeof bp.secs);
	memcpy(bp.magic, magic, sizeof bp.magic);
	memcpy(bp.chaddr, hwaddr, sizeof bp.chaddr);
	uchar *p = bp.optdata;
	p = hnoptput(p, ODtype, type, 1);
	p = optput(p, ODclientid, cid, strlen(cid));

	switch(type){
	case DHCPdiscover:
		break;
	case DHCPrequest:
//		memcpy(bp.ciaddr, client, sizeof bp.ciaddr);
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
	*p++=OBend;
	bpdump((void*)&bp, p-(uchar*)&bp);
	uchar *ip = (how==Broadcast)?IP(255,255,255,255):server;
	udpsend(ip, sock, &bp, p-(uchar*)&bp);
}

static int
dhcprecv()
{
	dbgprintf("\nReceiving ");
	memset(&bp, 0, sizeof bp);
	struct pollfd pfd = {sock, POLLIN};
	if(poll(&pfd, 1, -1)==-1){
		if(errno!=EINTR)
			die("poll");
		else 
			return Timeout;
	}
	int x = udprecv(IP(255,255,255,255), sock, &bp, sizeof bp);
	bpdump((void*)&bp, x);
	uchar type;	
	optget(&bp, &type, ODtype, sizeof type);
	return type;
}

static void
acceptlease()
{
	setip(client, mask, router);
	setdns(dns);
	alarm(t1);
}

static void
run()
{
#if 0
InitReboot:
	//send DHCPrequest to old server
	dhcpsend(DHCPrequest, Broadcasr);
	goto Rebooting;
Rebooting:
	switch (dhcprecv()){
	case DHCPnak:
		goto Init;
	case DHCPack:
		acceptoffer();
		goto Bound;	
	}
#endif
Init:
	dbgprintf("\n\n------- Init ------\n");
	dhcpsend(DHCPdiscover, Broadcast);
	alarm(1);
	goto Selecting;
Selecting:
	dbgprintf("\n\n------- Selecting ------\n");
	switch(dhcprecv()){
	case DHCPoffer:
		alarm(0);
		memcpy(client, bp.yiaddr, sizeof client);
		optget(&bp, server, ODserverid, sizeof server);
		optget(&bp,  mask, OBmask, sizeof mask);
		optget(&bp,  router, OBrouter, sizeof router);
		optget(&bp,  dns, OBdnsserver, sizeof dns);
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
	dbgprintf("\n\n------- Requesting ------\n");
	switch(dhcprecv()){
	case DHCPoffer:
		goto Requesting; //ignore other offers.
//	case DHCPack: //(and you don't want it)?
//		dhcpsend(DHCPdecline, Unicast);
//		goto Init;
	case DHCPack:
		acceptlease();
		goto Bound;
	}
Bound:
	dbgprintf("\n\n------- Bound ------\n");
	write(1, "Congrats! You should be on the 'net.\n", 37);
	if(fork())
		exit(0);
	switch (dhcprecv()){
	case DHCPoffer:
	case DHCPack:
	case DHCPnak:
		goto Bound; //discard offer, ack, or nak
	case Timeout:
		dhcpsend(DHCPrequest, Unicast);
		goto Renewing;	
	}
Renewing:
	dbgprintf("\n\n------- Renewing ------\n");
	switch(dhcprecv()){
	case DHCPack:
		acceptlease();
		goto Bound;
	case DHCPnak:
		//halt network;
		goto Init;
	case Timeout: //t2 expires:
		dhcpsend(DHCPrequest, Broadcast);
		goto Rebinding;
	}
Rebinding:
	dbgprintf("\n\n------- Rebinding ------\n");
	switch(dhcprecv()){
	case DHCPnak: //lease expired
		//halt network;
		goto Init;
	case DHCPack:
		acceptlease();
		goto Bound;
	}
}

static void nop(int unused){ }
static void cleanexit(int unused){ 
	dhcpsend(DHCPrelease, Unicast);
	exit(0);
}

int
main(int argc, char *argv[])
{
	if(argc>2){
		write(2, "usage: sdhcp [inferface]\n",25);
		exit(EXIT_FAILURE);
	}if(argc==2)
		ifname = argv[1];

	signal(SIGALRM, nop);
	signal(SIGTERM, cleanexit);

	if((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		die("socket");
	int bcast = 1;
	if(setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &bcast, sizeof bcast)==-1)
		die("setsockopt");
	struct ifreq ifreq = {0,};
	strcpy(ifreq.ifr_name, ifname);
	ioctl(sock, SIOCGIFINDEX, &ifreq);
	if(setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, &ifreq, sizeof ifreq)==-1)
		die("setsockopt");
	struct sockaddr addr = iptoaddr(IP(255,255,255,255), 68);
	if(bind(sock, (void*)&addr, sizeof addr)!=0)
		die("bind");
	ioctl(sock, SIOCGIFHWADDR, &ifreq);
	memcpy(hwaddr, ifreq.ifr_hwaddr.sa_data, sizeof ifreq.ifr_hwaddr.sa_data);
	int rnd = open("/dev/urandom", O_RDONLY);
	read(rnd, xid, sizeof xid);
	close(rnd);

	starttime = time(NULL);	
	run();
	return 0;
}

