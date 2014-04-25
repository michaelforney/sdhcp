#include <stdarg.h>

void bpdump(unsigned char *p, int n);

unsigned short
nhgets(unsigned char c[2])
{
	return ((c[0] << 8) + c[1]) & 0xffff;
}

unsigned long
nhgetl(unsigned char c[4])
{
	return (nhgets(c) << 16) + nhgets(c + 2);
}

char *
ipstr(unsigned char *ip)
{
	char * ch = malloc(3 * 4 + 3 + 10);
	sprintf(ch, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
	return ch;
}

#if 0
void
dbgprintf(char *str, ...)
{
	va_list ap;
	va_start(ap, str);
	vfprintf(stderr, str, ap);
	va_end(ap);
}
#endif

void
bpdump(unsigned char *p, int n)
{
	int len, i, code;
	Bootp *bp;
	unsigned char type;
	char *types[] = {
		"discover", "offer", "request",
		"decline", "ack", "nak", "release", "inform"
	};
	/* Udphdr *up; */

	bp = (Bootp*)p;
	/* up = (Udphdr*)bp->udphdr; */

	if(n < bp->magic - p) {
		fprintf(stderr, "dhcpclient: short bootp packet");
		return;
	}

	optget(bp, &type, ODtype, sizeof type);
	fprintf(stderr, "DHCP%s\n", types[type - 1]);
	/* fprintf(stderr, "laddr=%I lport=%d raddr=%I rport=%d\n", up->laddr,
	nhgets(up->lport), up->raddr, nhgets(up->rport)); */
	fprintf(stderr, "op = %d htype = %d hlen = %d hops = %d\n", *bp->op, *bp->htype,
	        *bp->hlen, *bp->hops);
	fprintf(stderr, "xid = %x secs = %d flags = %x\n", nhgetl(bp->xid),
	        nhgets(bp->secs), nhgets(bp->flags));
	fprintf(stderr, "ciaddr = %s, yiaddr = %s, siaddr = %s, giaddr = %s\n",
	        ipstr(bp->ciaddr), ipstr(bp->yiaddr), ipstr(bp->siaddr), ipstr(bp->giaddr));
	fprintf(stderr, "chaddr =");
	for(i=0; i<15; i++)
		fprintf(stderr, "%.2x:", bp->chaddr[i]);
	fprintf(stderr, "%.2x\n", bp->chaddr[15]);
	fprintf(stderr, "sname = %s\n", bp->sname);
	fprintf(stderr, "file = %s\n", bp->file);

	n -= bp->magic - p;
	p = bp->magic;

	if(n < 4)
		return;
	if(memcmp(magic, p, 4) != 0)
		fprintf(stderr, "dhcpclient: bad opt magic %#x %#x %#x %#x\n",
		        p[0], p[1], p[2], p[3]);
	p += 4;
	n -= 4;

	while(n > 0) {
		code = *p++;
		n--;
		if(code == OBpad)
			continue;
		if(code == OBend)
			break;
		if(n == 0) {
			fprintf(stderr, " bad option: %d", code);
			return;
		}
		len = *p++;
		n--;
		if(len > n) {
			fprintf(stderr, " bad option: %d", code);
			return;
		}
		switch(code) {
		case ODtype:
			fprintf(stderr, "DHCP type %d\n", p[0]);
			break;
		case ODclientid:
			fprintf(stderr, "client id=");
			for(i = 0; i<len; i++)
				fprintf(stderr, "%x ", p[i]);
			fprintf(stderr, "\n");
			break;
		case ODlease:
			fprintf(stderr, "lease=%d sec\n", nhgetl(p));
			break;
		case ODserverid:
			fprintf(stderr, "server id=%s\n", ipstr(p));
			break;
		case OBmask:
			fprintf(stderr, "mask=%s\n", ipstr(p));
			break;
		case OBrouter:
			fprintf(stderr, "router=%s\n", ipstr(p));
			break;
		case ODipaddr:
			fprintf(stderr, "ip addr=%s\n", ipstr(p));
			break;
		case OBdnsserver:
			fprintf(stderr, "dns=%s\n", ipstr(p));
			break;
		case OBbaddr:
			fprintf(stderr, "broadcast=%s\n", ipstr(p));
			break;
		case ODrenewaltime:
			fprintf(stderr, "renew time=%d sec\n", nhgetl(p));
			break;
		case ODrebindingtime:
			fprintf(stderr, "rebind time=%d sec\n", nhgetl(p));
			break;
		default:
			fprintf(stderr, "unknown option %d\n", code);
			for(i = 0; i<len; i++)
				fprintf(stderr, "%x ", p[i]);
			fprintf(stderr, "\n");
			break;
		}
		p += len;
		n -= len;
	}
}
