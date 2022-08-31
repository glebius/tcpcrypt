#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <unistd.h>

#include "tcpcrypt_divert.h"
#include "tcpcryptd.h"

static int	  _s;
static divert_cb _cb;

static int bsd_open(int port, divert_cb cb)
{
	struct sockaddr_in s_in;

	memset(&s_in, 0, sizeof(s_in));

	s_in.sin_family = PF_INET;
	s_in.sin_port   = htons(port);

#ifdef PF_DIVERT
	if ((_s = socket(PF_DIVERT, SOCK_RAW, 0)) == -1)
#else
	if ((_s = socket(PF_INET, SOCK_RAW, IPPROTO_DIVERT)) == -1)
#endif
		err(1, "socket()");

	if (bind(_s, (struct sockaddr*) &s_in, sizeof(s_in)) == -1)
		err(1, "bind()");

	_cb = cb;

        xprintf(XP_DEFAULT, "Divert packets using ipfw add divert %d\n", port);

	raw_open();

	return _s;
}

static void bsd_close(void)
{
	close(_s);
}

static void bsd_next_packet(int s)
{
	unsigned char buf[2048];
	struct sockaddr_in s_in;
	socklen_t len = sizeof(s_in);
	int rc;
	int verdict;
	int flags = 0;

	rc = recvfrom(_s, buf, sizeof(buf), 0, (struct sockaddr*) &s_in, &len);
	if (rc == -1)
		err(1, "recvfrom()");

	if (rc == 0)
		errx(1, "EOF");

	if (s_in.sin_addr.s_addr != INADDR_ANY)
		flags |= DF_IN;

	verdict = _cb(buf, rc, flags);

	switch (verdict) {
	case DIVERT_MODIFY:
		rc = ntohs(((struct ip*) buf)->ip_len);
		/* fallthrough */
	case DIVERT_ACCEPT:
		flags = sendto(_s, buf, rc, 0, (struct sockaddr*)  &s_in, len);
		if (flags == -1)
			err(1, "sendto()");

		if (flags != rc)
			errx(1, "sent %d/%d", flags, rc);
		break;

	case DIVERT_DROP:
		break;

	default:
		abort();
		break;
	}
}

struct divert *divert_get(void)
{
        static struct divert _divert_bsd = {
                .open           = bsd_open,
                .next_packet    = bsd_next_packet,
                .close          = bsd_close,
                .inject         = raw_inject,
        };

	if (_conf.cf_rdr)
		return divert_get_pcap();

        return &_divert_bsd;
}
