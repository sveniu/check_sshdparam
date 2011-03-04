/*
 * Nagios plugin for checking remote SSH server parameters
 *
 * List of parameters that can be checked:
 * - Blacklist of user authentication methods
 * - List of required user authentication methods
 *
 * Example invocation:
 *   check_sshdparam --host localhost --timeout 5 \
 *     --uablacklist password,keyboard-interactive \
 *     --uawhitelist publickey
 *
 * TODO:
 * - Host key fingerprint? Or just leave that to known_hosts.
 * - Host SSH string? Already done by check_ssh. Not in libssh2.
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>	/* getopt_long(3) */
#include <string.h>	/* strtok(3) */
#include <ctype.h>	/* isprint(3) */
#include <unistd.h>	/* close(2), alarm(2) */
#include <error.h>	/* error(3) */
#include <signal.h>	/* signal(2) */
#include <netdb.h>	/* getaddrinfo(3) */
#include <sys/socket.h>	/* socket(7) */
#include <libssh2.h>

#define MAXCSLISTSIZE 2048
#define MAXSTRSIZE 4096
#define MAXHOSTBUFSIZE 256
#define FIELDSEP ","

#ifndef DEBUG
#define DEBUG 0
#endif
#define dp(fmt, ...) \
	do { if (DEBUG || opt_verbose) fprintf(stderr, "%s:%d:%s(): " fmt, __FILE__, \
			__LINE__, __func__, ## __VA_ARGS__); } while (0)

enum alertstate {
	OK = 0,
	WARNING = 1,
	CRITICAL = 2,
	UNKNOWN = 3,
	INIT = 4,
};

struct retval_descr {
	enum alertstate type;
	char *text;
};

static struct retval_descr retval_list[] = {
	{OK,		"OK"},
	{WARNING,	"WARNING"},
	{CRITICAL,	"CRITICAL"},
	{UNKNOWN,	"UNKNOWN"},
};

char *opt_host = NULL;
char *opt_port = NULL;
char *opt_username = NULL;
int opt_timeout = 10;
char *opt_uablacklist = NULL;
char *opt_uawhitelist = NULL;
int opt_verbose = 0;

int curstate = INIT;
char *curstatebuf = NULL;
char *curstatebufptr;

char *serverualist;
char *uablacklistout;
char *uawhitelistout;
char *ualistoutptr;

void usage(char *prog)
{
	fprintf(stderr, "%s: Nagios plugin for checking remote SSH server parameters\n", prog);
	fprintf(stderr, "Usage: %s [OPTION]...\n", prog);
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "  -H, --host=HOST         Destination host, name or IP. Default: 127.0.0.1\n");
	fprintf(stderr, "  -p, --port=PORT         Destination port, name or num. Default: ssh\n");
	fprintf(stderr, "  -u, --username=USER     Username for SSH login. Default: root\n");
	fprintf(stderr, "  -t, --timeout=SEC       Timeout in seconds. Default: 10\n");
	fprintf(stderr, "  -B, --uablacklist=LIST  Auth method blacklist*. Default: empty\n");
	fprintf(stderr, "  -W, --uawhitelist=LIST  Auth method required list*. Default: empty\n");
	fprintf(stderr, "  -v, --verbose           Verbose operation. Default: not enabled\n");
	fprintf(stderr, "*: LIST is comma-separated, e.g. \"publickey,keyboard-interactive\"\n");
	return;
}

void nagios_exit()
{
	if(curstate == INIT)
		curstate = UNKNOWN;
	if(curstatebuf == NULL || !strlen(curstatebuf))
		sprintf(curstatebuf, "Unhandled error");
	printf("%s: %s\n", retval_list[curstate].text, curstatebuf);
	free(curstatebuf);
	exit(curstate);
}

int parse_options(int argc, char **argv)
{
	int c;
	static struct option long_options[] = {
		{"host",	1, 0, 'H'},
		{"port",	1, 0, 'p'},
		{"username",	1, 0, 'u'},
		{"timeout",	1, 0, 't'},
		{"uablacklist",	1, 0, 'B'},
		{"uawhitelist",	1, 0, 'W'},
		{"verbose",	0, 0, 'v'},
		{"help",	0, 0, 'h'},
		{NULL,		0, NULL, 0}
	};
	int option_index = 0;
	while ((c = getopt_long(argc, argv, "H:p:u:t:B:W:vh",
					long_options, &option_index)) != -1) {
		switch (c) {
			case 'H':
				opt_host = optarg;
				break;
			case 'p':
				opt_port = optarg;
				break;
			case 'u':
				opt_username = optarg;
				break;
			case 't':
				opt_timeout = atoi(optarg);
				break;
			case 'B':
				opt_uablacklist = optarg;
				break;
			case 'W':
				opt_uawhitelist = optarg;
				break;
			case 'v':
				opt_verbose++;
				break;
			case 'h':
				usage(argv[0]);
				exit(EXIT_SUCCESS);
				break;
			case '?':
			default:
				/* FIXME: How does '?' work? */
				/*
				if(isprint(c))
					fprintf(stderr, "Fatal: Unknown option `-%c'.\n", c);
				else
					fprintf(stderr, "Fatal: Unknown option character `\\x%x'.\n", c);
				*/
				usage(argv[0]);
				return -1;
				break;
		}
	}
	return 0;
}

void timeout_handler(int sig)
{
	dp("Caught signal %d: Timeout!\n", sig);
	curstate = CRITICAL;
	sprintf(curstatebuf, "%d second timeout reached", opt_timeout);
	nagios_exit();
	return;
}

/* Return comma-separated list representing intersection between
 * comma-separated lists lista and listb.
 */
char *cslist_intersect(char *lista, char *listb)
{
	char *tmpstr1, *tmpstr2, *token, *token2;
	char *tmpstr1save, *tmpstr2save;
	char *saveptr1, *saveptr2;
	char *ptr, *output = NULL;

	if(lista == NULL || listb == NULL)
		return output;
	output = malloc(MAXCSLISTSIZE);
	*output = '\0';

	/* Iterate through lista */
	dp("Input list A / B: %s / %s\n", lista, listb);
	tmpstr1save = tmpstr1 = strdup(listb);
	ptr = output;
	for(;; tmpstr1 = NULL) {
		token = strtok_r(tmpstr1, FIELDSEP, &saveptr1);
		if(token == NULL)
			break;

		/* Iterate through listb */
		tmpstr2save = tmpstr2 = strdup(lista);
		for(;; tmpstr2 = NULL) {
			token2 = strtok_r(tmpstr2, FIELDSEP, &saveptr2);
			if(token2 == NULL)
				break;

			if(!strcmp(token, token2))
			{
				/* Item from lista found in listb */
				if(ptr > output)
					*ptr++ = ',';
				strcpy(ptr, token);
				ptr += strlen(ptr);
				break;
			}
		}
		free(tmpstr2save);
	}
	free(tmpstr1save);
	dp("Result: %s\n", output);
	return output;
}

/* Return comma-separated list representing difference between
 * comma-separated lists lista and listb.
 */
char *cslist_difference(char *lista, char *listb)
{
	char *tmpstr1, *tmpstr2, *token, *token2;
	char *tmpstr1save, *tmpstr2save;
	char *saveptr1, *saveptr2;
	char *ptr, *output = NULL;
	int found;

	if(lista == NULL || listb == NULL)
		return output;
	output = malloc(MAXCSLISTSIZE);
	*output = '\0';

	/* Iterate through lista */
	dp("Input list A / B: %s / %s\n", lista, listb);
	tmpstr1save = tmpstr1 = strdup(lista);
	ptr = output;
	for (;; tmpstr1 = NULL) {
		token = strtok_r(tmpstr1, FIELDSEP, &saveptr1);
		if(token == NULL)
			break;
/* Iterate through listb */
		found = 0;
		tmpstr2save = tmpstr2 = strdup(listb);
		for(;; tmpstr2 = NULL) {
			token2 = strtok_r(tmpstr2, FIELDSEP, &saveptr2);
			if(token2 == NULL)
				break;
			if(!strcmp(token, token2))
				found = 1;
		}

		if(!found)
		{
			/* Item from lista not found in listb */
			if(ptr > output)
				*ptr++ = ',';
			strcpy(ptr, token);
			ptr += strlen(ptr);
		}
		free(tmpstr2save);
	}
	free(tmpstr1save);
	dp("Result: %s\n", output);
	return output;
}

/* IPv6 ref: http://www.akkadia.org/drepper/userapi-ipv6.html */
int main(int argc, char** argv)
{
	int rc, sock = -1;
	struct addrinfo *ai, *r;
	struct addrinfo hints;
	char bufhost[MAXHOSTBUFSIZE];
	char bufport[MAXHOSTBUFSIZE];
	LIBSSH2_SESSION *session;

	curstatebuf = malloc(MAXSTRSIZE);
	*curstatebuf = '\0';

	/* Option defaults */
	opt_host = "127.0.0.1";
	opt_port = "ssh";
	opt_username = "root";
	if((rc = parse_options(argc, argv)) != 0)
	{
		curstate = CRITICAL;
		sprintf(curstatebuf, "Option parsing failed (%d). See stderr.", rc);
		nagios_exit();
	}

	signal(SIGALRM, timeout_handler);
	alarm(opt_timeout);

	memset(&hints, '\0', sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_ADDRCONFIG;
	dp("Connecting to %s:%s\n", opt_host, opt_port);
	int e = getaddrinfo(opt_host, opt_port, &hints, &ai);
	if (e != 0)
	{
		curstate = CRITICAL;
		sprintf(curstatebuf, "getaddrinfo: %s", gai_strerror(e));
		nagios_exit();
	}

	dp("Attempting connection to %s:%s\n", opt_host, opt_port);
	for(r = ai; r != NULL; r = r->ai_next) {
		dp("-> Trying family/socktype/proto %d/%d/%d\n",
				r->ai_family, r->ai_socktype, r->ai_protocol);
		sock = socket(r->ai_family, r->ai_socktype, r->ai_protocol);
		if (sock != -1 && connect(sock, r->ai_addr, r->ai_addrlen) == 0)
			break;
		if (sock != -1) {
			close(sock);
			sock = -1;
		}
	}
	if (sock == -1)
	{
		freeaddrinfo(ai);
		curstate = CRITICAL;
		sprintf(curstatebuf, "No socket");
		nagios_exit();
	}

	(void) getnameinfo(r->ai_addr, r->ai_addrlen,
			bufhost, sizeof (bufhost), bufport, sizeof(bufport),
			NI_NUMERICHOST|NI_NUMERICSERV);
	dp("Successfully connected to %s:%s\n", bufhost, bufport);
	freeaddrinfo(ai);

	if((rc = libssh2_init(0)) != 0)
	{
		curstate = CRITICAL;
		sprintf(curstatebuf, "libssh2 initialization failed (%d)", rc);
		nagios_exit();
	}

	session = libssh2_session_init();
	if(libssh2_session_startup(session, sock) != 0)
	{
		char *err_msg;
		libssh2_session_last_error(session, &err_msg, NULL, 0);
		curstate = CRITICAL;
		sprintf(curstatebuf, "SSH error: %s", err_msg);
		nagios_exit();
	}

	serverualist = strdup(libssh2_userauth_list(session, opt_username, strlen(opt_username)));
	dp("Server auth list: %s\n", serverualist);

	/* Run checks that were requested on the command line */
	if(opt_uablacklist != NULL && strlen(opt_uablacklist))
		uablacklistout = cslist_intersect(opt_uablacklist, serverualist);
	if(opt_uawhitelist != NULL && strlen(opt_uawhitelist))
		uawhitelistout = cslist_difference(opt_uawhitelist, serverualist);
	dp("Matching blacklist: %s\n", uablacklistout);
	dp("Matching whitelist: %s\n", uawhitelistout);

	/* Construct status string */
	curstatebufptr = curstatebuf;
	if(uablacklistout != NULL && strlen(uablacklistout))
	{
		curstate = CRITICAL;
		sprintf(curstatebufptr, "Blacklisted SSH auth methods found (%s)", uablacklistout);
		curstatebufptr = strchr(curstatebuf, '\0');
	}
	if(uawhitelistout != NULL && strlen(uawhitelistout))
	{
		if(curstatebufptr > curstatebuf)
		{
			sprintf(curstatebufptr, ", ");
			curstatebufptr = strchr(curstatebuf, '\0');
		}
		curstate = CRITICAL;
		sprintf(curstatebufptr, "Required SSH auth methods not found (%s)", uawhitelistout);
		curstatebufptr = strchr(curstatebuf, '\0');
	}

	if(uablacklistout != NULL)
		free(uablacklistout);
	if(uawhitelistout != NULL)
		free(uawhitelistout);
	free(serverualist);

	libssh2_session_disconnect(session, "ok");
	libssh2_session_free(session);
	close(sock);
	libssh2_exit();
	alarm(0);

	if(curstate == INIT)
	{
		curstate = OK;
		sprintf(curstatebuf, "SSH server parameters match expectations");
	}
	nagios_exit();

	return 0;
}
