/* See LICENSE file for copyright and license details. */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../util.h"

char *argv0;

static void venprintf(int, const char *, va_list);

void
eprintf(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	venprintf(EXIT_FAILURE, fmt, ap);
	va_end(ap);
}

void
enprintf(int status, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	venprintf(status, fmt, ap);
	va_end(ap);
}

void
venprintf(int status, const char *fmt, va_list ap)
{
#ifdef DEBUG
	fprintf(stderr, "%s: ", argv0);
#endif

	vfprintf(stderr, fmt, ap);

	if(fmt[0] && fmt[strlen(fmt)-1] == ':') {
		fputc(' ', stderr);
		perror(NULL);
	}

	exit(status);
}

void
weprintf(const char *fmt, ...)
{
	va_list ap;

#ifdef DEBUG
	fprintf(stderr, "%s: ", argv0);
#endif

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);

	if (fmt[0] && fmt[strlen(fmt)-1] == ':') {
		fputc(' ', stderr);
		perror(NULL);
	}
}
