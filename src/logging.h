#ifndef LOGGING_H
#define LOGGING_H

#include <stdarg.h>
#include <stdio.h>
#include <time.h>

static inline void log_msg(const char *level, const char *fmt, ...) {
    char tbuf[32];
    time_t t = time(NULL);
    struct tm tm;
    localtime_r(&t, &tm);
    strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", &tm);
    fprintf(stderr, "[%s] %s: ", tbuf, level);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
}

#define LOG(...) log_msg("INFO", __VA_ARGS__)
#define LOG_ERR(...) log_msg("ERROR", __VA_ARGS__)

#endif
