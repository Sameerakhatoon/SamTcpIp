#ifndef SAMTCPIP_LOG_H
#define SAMTCPIP_LOG_H

// ch37: log-level discipline.
//
// Four levels (low to high): DEBUG < INFO < WARN < ERROR.
// `g_log_level` filters: messages below the threshold are
// silently dropped.
//
// Default level is INFO. The thousands of existing printf()
// calls in the codebase are treated as INFO-level (they were
// written before this chapter and stay as-is). New code uses
// the LOG_*() macros so it can be silenced.

#include <stdio.h>

#define LOG_LEVEL_DEBUG  0
#define LOG_LEVEL_INFO   1
#define LOG_LEVEL_WARN   2
#define LOG_LEVEL_ERROR  3

extern int g_log_level;

void log_set_level_by_name(const char* name);

#define LOG_DEBUG(...) do { if(g_log_level <= LOG_LEVEL_DEBUG){ printf("[D] "); printf(__VA_ARGS__); fflush(stdout);} } while(0)
#define LOG_INFO(...)  do { if(g_log_level <= LOG_LEVEL_INFO ){ printf("[I] "); printf(__VA_ARGS__); fflush(stdout);} } while(0)
#define LOG_WARN(...)  do { if(g_log_level <= LOG_LEVEL_WARN ){ printf("[W] "); printf(__VA_ARGS__); fflush(stdout);} } while(0)
#define LOG_ERROR(...) do { if(g_log_level <= LOG_LEVEL_ERROR){ printf("[E] "); printf(__VA_ARGS__); fflush(stdout);} } while(0)

#endif
