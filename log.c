#include <stdio.h>
#include <string.h>
#include "log.h"

int g_log_level = LOG_LEVEL_INFO;

void log_set_level_by_name(const char* name){
    if(!name){
        printf("log-level : bad arg\n");
        return;
    }
    if(strcmp(name, "debug") == 0)      g_log_level = LOG_LEVEL_DEBUG;
    else if(strcmp(name, "info") == 0)  g_log_level = LOG_LEVEL_INFO;
    else if(strcmp(name, "warn") == 0)  g_log_level = LOG_LEVEL_WARN;
    else if(strcmp(name, "error") == 0) g_log_level = LOG_LEVEL_ERROR;
    else {
        printf("log-level : unknown `%s` (expected debug|info|warn|error)\n", name);
        return;
    }
    printf("log-level : set to %s\n", name);
}
