#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> 
#include <getopt.h>
#include <stdint.h>

struct mapinfo {
    struct mapinfo* next;
    uintptr_t start;
    uintptr_t end;
    uintptr_t offset;
    uintptr_t load_base;
    int load_base_read;
    char name[];
};

struct pc {
    uintptr_t offset;
    char name[128];
};

struct result {
    struct result *next;
    struct mem *m_mem;
    struct pc array[32];
};

struct mem {
    struct mem *next;
    int size;
    int dup;
    uintptr_t addr[32];
};




