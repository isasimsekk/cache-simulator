#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <assert.h>

#define BLOCK_MAX 64
 
typedef struct {
    uint32_t tag;
    int      valid;
    int      time;
    uint8_t  data[BLOCK_MAX];
} CacheLine;

typedef struct {
    int s, E, b;
    int S, B;
    CacheLine **sets;
} Cache;


static Cache* init_cache(int s, int E, int b) {
    Cache *cache = malloc(sizeof(Cache));
    assert(cache != NULL);
    cache->s = s;
    cache->E = E;
    cache->b = b;
    cache->S = 1 << s;
    cache->B = 1 << b;
    cache->sets = malloc(sizeof(CacheLine*) * cache->S);
    assert(cache->sets != NULL);
    for (int i = 0; i < cache->S; i++) {
        cache->sets[i] = malloc(sizeof(CacheLine) * E);
        assert(cache->sets[i] != NULL);
        for (int j = 0; j < E; j++) {
            cache->sets[i][j].valid = 0;
            cache->sets[i][j].time  = 0;
            memset(cache->sets[i][j].data, 0, BLOCK_MAX);
        }
    }
    return cache;
}


static void free_cache(Cache *cache) {
    for (int i = 0; i < cache->S; i++) free(cache->sets[i]);
    free(cache->sets);
    free(cache);
}


static void read_from_ram(FILE *ram, uint32_t addr, int size, uint8_t *buf) {
    fseek(ram, addr, SEEK_SET);
    fread(buf, 1, size, ram);
}


static int access_cache(Cache *cache, uint32_t addr, uint8_t *data_buf, int size, int is_store, int *evict_flag, int *global_time) {
    *evict_flag = 0;
    uint32_t tag = addr >> (cache->s + cache->b);
    uint32_t index = (addr >> cache->b) & ((1 << cache->s) - 1);
    CacheLine *set = cache->sets[index];

    
    for (int i = 0; i < cache->E; i++) {
        if (set[i].valid && set[i].tag == tag) {
            if (is_store && data_buf) { 
                memcpy(set[i].data + (addr & (cache->B - 1)), data_buf, size);
            }
            return 1; 
        }
    }


    if (is_store) return 0; 

    int victim = -1;
    for (int i = 0; i < cache->E; i++) {
        if (!set[i].valid) {
            victim = i;
            break;
        }
    }
    if (victim == -1) { 
        *evict_flag = 1;
        int oldest_time = INT_MAX;
        for (int i = 0; i < cache->E; i++) {
            if (set[i].time < oldest_time) {
                oldest_time = set[i].time;
                victim = i;
            }
        }
    }

    
    set[victim].valid = 1;
    set[victim].tag = tag;
    set[victim].time = (*global_time)++;
    if (data_buf) { 
        memcpy(set[victim].data, data_buf, cache->B);
    }
    return 0; // Miss
}


static void write_cache(Cache *cache, const char *name) {
    FILE *f = fopen(name, "w");
    if (!f) { perror("dump file"); return; }
    for (int i = 0; i < cache->S; i++) {
        if (cache->S > 1) {
            fprintf(f, "Set %d:\n", i);
        }
        for (int j = 0; j < cache->E; j++) {
            if (cache->sets[i][j].valid) {
                CacheLine *line = &cache->sets[i][j];
                if (cache->S > 1) fprintf(f, "  ");
                fprintf(f, "0x%x %d %d ", line->tag, line->time, line->valid);
                for (int k = 0; k < 8; k++) {
                    fprintf(f, "%02x", line->data[k]);
                }
                fprintf(f, "\n");
            }
        }
    }
    fclose(f);
}


int main(int argc, char **argv) {
    int L1s = 0, L1E = 0, L1b = 0, L2s = 0, L2E = 0, L2b = 0;
    char *trace_file = NULL;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-L1s")) L1s = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-L1E")) L1E = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-L1b")) L1b = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-L2s")) L2s = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-L2E")) L2E = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-L2b")) L2b = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-t")) trace_file = argv[++i];
    }

    if (!trace_file) {
        fprintf(stderr, "Error: Trace file not specified.\n");
        return 1;
    }

    Cache *L1I = init_cache(L1s, L1E, L1b);
    Cache *L1D = init_cache(L1s, L1E, L1b);
    Cache *L2 = init_cache(L2s, L2E, L2b);

    FILE *trace = fopen(trace_file, "r");
    FILE *ram = fopen("RAM.dat", "rb+");
    if (!trace) { perror("open trace"); return 1; }
    if (!ram) { perror("open RAM.dat"); return 1; }

    int L1I_hits = 0, L1I_misses = 0, L1I_evictions = 0;
    int L1D_hits = 0, L1D_misses = 0, L1D_evictions = 0;
    int L2_hits = 0, L2_misses = 0, L2_evictions = 0;

    char line[256];
    static int global_time = 1;

    while (fgets(line, sizeof(line), trace)) {
        if (line[0] == '\n' || line[0] == '#') continue;

        char op;
        uint32_t addr;
        int size = 0;
        char data_str[128] = "";
        sscanf(line, " %c %x,%d,%127s", &op, &addr, &size, data_str);

        int evict = 0;

        if (op == 'I' || op == 'L' || op == 'M') {
            Cache* l1_cache = (op == 'I') ? L1I : L1D;
            int* hits = (op == 'I') ? &L1I_hits : &L1D_hits;
            int* misses = (op == 'I') ? &L1I_misses : &L1D_misses;
            int* evictions = (op == 'I') ? &L1I_evictions : &L1D_evictions;

            
            if (access_cache(l1_cache, addr, NULL, 0, 0, &evict, &global_time)) {
                (*hits)++;
                if(access_cache(L2, addr, NULL, 0, 0, &evict, &global_time)) L2_hits++;
            } else { 
                (*misses)++;
                if (evict) (*evictions)++;

                uint8_t ram_buffer[BLOCK_MAX] = {0};
                
                uint32_t block_start_addr = addr & (~((1u << l1_cache->b) - 1));
                read_from_ram(ram, block_start_addr, 8, ram_buffer);

                
                if (access_cache(L2, addr, ram_buffer, 0, 0, &evict, &global_time)) {
                    L2_hits++;
                } else { 
                    L2_misses++;
                    if(evict) L2_evictions++;
                }

               
                access_cache(l1_cache, addr, ram_buffer, 0, 0, &evict, &global_time);
            }
        }

        if (op == 'S' || op == 'M') {
             
            uint8_t write_data[BLOCK_MAX] = {0};
            unsigned int temp_byte;
            for (int i = 0; i < size && i < (int)(strlen(data_str) / 2); i++) {
                sscanf(&data_str[i * 2], "%2x", &temp_byte);
                write_data[i] = (uint8_t)temp_byte;
            }
            fseek(ram, addr, SEEK_SET);
            fwrite(write_data, 1, size, ram);

            if (op == 'M') {
                L1D_hits++; L2_hits++;
                access_cache(L1D, addr, write_data, size, 1, &evict, &global_time);
                access_cache(L2, addr, write_data, size, 1, &evict, &global_time);
            } else { 
                if (access_cache(L1D, addr, write_data, size, 1, &evict, &global_time)) {
                    L1D_hits++;
                    if(access_cache(L2, addr, write_data, size, 1, &evict, &global_time)) L2_hits++;
                } else {
                    L1D_misses++;
                    if (access_cache(L2, addr, write_data, size, 1, &evict, &global_time)) { L2_hits++; }
                    else { L2_misses++; }
                }
            }
        }
    }

    printf("\nL1I-hits:%d L1I-misses:%d L1I-evictions:%d\n", L1I_hits, L1I_misses, L1I_evictions);
    printf("L1D-hits:%d L1D-misses:%d L1D-evictions:%d\n", L1D_hits, L1D_misses, L1D_evictions);
    printf("L2-hits:%d L2-misses:%d L2-evictions:%d\n", L2_hits, L2_misses, L2_evictions);

    write_cache(L1I, "L1I.txt");
    write_cache(L1D, "L1D.txt");
    write_cache(L2, "L2.txt");

    fclose(trace);
    fclose(ram);
    free_cache(L1I);
    free_cache(L1D);
    free_cache(L2);
    return 0;
}
