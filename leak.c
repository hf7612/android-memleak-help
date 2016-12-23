#include "leak.h"
#include "error.h"
#include <inttypes.h>
#include <unistd.h>
#include <errno.h>

/*
 * in <unistd.h> for getopt_long
 */
extern char *optarg;
extern int optind;

static struct mapinfo* g_mapinfo = NULL;
static struct mem *g_mem = NULL;
static struct result *g_res = NULL;
#define ADDR2LINE "/usr/bin/addr2line"


static void usage()
{
    fprintf(stderr,
        "Usage:\n"
        "\t./leak\n"
        "\t      -m maps file\n"
        "\t      -d diff file\n"
        "\t      -r root directory\n"
        "\t      -a has addr2line cmd, should set -r\n"
        "\t      -h show help\n"
        "\n");
}

static void help()
{
    usage();
    fprintf(stderr,
        "Options:\n"
        "\t -m maps file: maps file of the leak process\n"
        "\t -d diff file: diff file befor and after leak.\n"
        "\t -r: root directory \n"
        "\t -a: has addr2line, default is disabled\n"
        "\t example:  \n"
        "\t\t if has addr2line\n"
        "\t\t\t./tt -a -m maps -d diff -r /mnt/fileroot/baocheng.sun/lollipop/out/target/product/p200/symbols/\n"
        "\t\t else\n"
        "\t\t\t./tt -m maps -d diff\n"
        "\t -v: print the version and exit()\n");
}


// Format of /proc/<PID>/maps:
//   6f000000-6f01e000 rwxp 00000000 00:0c 16389419   /system/lib/libcomposer.so
static struct mapinfo* parse_maps_line(char* line) {
    uintptr_t start;
    uintptr_t end;
    uintptr_t offset;

    char permissions[4];
    int name_pos;
    if (sscanf(line, "%" PRIxPTR "-%" PRIxPTR " %4s %" PRIxPTR " %*x:%*x %*d%n", &start,
   // if (sscanf(line, "%" SCNd64 "-%" SCNd64 " %4s %" SCNd64 " %*x:%*x %*d%n", &start,
                &end, permissions, &offset, &name_pos) < 2) {
        return NULL;
    }

    while (isspace(line[name_pos])) {
      name_pos += 1;
    }
    const char* name = line + name_pos;
    size_t name_len = strlen(name);
    if (name_len && name[name_len - 1] == '\n') {
      name_len -= 1;
    }

    struct mapinfo* mi = (struct mapinfo *)(calloc(1, sizeof(struct mapinfo) + name_len + 1));
    if (mi) {
      mi->start = start;
      mi->end = end;
      mi->offset = offset;
      if (permissions[0] != 'r') {
        // Any unreadable map will just get a zero load base.
        mi->load_base = 0;
        mi->load_base_read = 1;
      } else {
        mi->load_base_read = 0;
      }
      memcpy(mi->name, name, name_len);
      mi->name[name_len] = '\0';
    }
    return mi;
}

static struct mapinfo* parse_maps(char *maps_file)
{
    FILE *fp;
    char buffer[2048];
    struct mapinfo *milist = NULL;

    if ((fp = fopen(maps_file, "r")) == NULL) {
        err_sys("open file %s error\n", maps_file);
    }

    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        struct mapinfo* mi = parse_maps_line(buffer);
        if (mi) {
            mi->next = milist;
            milist = mi;
        }
    }

    fclose(fp);

    return milist;
}

static struct mem* parse_mem_line(char *line)
{
    char *p, *s;
    int size = 0, i;
    struct mem *part = (struct mem *)(calloc(1, sizeof(struct mem) + 1));

    p = strtok(line, ",");

    if ((s = strstr(p, "size")) != NULL) {
        s += sizeof("size");
        for (i = 0; i < strlen(s); i++) {
            if (!isspace(s[i])) {
                s += i;
                break;
            }
        }
        size = atoi(s);
    }

   // sscanf(p, "%*s%d", &size);
    part->size = size;


    i = 0;
    while ((p = strtok(NULL, ",")) != NULL) {
        if (strstr(p, "dup")) {
            sscanf(p, "%*s%d", &part->dup);
         } else {
             sscanf(p, "%" PRIxPTR, &part->addr[i]);
             i++;
             if (i == FRAMESIZE) {
                 err_msg("backtrace is more than %d\n", FRAMESIZE);
                 break;
             }
         }
    }
    return part;
}

static struct mem *parse_diff(char *diff_file)
{
    FILE *fp;
    char buffer[2048];
    struct mem *mlist = NULL;

    if ((fp = fopen(diff_file, "r")) == NULL) {
        err_sys("open file %s error\n", diff_file);
    }

    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        if (!strstr(buffer, "size")  || !strstr(buffer, "dup"))
            continue;

        struct mem* mi = parse_mem_line(buffer);
        if (mi) {
            mi->next = mlist;
            mlist = mi;
        }
    }

    fclose(fp);
    return mlist;
}

static struct mapinfo *find_mapinfo(struct mapinfo *item, uintptr_t pc)
{
    for (; item != NULL; item = item->next) {
        if ((pc >= item->start) && (pc < item->end))
            return item;
    }

    return NULL;
}

static int get_result()
{
    struct result *res;
    struct mem *mem_item;
    struct mapinfo *map_item;
    int i;

    mem_item = g_mem;

    while (mem_item != NULL) {
        res = (struct result *)(calloc(1, sizeof(struct result)));
        res->m_mem = mem_item;

        for (i = 0; i < FRAMESIZE; i++) {
            if (mem_item->addr[i] == 0)
                break;

            map_item = find_mapinfo(g_mapinfo, mem_item->addr[i]);
            if (map_item != NULL) {
                res->array[i].offset = mem_item->addr[i] - map_item->start;
                strcpy(res->array[i].name, map_item->name);
            }
        }

        res->next = g_res;
        g_res = res;
        mem_item = mem_item->next;
    }

    return 0;
}

static void print_item(const struct result *item)
{
    int i;
    if (item == NULL)
        return;

    printf("size %d, dup %d\n", item->m_mem->size, item->m_mem->dup);
    for (i = 0; i < 32; i++) {
        if (item->array[i].offset == 0)
            break;
        printf("\t\t%08"PRIxPTR"\t%s\n", item->array[i].offset, item->array[i].name);
    }
}

static void addr2line(char *root)
{

    struct result *res = g_res;
    int i = 0;
    char cmd[512], line[512];
    int pid, status;
    FILE *fp;

    while (res != NULL) {
        print_item(res);
        for (i = 0; i < 32; i++) {
            if (res->array[i].offset == 0)
                break;

            sprintf(cmd, "%s %s %s/%s %08"PRIxPTR,
                    ADDR2LINE, "-e", root, res->array[i].name, res->array[i].offset);

            fp = popen(cmd, "r");
            if (!fp) {
                err_msg("failed to popen");
                break;
            }
            while (fgets(line, sizeof(line), fp))
                printf("%s", line);
            pclose(fp);

        }

        res = res->next;
    }

}

static void print_result()
{
    struct result *res = g_res;
    int i = 0;

    while (res != NULL) {
        print_item(res);
        res = res->next;
    }
}

static struct result* sort_result(struct result *head)
{
    struct result *item, *prev, *now, *tmp;
    int flag;
    if (head == NULL)
        return NULL;

    item = head->next;
    head->next = NULL;

    while (item != NULL) {
        tmp = item;
        item = item->next;

        // tmp is biger
        if (head->m_mem->dup <= tmp->m_mem->dup) {
            tmp->next = head;
            head = tmp;
        } else {
            flag = 0;
            for (now = head; now != NULL; now = now->next) {
                if (now->m_mem->dup > tmp->m_mem->dup) {
                    prev = now;
                } else {
                    tmp->next = now;
                    prev->next = tmp;
                    flag = 1;
                    break;
                }
            }

            // tmp is smallest
            if (flag == 0) {
                prev->next = tmp;
                tmp->next = NULL;
            }
        }
    }

    return head;
}

void cleanup()
{
    struct mapinfo *p_mapinfo;
    while (g_mapinfo != NULL) {
        p_mapinfo = g_mapinfo;
        g_mapinfo = g_mapinfo->next;
        free(p_mapinfo);
    }

    struct mem *p_mem;
    while (g_mem != NULL) {
        p_mem = g_mem;
        g_mem = g_mem->next;
        free(p_mem);
    }

    struct result *p_res;
    while(g_res != NULL) {
        p_res = g_res;
        g_res = g_res->next;
        free(p_res);
    }
}

int main(int argc, char *argv[])
{
    int c, index = 0;
    /* option_name, has_arg(0: none, 1:recquired, 2 optional), flag, return_value) */
    static struct option long_opts[] = {
        {"help", 0, NULL, 'h'},
        {"version", 0, NULL, 'v'},
        {0, 0, NULL, 0}
    };

    char *maps_file, *diff_file, *root;
    FILE *m_fp, *d_fp;
    int has_addr2line = 0;

    if (argc == 1) {
        usage();
        exit(-1);
    } else {
        while ((c=getopt_long(argc, argv, "ad:m:r:h", long_opts, &index)) != EOF) {
            switch (c) {
            case 'm':    /* -m */
                maps_file = strdup(optarg);
                break;
            case 'd':
                diff_file = strdup(optarg);
                break;
            case 'r':
                root = strdup(optarg);
                break;
            case 'a':
                has_addr2line = 1;
                break;
            case 'h':    /* fall through to default */
            default:
                help();
                exit(0);
            }
        }
    }

    g_mapinfo = parse_maps(maps_file);
    g_mem = parse_diff(diff_file);
    get_result();
    g_res = sort_result(g_res);

    //print_result();

    if (has_addr2line) {
        if (root == NULL) {
            err_quit("root directory should not be null");
        }
        addr2line(root);
    } else {
        print_result();
    }

    cleanup();
    return 0;
}
