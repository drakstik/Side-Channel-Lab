/**
 * 
 * CMU 15-799 Security for Software and Hardware Systems Spring 2023
 * 
 *  thief.c is the attacker implementation. You need to add the code for 
 *  prime_probe_l2_set_new()
 * 
 */

#include "util.h"
#include "params.h"
#include <sys/mman.h>

// you will need to generate an eviction linked list structure with next,
// previous pointers and time measurements
// then you can use the shuffle function to randomize the access pattern 
// and avoid prefetchers being activated
// then traverse the list for prime and probe
// you might want to consider adding some delay between steps
// finally you need to traverse the list one more time to retrieve 
// the time measurements
bool prime_probe_l2_set(int set, char *buf) {
    bool found = false;
    return found;
}

int main(int argc, char const *argv[]) {
    void *buf = NULL;
    int buf_size = 1 << 21;
    if (posix_memalign(&buf, 1 << 21, buf_size)) {
        perror("posix_memalign");
    }
    madvise(buf, buf_size, MADV_HUGEPAGE);
    *((char *)buf) = 5;

    int evict_count[L2_SETS];
    for (int i = 0; i < L2_SETS; i++) {
        evict_count[i] = 0;
    }

    int num_reps = 1000;
    for (int rep = 0; rep < num_reps; rep++) {
        for (int set = 0; set < L2_SETS; set++) {
            if (prime_probe_l2_set(set, buf)) {
                evict_count[set]++;
            }
        }
    }


    int max_val = -1;
    int max_set = -1;
    for (int set = 0; set < L2_SETS; set++) {
        if (evict_count[set] > max_val) {
            max_val = evict_count[set];
            max_set = set;
        }
    }
    printf("Vault code: %d (%d)\n", max_set, max_val);
}
