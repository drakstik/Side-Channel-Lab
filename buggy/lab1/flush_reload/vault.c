/**
 * 
 * CMU 15-799 Security for Software and Hardware Systems Spring 2023
 * 
 *  vault.c is a the vault code that only opens based on a secret code
 *  the vault is locked once with a randomly chosen code
 *  then it periodically unlocks
 * 
 */

#include <time.h>
#include <stdlib.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>

#define SHARED_ID "CHANNEL"

#define BUF_LINES (4096 * 511)/64

int get_random_code() {
    return rand() % BUF_LINES;
}

int main(int argc, char const *argv[]) {
    srand(time(NULL));
    int buf_size = 4096 * 512;
    int fd;
    int var = 0;
    
    fd = shm_open(SHARED_ID, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    if (fd == -1){
	printf("shm_open error\n");
	exit(1);
    }
     
    int ret = ftruncate(fd, buf_size);
    if (ret == -1){
	printf("ftruncate error\n");
	exit(1);
    }

    uint8_t *buf;
    if ((buf = (uint8_t *)mmap(
           NULL, buf_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)) == MAP_FAILED) {
        printf("mmap error\n");
        exit(1);
    }

    int vault_code = get_random_code()*64;

    printf("vault_code: %d\n", vault_code);
    while (1) {
	buf[vault_code]++;
    }

    return 0;
}
