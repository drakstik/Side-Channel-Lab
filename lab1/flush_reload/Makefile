CC=gcc
CFLAGS=-O0 -I /usr/local
VAULT_CPU=0
THIEF_CPU=1

TARGETS=thief vault
UTILS=util.o 

.PHONY:	clean all run_vault run_thief

-include thief.d util.d vault.d

all: $(TARGETS)

$(UTILS): %.o: %.c %.h
	$(CC) $(CFLAGS) -MMD -c $<

%.o: %.c util.h
	$(CC) $(CFLAGS) -MMD  -c $< 

$(TARGETS): %:%.o util.o
	$(CC) $(CFLAGS) $^ -o $@ -lrt

run_vault: vault
	taskset -c $(VAULT_CPU) ./vault

run_thief: thief 
	taskset -c $(THIEF_CPU) ./thief

clean:
	$(RM) *.o *.d  $(HELPERS) $(TARGETS) 
