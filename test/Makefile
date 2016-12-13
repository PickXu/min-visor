CC := gcc
CFLAGS := -Wall -D__USER_APP__
NONPREMPT := 
NOP := 

SRCS := cache_miss_msrmt.c lock_core.c
OBJS := cache_miss_msrmt.o lock_core.o

cache_miss_msrmt: $(SRCS)
	$(CC) $(CFLAGS) $(NONPREEMPT) $(NOP) $^ -o $@

clean:
	rm cache_miss_msrmt
