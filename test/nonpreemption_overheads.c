#include "lock_core.h"
#include <stdio.h>
#include <sys/time.h>

int main() {

    struct timeval a,b,c,t1,t2;
    int i;

    timerclear(&t1);
    timerclear(&t2);
    for(i=0;i<1000;i++) {
	
    	gettimeofday(&a,NULL);
	lock_core();
    	gettimeofday(&b,NULL);
	timersub(&b,&a,&c);
	timeradd(&c,&t1,&t1);

    	gettimeofday(&a,NULL);
	unlock_core();
	gettimeofday(&b,NULL);
	timersub(&b,&a,&c);
	timeradd(&c,&t2,&t2);

    } 

    printf("Lock Overheads: %06lu.%06lu\n", t1.tv_sec,t1.tv_usec);
    printf("UnLock Overheads: %06lu.%06lu\n", t2.tv_sec,t2.tv_usec);
    return 0;
}
