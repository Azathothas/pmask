#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <stdlib.h>
int main(int c,char**v){ if(c>1) prctl(PR_SET_DUMPABLE,0);
  printf("%d\n",getpid()); fflush(stdout); sleep(30); return 0; }
