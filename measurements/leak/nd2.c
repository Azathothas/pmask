#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <stdlib.h>
#include <string.h>
/* argv[1]=dumpable(0/1); detaches into its own session so the prober is NOT an ancestor */
int main(int c,char**v){ int d = c>1 ? atoi(v[1]) : 1;
  prctl(PR_SET_DUMPABLE,d);
  if(fork()!=0) _exit(0);           /* original exits, child reparents to init/pid1 */
  setsid();
  FILE*f=fopen("/tmp/nd2.pid","w"); fprintf(f,"%d\n",getpid()); fclose(f);
  sleep(60); return 0; }
