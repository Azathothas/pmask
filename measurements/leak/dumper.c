#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <fcntl.h>
static void set_filter(const char *v){int fd=open("/proc/self/coredump_filter",1);if(fd<0)return;if(v)write(fd,v,strlen(v));close(fd);}
int main(int argc,char**argv){
  /* argv[1]=mode: keep|filter0|reloc ; argv[2]=token-ish arg */
  struct rlimit rl={RLIM_INFINITY,RLIM_INFINITY}; setrlimit(RLIMIT_CORE,&rl);
  if(argc>1 && !strcmp(argv[1],"filter0")) set_filter("0");
  if(argc>1 && !strcmp(argv[1],"hdr_only")) set_filter("8");
  if(argc>1 && !strcmp(argv[1],"nodump")) prctl(PR_SET_DUMPABLE,0);
  fprintf(stderr,"pid=%d mode=%s arg_end-arg_start check via /proc\n",getpid(),argc>1?argv[1]:"keep");
  sleep(1);
  *(volatile int*)0=1;   /* SIGSEGV */
  return 0;
}
