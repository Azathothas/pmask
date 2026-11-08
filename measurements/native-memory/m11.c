#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <linux/prctl.h>
struct prctl_mm_map m;
static unsigned long fld(const char*s,int f){char*p=(char*)s;for(int i=3;i<f;i++){p=strchr(p,' ');if(!p)return 0;p++;}return strtoul(p,NULL,10);}
int main(void){
  pid_t c=fork();
  if(c==0){
    char buf[8192];FILE*f=fopen("/proc/self/stat","r");fgets(buf,8192,f);fclose(f);
    char*s=strrchr(buf,')')+2;
    memset(&m,0,sizeof m);
    m.start_code=fld(s,26);m.end_code=fld(s,27);m.start_data=fld(s,45);m.end_data=fld(s,46);
    m.start_brk=fld(s,47);m.brk=(unsigned long)sbrk(0);m.exe_fd=(unsigned)-1;
    int fd=memfd_create("lbl",0);ftruncate(fd,4096);
    char*mp=mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0); strcpy(mp,"hidden-label");
    m.arg_start=(unsigned long)mp;m.arg_end=(unsigned long)mp+13;m.env_start=m.arg_end;m.env_end=m.arg_end;
    m.start_stack=m.arg_start+16;
    prctl(PR_SET_MM,PR_SET_MM_MAP,&m,sizeof m,0);
    sleep(2); _exit(0);
  }
  sleep(1);
  char cmd[256]; snprintf(cmd,sizeof cmd,"ps -o pid,comm,args -p %d; wc -c < /proc/%d/cmdline",c,c);
  system(cmd); waitpid(c,NULL,0); return 0;
}
