#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <linux/prctl.h>
struct prctl_mm_map m;
static unsigned long fld(const char*s,int field){char*p=(char*)s;for(int i=3;i<field;i++){p=strchr(p,' ');if(!p)return 0;p++;}return strtoul(p,NULL,10);}
int main(void){
  pid_t c=fork();
  if(c==0){
    char buf[8192];FILE*f=fopen("/proc/self/stat","r");fgets(buf,8192,f);fclose(f);
    char*s=strrchr(buf,')')+2;
    unsigned long sc=fld(s,26),ec=fld(s,27),sd=fld(s,45),ed=fld(s,46),sb=fld(s,47);
    memset(&m,0,sizeof m);
    m.start_code=sc;m.end_code=ec;m.start_data=sd;m.end_data=ed;
    m.start_brk=sb;m.brk=(unsigned long)sbrk(0);m.exe_fd=(unsigned)-1;
    char *fake=mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    strcpy(fake,"proxy-worker --token=REDACTED");
    m.arg_start=(unsigned long)fake;m.arg_end=(unsigned long)fake+strlen(fake)+1;
    m.env_start=m.arg_end;m.env_end=m.arg_end;
    m.start_stack=m.arg_start+16;
    int r=prctl(PR_SET_MM,PR_SET_MM_MAP,&m,sizeof m,0);
    if(r) fprintf(stderr,"prctl failed: %s\n",strerror(errno));
    sleep(3);
    _exit(0);
  }
  sleep(1);
  char cmd[512];
  snprintf(cmd,sizeof cmd,
    "echo '--- ps -o pid,ppid,comm,args'; ps -o pid,ppid,comm,args -p %d; "
    "echo '--- stat fields 28/48-51'; awk '{print \"startstack=\" $28, \"arg_start=\" $48, \"arg_end=\" $49, \"env_start=\" $50, \"env_end=\" $51}' /proc/%d/stat; "
    "echo "--- all [stack] maps"; grep -c "\[stack\]" /proc/%d/maps; grep "\[stack\]" /proc/%d/maps; "
    "echo '--- wc -c cmdline'; wc -c < /proc/%d/cmdline; "
    "echo '--- NUL count in cmdline'; tr -cd '\\000' < /proc/%d/cmdline | wc -c",
    c,c,c,c,c);
  system(cmd);
  waitpid(c,NULL,0);
  return 0;
}
