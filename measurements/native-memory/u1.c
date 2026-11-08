#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <linux/prctl.h>
struct prctl_mm_map m;
static unsigned long fld(const char*s,int f){char*p=(char*)s;for(int i=3;i<f;i++){p=strchr(p,' ');if(!p)return 0;p++;}return strtoul(p,NULL,10);}
int main(void){
  setvbuf(stdout,NULL,_IONBF,0);
  if(unshare(CLONE_NEWUSER)!=0){printf("unshare(NEWUSER) failed: %s\n",strerror(errno));return 1;}
  printf("in userns; uid=%d euid=%d\n",getuid(),geteuid());
  { char b[256]; FILE*f=fopen("/proc/self/status","r"); while(fgets(b,256,f)) if(!strncmp(b,"CapEff",6)) fputs(b,stdout); fclose(f);}
  char buf[8192];FILE*f=fopen("/proc/self/stat","r");fgets(buf,8192,f);fclose(f);
  char*s=strrchr(buf,')')+2;
  memset(&m,0,sizeof m);
  m.start_code=fld(s,26);m.end_code=fld(s,27);m.start_data=fld(s,45);m.end_data=fld(s,46);
  m.start_brk=fld(s,47);m.brk=(unsigned long)sbrk(0);m.exe_fd=(unsigned)-1;
  char *ap=mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
  strcpy(ap,"ns-label"); m.arg_start=(unsigned long)ap;m.arg_end=(unsigned long)ap+9;
  m.env_start=m.arg_end;m.env_end=m.arg_end;m.start_stack=m.arg_start+16;
  int r=prctl(PR_SET_MM,PR_SET_MM_MAP,&m,sizeof m,0);
  printf("MAP in userns -> %d (%s)\n",r,r?strerror(errno):"OK");
  int fd=open("/bin/true",O_RDONLY);
  printf("open(/bin/true)=%d\n",fd);
  m.exe_fd=fd;
  r=prctl(PR_SET_MM,PR_SET_MM_MAP,&m,sizeof m,0);
  printf("MAP exe_fd in userns -> %d (%s)\n",r,r?strerror(errno):"OK");
  { char b[256]; ssize_t n=readlink("/proc/self/exe",b,255); if(n>0){b[n]=0;printf("  /proc/self/exe -> %s\n",b);} }
  return 0;
}
