#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <linux/prctl.h>
struct prctl_mm_map m;
static unsigned long fld(const char*s,int f){char*p=(char*)s;for(int i=3;i<f;i++){p=strchr(p,' ');if(!p)return 0;p++;}return strtoul(p,NULL,10);}
static void show(const char*tag){char b[128];FILE*g=fopen("/proc/self/cmdline","r");size_t n=fread(b,1,127,g);fclose(g);
  printf("%-46s %3zu bytes: ",tag,n);for(size_t i=0;i<n&&i<50;i++)putchar(b[i]?b[i]:'.');printf("\n");}
int main(void){
  setvbuf(stdout,NULL,_IONBF,0);
  char buf[8192];FILE*f=fopen("/proc/self/stat","r");fgets(buf,8192,f);fclose(f);
  char*s=strrchr(buf,')')+2;
  unsigned long sc=fld(s,26),ec=fld(s,27),sd=fld(s,45),ed=fld(s,46),sb=fld(s,47);
  memset(&m,0,sizeof m);
  m.start_code=sc;m.end_code=ec;m.start_data=sd;m.end_data=ed;
  m.start_brk=sb;m.brk=(unsigned long)sbrk(0);m.exe_fd=(unsigned)-1;
  for(int k=0;k<2;k++){
    int flags = k? MAP_PRIVATE : MAP_SHARED;
    int fd=memfd_create("secret",0); ftruncate(fd,4096);
    char *mp=mmap(NULL,4096,PROT_READ|PROT_WRITE,flags,fd,0);
    strcpy(mp,"from-memfd");
    m.arg_start=(unsigned long)mp;m.arg_end=(unsigned long)mp+strlen(mp)+1;
    m.env_start=m.arg_end;m.env_end=m.arg_end;m.start_stack=m.arg_start+16;
    int r=prctl(PR_SET_MM,PR_SET_MM_MAP,&m,sizeof m,0);
    char tag[80]; snprintf(tag,sizeof tag,"memfd %s prctl=%d:",k?"MAP_PRIVATE":"MAP_SHARED",r);
    show(tag);
    /* populate the page then retry */
    volatile char c=mp[0]; (void)c;
    show("  after touching page:");
  }
  /* 2M large page / THP-free test: anon containing an 'f' write to be safe */
  return 0;
}
