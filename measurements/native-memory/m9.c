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
  printf("%-28s %3zu bytes: ",tag,n);for(size_t i=0;i<n&&i<60;i++)putchar(b[i]?b[i]:'.');printf("\n");}
int main(void){
  setvbuf(stdout,NULL,_IONBF,0);
  char buf[8192];FILE*f=fopen("/proc/self/stat","r");fgets(buf,8192,f);fclose(f);
  char*s=strrchr(buf,')')+2;
  unsigned long sc=fld(s,26),ec=fld(s,27),sd=fld(s,45),ed=fld(s,46),sb=fld(s,47),ss=fld(s,28);
  memset(&m,0,sizeof m);
  m.start_code=sc;m.end_code=ec;m.start_data=sd;m.end_data=ed;
  m.start_brk=sb;m.brk=(unsigned long)sbrk(0);m.exe_fd=(unsigned)-1;
  /* case 1: file-backed memfd page (what pmask already has) */
  int fd=memfd_create("secret",0); ftruncate(fd,4096);
  char *mp=mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
  strcpy(mp,"from-memfd-label");
  m.arg_start=(unsigned long)mp;m.arg_end=(unsigned long)mp+strlen(mp)+1;
  m.env_start=m.arg_end;m.env_end=m.arg_end;m.start_stack=m.arg_start+16;
  int r=prctl(PR_SET_MM,PR_SET_MM_MAP,&m,sizeof m,0);
  printf("case1 file-backed memfd: prctl=%d (%s)\n",r,r?strerror(errno):"ok"); show("  cmdline:");
  /* case 2: arg_end == arg_start */
  m.arg_start=(unsigned long)mp;m.arg_end=(unsigned long)mp;m.env_start=(unsigned long)mp;m.env_end=(unsigned long)mp;
  r=prctl(PR_SET_MM,PR_SET_MM_MAP,&m,sizeof m,0);
  printf("case2 arg_start==arg_end: prctl=%d (%s)\n",r,r?strerror(errno):"ok"); show("  cmdline:");
  /* case 3: restore, then unmap the region -> read should fail */
  char *ap=mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
  strcpy(ap,"anon-label"); m.arg_start=(unsigned long)ap;m.arg_end=(unsigned long)ap+strlen("anon-label")+1;
  m.env_start=m.arg_end;m.env_end=m.arg_end;m.start_stack=m.arg_start+16;
  r=prctl(PR_SET_MM,PR_SET_MM_MAP,&m,sizeof m,0);
  show("case3 anon:");
  munmap(ap,4096); show("case3 after munmap:");
  return 0;
}
