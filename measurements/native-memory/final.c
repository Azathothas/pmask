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
static void show(const char*t){char b[128];FILE*g=fopen("/proc/self/cmdline","r");size_t n=fread(b,1,127,g);fclose(g);printf("%-40s len=%zu\n",t,n);}
int main(void){
  setvbuf(stdout,NULL,_IONBF,0);
  char buf[8192];FILE*f=fopen("/proc/self/stat","r");fgets(buf,8192,f);fclose(f);
  char*s=strrchr(buf,')')+2;
  memset(&m,0,sizeof m);
  m.start_code=fld(s,26);m.end_code=fld(s,27);m.start_data=fld(s,45);m.end_data=fld(s,46);
  m.start_brk=fld(s,47);m.brk=(unsigned long)sbrk(0);m.exe_fd=(unsigned)-1;
  char*ap=mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
  strcpy(ap,"label");                         /* 5 bytes + NUL = 6 */
  m.arg_start=(unsigned long)ap; m.arg_end=(unsigned long)ap+6;   /* exactly len+1 */
  m.env_start=m.arg_end; m.env_end=m.arg_end; m.start_stack=m.arg_start+16;
  printf("prctl=%d\n",prctl(PR_SET_MM,PR_SET_MM_MAP,&m,sizeof m,0));
  show("arg_end = arg_start+len+1 :");
  m.arg_end=(unsigned long)ap+7;              /* len+2 */
  prctl(PR_SET_MM,PR_SET_MM_MAP,&m,sizeof m,0); show("arg_end = arg_start+len+2 :");
  return 0;
}
