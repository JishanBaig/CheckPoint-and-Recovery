
#define _GNU_SOURCE
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <stdint.h>

#define PAGEMAP_ENTRY 8
#define GET_BIT(X,Y) (X & ((uint64_t)1<<Y)) >> Y
#define GET_PFN(X) X & 0x7FFFFFFFFFFFFF


const int long_size = sizeof(long);
void getProcPath(int opt, int pid, char **path) {
    switch (opt) {
        case 1:
        asprintf(path, "/proc/%d/maps", pid);
        //printf("%s",*path);
        break;
        case 2:
        asprintf(path,"/proc/%d/mem", pid);
        break;
        case 3:
        asprintf(path,"/proc/%d/pagemap", pid);
        break;
    }
}

void getSegmentLimits(char *addr, long *startAddr, long *endAddr, long *size) {
    // we get address range like 7efc9206e000-7efc9206f000 as input param addr
    char *pch2;
    pch2 = strtok(addr,"-");
    printf("%s\n",pch2);
    *startAddr = strtol(pch2,NULL,16);
    printf("%lx\n",*startAddr);
    pch2 = strtok(NULL,"");
    printf("%s\n",pch2);
    *endAddr = strtol(pch2,NULL,16);
    printf("%lx\n",*endAddr);
    *size = (*endAddr) - (*startAddr);
    printf("%ld\n",*size);
}

void getData(pid_t child, long addr, char *str, int len) {
    char *laddr;
    int i, j;
    union u {
        long val;
        char chars[long_size];
    }data;
    i = 0;
    j = len / long_size;
    laddr = str;
    
    while(i < j) {
        data.val = ptrace(PTRACE_PEEKDATA, child, addr + i * 4, NULL);
        memcpy(laddr, data.chars, long_size);
        ++i;
        laddr += long_size;
    }

    j = len % long_size;

    if(j != 0) {
        data.val = ptrace(PTRACE_PEEKDATA, child, addr + i * 4,NULL);
        memcpy(laddr, data.chars, j);
    }

    str[len] = '\0';
}

void putData(pid_t child, long addr, char *str, int len) {
    char *laddr;
    int i, j;
    union u {
        long val;
        char chars[long_size];
    }data;
    i = 0;
    j = len / long_size;
    laddr = str;
    
    while(i < j) {
        
        memcpy(data.chars, laddr, long_size);
        ptrace(PTRACE_POKEDATA, child, addr + i * 4, data.val);
        ++i;
        laddr += long_size;
        printf("working\n");
    }

    j = len % long_size;
    if(j != 0) {
        printf("Last piece\n");
        memcpy(data.chars, laddr, j);
        ptrace(PTRACE_POKEDATA, child, addr + i * 4, data.val);
    }
}

void printAllRegs(FILE *fp, struct user_regs_struct *regs) {
    fprintf(fp,"%llu\n",regs->r15);
    fprintf(fp,"%llu\n",regs->r14);
    fprintf(fp,"%llu\n",regs->r13);
    fprintf(fp,"%llu\n",regs->r12);
    fprintf(fp,"%llu\n",regs->rbp);
    fprintf(fp,"%llu\n",regs->rbx);
    fprintf(fp,"%llu\n",regs->r11);
    fprintf(fp,"%llu\n",regs->r10);
    fprintf(fp,"%llu\n",regs->r9);
    fprintf(fp,"%llu\n",regs->r8);
    fprintf(fp,"%llu\n",regs->rax);
    fprintf(fp,"%llu\n",regs->rcx);
    fprintf(fp,"%llu\n",regs->rdx);
    fprintf(fp,"%llu\n",regs->rsi);
    fprintf(fp,"%llu\n",regs->rdi);
    fprintf(fp,"%llu\n",regs->orig_rax);
    fprintf(fp,"%llu\n",regs->rip);
    fprintf(fp,"%llu\n",regs->cs);
    fprintf(fp,"%llu\n",regs->eflags);
    fprintf(fp,"%llu\n",regs->rsp);
    fprintf(fp,"%llu\n",regs->ss);
    fprintf(fp,"%llu\n",regs->fs_base);
    fprintf(fp,"%llu\n",regs->gs_base);
    fprintf(fp,"%llu\n",regs->ds);
    fprintf(fp,"%llu\n",regs->es);
    fprintf(fp,"%llu\n",regs->fs);
    fprintf(fp,"%llu\n",regs->gs);
}

void readAllRegs(FILE *fp, struct user_regs_struct *regs) {
    fscanf(fp,"%llu\n",&(regs->r15));
    fscanf(fp,"%llu\n",&(regs->r14));
    fscanf(fp,"%llu\n",&(regs->r13));
    fscanf(fp,"%llu\n",&(regs->r12));
    fscanf(fp,"%llu\n",&(regs->rbp));
    fscanf(fp,"%llu\n",&(regs->rbx));
    fscanf(fp,"%llu\n",&(regs->r11));
    fscanf(fp,"%llu\n",&(regs->r10));
    fscanf(fp,"%llu\n",&(regs->r9));
    fscanf(fp,"%llu\n",&(regs->r8));
    fscanf(fp,"%llu\n",&(regs->rax));
    fscanf(fp,"%llu\n",&(regs->rcx));
    fscanf(fp,"%llu\n",&(regs->rdx));
    fscanf(fp,"%llu\n",&(regs->rsi));
    fscanf(fp,"%llu\n",&(regs->rdi));
    fscanf(fp,"%llu\n",&(regs->orig_rax));
    fscanf(fp,"%llu\n",&(regs->rip));
    fscanf(fp,"%llu\n",&(regs->cs));
    fscanf(fp,"%llu\n",&(regs->eflags));
    fscanf(fp,"%llu\n",&(regs->rsp));
    fscanf(fp,"%llu\n",&(regs->ss));
    fscanf(fp,"%llu\n",&(regs->fs_base));
    fscanf(fp,"%llu\n",&(regs->gs_base));
    fscanf(fp,"%llu\n",&(regs->ds));
    fscanf(fp,"%llu\n",&(regs->es));
    fscanf(fp,"%llu\n",&(regs->fs));
    fscanf(fp,"%llu\n",&(regs->gs));

}

int getMemProtVal(char *str) {
    int per = 0;
    if (str[0] == 'r')
        per |= PROT_READ;
    if (str[1] == 'w')
        per |= PROT_WRITE;
    if (str[2] == 'x')
        per |= PROT_EXEC;
    return per;
}

int isPagePresentInRAM(char * pageMapPath, unsigned long virtAddr){

   FILE *f = fopen(pageMapPath, "rb");
   char c;
   //Shifting by virt-addr-offset number of bytes
   //and multiplying by the size of an address (the size of an entry in pagemap file)
   uint64_t fileOffset = virtAddr / getpagesize() * PAGEMAP_ENTRY;
   printf("Vaddr: 0x%lx, Page_size: %d, Entry_size: %d\n", virtAddr, getpagesize(), PAGEMAP_ENTRY);
   printf("Reading %s at 0x%llx\n", pageMapPath, (unsigned long long) fileOffset);
   fseek(f, fileOffset, SEEK_SET);
  
   int errno = 0;
   int read_val = 0;
   unsigned char c_buf[PAGEMAP_ENTRY];
   for(int i=0; i < PAGEMAP_ENTRY; ++i){
      c = getc(f);
      if(c==EOF){
         printf("\nReached end of the file\n");
         return 0;
      }
      c_buf[PAGEMAP_ENTRY - i - 1] = c;
      printf("[%d]0x%x ", i, c);
   }
   for(int i=0; i < PAGEMAP_ENTRY; ++i){
      read_val = (read_val << 8) + c_buf[i];
   }
   printf("\n");
   printf("Result: 0x%llx\n", (unsigned long long) read_val);

   if(GET_BIT(read_val, 63)) {
    printf("Present \n");
      return 1;
   } else {
      return 0;
   }
 
   fclose(f);
}

void dumpMemoryRegion(int pid, FILE* pMemFile, FILE *pageMap, unsigned long start_address, char *flags, long length, FILE *fd) {
    unsigned long address;
    int pageLength = 4096;
    unsigned char page[pageLength];
    fseeko(pMemFile, start_address, SEEK_SET);
    int numPage = 0;
    char * procPagemap;
    getProcPath(3,pid,&procPagemap);
    //if (isPagePresentInRAM(procPagemap, start_address)) {
        for (address=start_address; address < start_address + length; address += pageLength) {
            fread(&page,sizeof(unsigned char), pageLength, pMemFile);
            fwrite(&page, sizeof(unsigned char), pageLength, fd);
            ++numPage;
        }
        int isPrivate;
        if (flags[3] == 'p') {
            isPrivate=MAP_PRIVATE;
        } else {
             isPrivate = 0;
        }
        fprintf(pageMap, "%0lx %d %d %d\n",start_address, numPage, getMemProtVal(flags), isPrivate);
    //}
}

void dumpMemory(int pid) {
    FILE *fp;
    char *line = NULL;
    char *line2 = NULL;
    char *line3 = NULL;
    size_t len = 0;
    ssize_t read;
    char * path;
    getProcPath(1,pid,&path);
    printf("%s\n",path);
    fp = fopen(path,"r");
    
    if (fp == NULL) {
        printf("Error while opening mem file\n");
    } else {
        printf("reading mem\n");
        int ln = 0;
        FILE *sizeFile = fopen("size","a+");
        FILE  *code = fopen("code","a+");
        char *path;
        getProcPath(2,pid,&path);
        FILE *memFile = fopen(path,"rb");
        FILE *pageMap = fopen("pagemaps","a+");
        long startaddr;
        long endaddr;
        long size;
      
        while ((read = getline(&line, &len, fp)) != -1) {
            char *pch;
            char *flags;
            char *addr;
            int i = 0;
            char *mempath;
            pch = strtok(line," ");
            while (pch != NULL) {
                if (i == 0)
                    addr = pch;
                else if (i == 1)
                    flags = pch;
                else if( i == 5)
                    mempath = pch;
                pch = strtok(NULL," ");
                ++i;
            }

            getSegmentLimits(addr,&startaddr,&endaddr,&size);
            dumpMemoryRegion(pid, memFile, pageMap, startaddr, flags, endaddr-startaddr, code);
            fwrite(&size,sizeof(long),1,sizeFile);
        }
        fclose(pageMap);
        fclose(sizeFile);
        fclose(memFile);    
    }

    fclose(fp);
    if (line)
        free(line);
}

int main(char** argv, int argc) {
  
    pid_t traced_proc;
    struct user_regs_struct regs;
    struct user_regs_struct readRegs;
    printf("Enter PID to start tracing : ");
    scanf("%d", &traced_proc);
    ptrace(PTRACE_ATTACH, traced_proc, NULL, NULL);
    wait(NULL);
    long ret = ptrace(PTRACE_GETREGS,traced_proc,NULL, &regs);
    if (ret == 0) {
        //printf("%llu\n",regs.r15);
        ssize_t nrd;
        FILE  *fp;
        fp = fopen("regs","w+");
        if (fp != NULL) {
           //write(fd,&regs.r15,sizeof(regs.r15));
            printAllRegs(fp,&regs);
            //printAllRegs(stdout,&regs);
            rewind(fp);
            readAllRegs(fp,&readRegs);
            //printf("reading regs from file .........................\n");
            //printAllRegs(stdout,&readRegs);
            fclose(fp);
        }

    }

    sigset_t mask; // this is just typedef to unsigned long
    sigemptyset (&mask);
    ptrace(PTRACE_GETSIGMASK,traced_proc,NULL,&mask);
    FILE *sigmaskFile = fopen("sigmask","ab+");
    fwrite(&mask,sizeof(mask),1,sigmaskFile);
    fclose(sigmaskFile);
    //TODO: File Descriptors remaining

    ptrace(PTRACE_DETACH,traced_proc, NULL, NULL);

    pid_t recov_proc;
    struct user_regs_struct readRegs1;
    printf("Enter PID to start tracing : ");
    scanf("%d", &recov_proc);
    ptrace(PTRACE_ATTACH, recov_proc, NULL, NULL);
    wait(NULL);
    //ret = ptrace(PTRACE_GETREGS,traced_proc,NULL, &readRegs1);
        ssize_t nrd;
        FILE  *fp;
        fp = fopen("regs","r");
        
        if (fp != NULL) {
           //write(fd,&regs.r15,sizeof(regs.r15));
          
            readAllRegs(fp,&readRegs1);
            // printf("restoring regs from file .........................\n");
            // printAllRegs(stdout,&readRegs1);
            fclose(fp);
        }

    ptrace(PTRACE_SETREGS,recov_proc,NULL, &readRegs1);
    dumpMemory(recov_proc);
    ptrace(PTRACE_CONT,recov_proc, NULL, NULL);
    pid_t parent  =  getpid();
    pid_t pid = fork();
   
    if (pid == -1)  {
        printf("Fork failed\n");
    } else if (pid > 0) {
        int status;
        wait(NULL);
        struct user_regs_struct recovRegs;
        FILE  *fp = fopen("regs","r");
        readAllRegs(fp,&readRegs);
        fclose(fp);
        ptrace(PTRACE_SETREGS,pid, NULL, &recovRegs)
        ptrace(PTRACE_CONT, pid, NULL, NULL);
        // waitpid(pid, &status, 0);
        // printf("Return Status of Child : %d\n", status);
    } else {
    // attempt to recover
    ptrace(PTRACE_TRACEME,0, NULL, NULL);
    // wait(NULL);
    FILE *pageMap = fopen("pagemaps","r");
    int code = open("code",O_RDONLY);
    long startAddr = 0;
    int noOfPages = 0;
    int protFlags = 0;
    int isPrivate = 0;
    int pageLength = 4096;
    int offset = 0;
    unsigned char *page;
    char *addr;
    printf("Started mapping\n");
    while (EOF != fscanf(pageMap, "%lx %d %d %d\n",&startAddr, &noOfPages, &protFlags, &isPrivate)) {
        for (int i = 0; i < noOfPages; ++i) {
            addr = mmap(&startAddr,pageLength,protFlags,isPrivate,code,offset);
            if (addr == MAP_FAILED) {
                printf("MMAP error\n");
            }
            offset += pageLength;
        }
    }
    fclose(pageMap);
    printf("Done mapping\n");

    // read size of code, data_r and data_wr segments
    // FILE *sizeFile = fopen("size","r");
    // printf("Reading Size file :\n");
    // long codeSize;
    // long dataRSize;
    // long dataWRSize;

    // fread(&codeSize, 1, sizeof(long), sizeFile);
    // fread(&dataRSize, 1, sizeof(long), sizeFile);
    // fread(&dataWRSize, 1, sizeof(long), sizeFile);

    // fclose(sizeFile);

    // struct user_regs_struct recovRegs;
    //  FILE  *regFp;
    //     regFp = fopen("regs","r");
    // ptrace(PTRACE_GETREGS,recov_proc,NULL, &recovRegs);
    // printf("Reading regs \n");
    // //readAllRegs(regFp,&recovRegs);
    // fclose(regFp);
   
    // // // set eip to start of the CS
    // long ptr,begin;
    // ptr = begin = recovRegs.rsp - codeSize;
    // recovRegs.rip = begin; 
    // ptrace(PTRACE_SETREGS, recov_proc, NULL, &recovRegs);

    // printf("%ld\n", codeSize);
    // FILE* code = fopen("code","r");

    // unsigned char *page = (unsigned char *)malloc(sizeof(unsigned char) * codeSize);
    

    // long rCodeSize = fread(page,sizeof(unsigned char), codeSize,code);
    // if (rCodeSize != codeSize)
    //     printf("Code memory read error\n");

    // //putdata(recov_proc,(recovRegs.rip * 4),page,codeSize);
    // ptrace(PTRACE_POKEDATA, recov_proc, begin, page);
 
    // free(page);    
    // fclose(code);

    // ptrace(PTRACE_DETACH,recov_proc, NULL, NULL);
    //     long buf;
    //      while (!feof(sizeFile)) {
    //         fread(&buf, 1, sizeof(long), sizeFile);
    //         printf("%ld\n", buf);
    //     }   
    // fclose(sizeFile);
    }

    


    // remove all temp files created for checkpointing
    // remove("regs");
    // remove("code");
    // remove("data_r");
    // remove("data_wr");
    // remove("size");
    // remove("sigmask");

    return 0;
}
