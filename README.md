# ghostwriting-2
A greatly improved version of the original [ghostwriting](https://github.com/c0de90e7/GhostWriting/blob/master/gw_ng.c) process injection technique, this technique is also able to inject threads using only `OpenThread`, `GetThreadContext`, `SetThreadContext`, `SuspendThread`, and `ResumeThread` APIs, without `WriteProcessMemory`, `CreateRemoteThread`, `QueueUserAPC`, or any common APIs for process injection. However, while the fundamental mechanism is similar, the whole implementations are rather different. Built for x86.

![image](https://github.com/lemond69/ghostwriting-2/assets/139056562/5b1a6df5-f688-479d-824a-a5ce4389f300)

## Method of action
First we select some gadgets. We will use `push edx; call eax` and `jmp $` gadgets. While the original ghostwriting uses `mov [reg1], reg2 ...... ret` gadgets, I find that far too overcomplicated as you need to basically implement an entire disassembler to find a good gadget. However, `push edx; call eax` is not the most reliable of gadgets, as some versions of Windows may not have the gadget in ntdll. It is definitely recommended to have this be generalized to any `push reg1; call reg2` gadgets (as we have observed Windows 8.1 to lack this gadget), but I feel it would overcomplicate the code for a simple POC, so you can implement it yourself if you need the support. The `jmp $` gadget, doesn't actually exist on it's own, but it is a part of a larger asm instruction, so it still works.

Then, we set the EIP to a `jmp $` and wait for thread to stop waiting for messages (blocking state). We know when it's ready when the usermode time from `GetThreadTimes` starts increasing steadily, indicating it's stuck in the `jmp $` instruction.

Now, we prepare the named pipe. We inject the pipe name into the stack, then call `CreateFileA` via a ROP, execute it, and we can obtain the handle of the pipe from victim process.

Then, we execute `VirtualAlloc` in victim, for a RW memory region, again getting the allocated memory address. Now we just prepare a `ReadFile` -> `CloseHandle` -> `VirtualProtect` -> `CreateThread` ROP sled, write the shellcode to be injected into the named pipe, then execute the ROP sled. We wait for this ROP sled to complete, then just restore the thread context to initial context.

## Improvements from original
Over the original ghostwriting technique, this technique has multiple differences:
- Uses only TID to inject, no HWND required. Means you can also inject background processes.
- No RWX memory is used. Original needs RWX, as you are executing off stack.
- Original thread is not sacrificed, can continue running
- Significantly less complicated, as gadget hunt is much simpler
- Significantly faster, especially for large shellcodes, as we just use named pipes instead of pushing shellcode to stack 4 bytes at a time. Shellcode size should not noticeably affect injection time, will not take like 10 minutes to inject a large shellcode.
- No shellcode size limit, stack limit of 1MB does not come into play as we use heap

## Compilation and usage
I used mingw gcc to compile, with `i686-w64-mingw32-gcc ghost.c -o ghost.exe`. Run with `ghost.exe [thread id]`

Injection of shellcode of arbitrary size should take <1s to complete. However, do note the program is effectively frozen for that time, and may be suspicious if you inject a GUI program.

This program has been fully tested on Windows 7 SP1 (build 7601) and Windows 10 22H2 (build 19045). It should also work on Windows 8 (build 9200) and Windows 11 (build 22621), but I do not expect it to work on 8.1 (build 9600).

## Credits
Original ghostwriting repo - https://github.com/c0de90e7/GhostWriting/
