#pragma once
#include<ntifs.h> //! defines the NT types, constants, and functions that are exposed to file system drivers.
#include<windef.h> //!  Basic Windows Type Definitions
#include<Ntstrsafe.h> 
typedef struct _PEB_LDR_DATA
{
	ULONG Length;
	BOOLEAN Initiaized;
	PVOID SsHandle;
	LIST_ENTRY ModuleListLoadOrder;
	LIST_ENTRY ModuleListMemoryOrder;
	LIST_ENTRY ModuleListInitOrder;
}PEB_LDR_DATA, *PPEB_LDR_DATA;


//! low-level packaging of the numerous arguments and parameters that can be specified to such Win32 API functions as CreateProcess.NtCreateUserProcess and ZwCreateUserProcess
typedef struct _RTL_USER_PROCESS_PARAMETERS
{
	BYTE Reserved1[16];
	PVOID Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
}RTL_USER_PROCESS_PARAMETERS,*PRTL_USER_PROCESS_PARAMETERS;

typedef void(__stdcall* PPS_POST_PROCESS_INIT_ROUTINE)(void); //! not exported; Field of _PEB

typedef struct _PEB  //! at gs[0x60]; offset 
{
	BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[1];
	PVOID Reserved3[2];
	PPEB_LDR_DATA Ldr;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID Reserved4[3];
	PVOID AtlThunkSListPtr;
	PVOID Reserved5;
	ULONG Reserved6;
	PVOID Reserved7;
	ULONG Reserved8;
	ULONG AtlThunkSListPtr32;
	PVOID Reserved9[45];
	BYTE Reserved10[96];
	PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
	BYTE Reserved11[128];
	PVOID Reserved12[1];
	ULONG SessionId;
} PEB, * PPEB;

//! NTDLL’s record of how a DLL is loaded into a process
//! More stable structure than _PEB_LOADER_DATA for conbating information on loaded modules
typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;  // in bytes
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;  //! LDR_*These might be just an internal detail of the boot loader’s, the kernel’s and NTDLL’s management of loaded modules
	USHORT LoadCount; //!, the LoadCount member of this structure is the DLL reference count for laoding unloading. 
	USHORT TlsIndex;
	LIST_ENTRY HashLinks;
	PVOID SectionPointer;
	ULONG CheckSum;
	ULONG TimeDateStamp;
	//    PVOID			LoadedImports;
	//    // seems they are exist only on XP !!! PVOID
	//    EntryPointActivationContext;	// -same-
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;


//!an enumeration whose values are intended as input to the ZwQuerySystemInformation, ZwQuerySystemInformationEx and ZwSetSystemInformation functions (also names begin with Nt ). Different values from the enumeration select different types of information to query or set.
typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation = 0x0B
} SYSTEM_INFORMATION_CLASS,
* PSYSTEM_INFORMATION_CLASS;

//PIDDBCacheEntry struct

typedef struct PIDDBCacheEntry
{
	LIST_ENTRY List;
	UNICODE_STRING DriverName;
	ULONG TimeDateStamp;
	NTSTATUS LoadStatus;
	char _0x0028[16]; //data from the shim engine or uninitialized memory for custom drivers
} PIDCacheobj;

//BBsCAN SECTION structs

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES        16

typedef struct _IMAGE_DATA_DIRECTORY
{
	ULONG VirtualAddress;
	ULONG Size;
} IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER64
{
	USHORT Magic;
	UCHAR MajorLinkerVersion;
	UCHAR MinorLinkerVersion;
	ULONG SizeOfCode;
	ULONG SizeOfInitializedData;
	ULONG SizeOfUninitializedData;
	ULONG AddressOfEntryPoint;
	ULONG BaseOfCode;
	ULONGLONG ImageBase;
	ULONG SectionAlignment;
	ULONG FileAlignment;
	USHORT MajorOperatingSystemVersion;
	USHORT MinorOperatingSystemVersion;
	USHORT MajorImageVersion;
	USHORT MinorImageVersion;
	USHORT MajorSubsystemVersion;
	USHORT MinorSubsystemVersion;
	ULONG Win32VersionValue;
	ULONG SizeOfImage;
	ULONG SizeOfHeaders;
	ULONG CheckSum;
	USHORT Subsystem;
	USHORT DllCharacteristics;
	ULONGLONG SizeOfStackReserve;
	ULONGLONG SizeOfStackCommit;
	ULONGLONG SizeOfHeapReserve;
	ULONGLONG SizeOfHeapCommit;
	ULONG LoaderFlags;
	ULONG NumberOfRvaAndSizes;
	struct _IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, * PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_FILE_HEADER // Size=20
{
	USHORT Machine;
	USHORT NumberOfSections;
	ULONG TimeDateStamp;
	ULONG PointerToSymbolTable;
	ULONG NumberOfSymbols;
	USHORT SizeOfOptionalHeader;
	USHORT Characteristics;
}IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;

typedef struct _IMAGE_NT_HEADERS64
{
	ULONG Signature;
	struct _IMAGE_FILE_HEADER FileHeader; // NOT POINTED TO BUT EMBEDDED STRUCTS
	struct _IMAGE_OPTIONAL_HEADER64 OptionalHeader;// NOT POINTED TO BUT EMBEDDED STRUCTS
}IMAGE_NT_HEADERS64, * PIMAGE_NT_HEADERS64;

typedef struct _IMAGE_SECTION_HEADER
{
	UCHAR Name[8];
	union
	{
		ULONG PhysicalAddress;
		ULONG VirtualSize;

	}Misc;
	ULONG VirtualAddress;
	ULONG SizeOfRawData;
	ULONG PointerToRawData;
	ULONG PointerToRelocations;
	ULONG PointerToLIneNumbers;
	USHORT NumberOfRelocations;
	USHORT NumberOfLineNumbers;
	ULONG Characteristics;
}  IMAGE_SECTION_HEADER, * PIMAGE_SECTION_HEADER;

//Random Native structs


typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
}RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
}RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

//MmUnload structs

#define MM_UNOADED_DRIVERS_SIZE 50 // maybe number of entry of unloaded drivers

typedef struct _MM_UNLOADED_DRIVER
{
	UNICODE_STRING Name;
	PVOID ModuleStart;
	PVOID ModuleEnd;
	ULONG64 UnloadTime;
} MM_UNLOADED_DRIVER, * PMM_UNLOADED_DRIVER;

//! to get Nt_HEADRS 
extern "C"
NTSYSAPI //expands to __declspec(dllimport)
PIMAGE_NT_HEADERS
NTAPI  //expands to __stdcall
RtlImageNtHeader(PVOID Base);


