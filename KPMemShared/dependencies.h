#pragma once
#include<ntdef.h>
#include<ntifs.h> 
#include<Ntstrsafe.h> 
#include<windef.h> //!  Basic Windows Type Definitions  



// !API function from ntoskrnl.exe which we use
// ! to copy memory to and from an user process.
//? for i/o devices mapped memory space mmio-decices use MmMapIoSpace

extern "C"
NTSTATUS NTAPI MmCopyVirtualMemory

(
	PEPROCESS SourceProcess, //! pointer to _KPROCESS OR _EPROCESS struct named as Pcb
	PVOID SourceAddress,
	PEPROCESS TargetProcess,
	PVOID TargetAddress,
	SIZE_T BufferSize,
	KPROCESSOR_MODE PreviousMode,
	PSIZE_T ReturnSize
);

extern "C"
NTKERNELAPI  //!means  __declspec(dllimport) function/object is imported or exportedd by DLL
NTSTATUS
PsLookupProcessByProcessId(
	_In_ HANDLE ProcessId,
	_Out_ PEPROCESS* Process

);

extern "C"
NTKERNELAPI
PPEB
PsGetProcessPeb(
	_In_  PEPROCESS Process
);

extern "C"
NTSTATUS ZwQuerySystemInformation(ULONG InfoClass, PVOID Buffer, ULONG Length, PULONG ReturnLength);

// !Compond object by EXECutive for synchronization
//!  Threads that contend for access to some protected resource call functions that acquire and release the ERESOURCE. A contending thread may require exclusive access or be satisfied to share its access
extern "C"
NTKERNELAPI ERESOURCE PsLoadedModuleResource;

//?? redefiniton from Dependencies.h
extern "C"
NTSTATUS ZwQuerySystemInformation(ULONG InfoClass, PVOID Buffer, ULONG Length, PULONG ReturnLength);


void driverUnload(_In_ PDRIVER_OBJECT pdriverObject);
NTSTATUS CreateCall(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS CloseCall(PDEVICE_OBJECT DeviceObject, PIRP Irp);

//! to get Nt_HEADRS 
extern "C"
NTSYSAPI //expands to __declspec(dllimport)
PIMAGE_NT_HEADERS
NTAPI  //expands to __stdcall
RtlImageNtHeader(PVOID Base);
