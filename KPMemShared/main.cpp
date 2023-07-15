#include"Globals.h" // for gloabals 
#include"dependencies.h"
#include"loop.h"
#include"NtStructs.h"
#include"KUSharingStruct.h"


VOID ReadSharedMemory()
{
	//!Handle to a section object. This handle is created by a successful call to ZwCreateSection 
	if (sectionHandle) //? why return when sectionHandle is non-null
		return;
	if (SharedSection) //!Pointer to a variable that receives the base address of the view
		ZwUnmapViewOfSection(NtCurrentProcess(), SharedSection);

	SIZE_T ulViewSize = 1024 * 10;//!Specifies the size, in bytes, of the initially committed region of the view. CommitSize is meaningful only for page-file backed sections and is rounded up to the nearest multiple of PAGE_SIZE.

	//! if the parameters might be from either a user-mode source or a kernel-mode source, the driver instead calls the Nt version of the routine, which determines, based on the history of the calling thread, whether the parameters originated in user mode or kernel mode(Zw vs Nt call version)

	NTSTATUS ntStatus = ZwMapViewOfSection(sectionHandle, NtCurrentProcess(), &SharedSection, 0, ulViewSize, NULL, &ulViewSize, ViewShare, 0, PAGE_READWRITE | PAGE_NOCACHE);
	if (ntStatus != STATUS_SUCCESS)
	{
		DbgPrintEx(0, 0, "ZwMapViewOfSection fail! Status: %p\n", ntStatus);
		ZwClose(sectionHandle);
		return;
	}

}

NTSTATUS CreateSharedMemory()
{
	NTSTATUS Status = STATUS_SUCCESS;


}