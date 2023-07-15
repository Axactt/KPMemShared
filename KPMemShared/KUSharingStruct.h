#pragma once
#include"Globals.h"

// read struct to read from a user-mode process memory
typedef struct _KM_READ_REQUEST
{
	ULONG ProcessId;
	UINT_PTR SourceAddress;
	ULONGLONG Size;
	void* Output;
}KM_READ_REQUEST;

// write struct to write to a target process id
typedef struct _KM_WRITE_REQUEST
{
	ULONG ProcessId;
	ULONG ProcessIdOfSource;
	UINT_PTR SourceAddress;
	UINT_PTR TargetAddress;
	ULONGLONG Size;

}KM_WRITE_REQUEST;

// GET Module struct

typedef struct _GET_USERMODULE_IN_PROCESS
{
	ULONG pid;
	ULONG64	BaseAddress;
}; _GET_USERMODULE_IN_PROCESS;

