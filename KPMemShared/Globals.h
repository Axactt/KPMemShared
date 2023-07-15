#pragma once
//! Various Globalvariables and declartaion for drivers function made here
#include<ntifs.h>
//x #include<ntdef.h>
//x #include<ntddk.h>
#include<windef.h> //!  Basic Windows Type Definitions   
#include<Ntstrsafe.h>  //! This module defines safer C library string  routine replacements for drivers.These aremeant to make C a bit more safe in reference to securityand robustness.A similar file, strsafe.h, is for applications.

const WCHAR SharedSectionName[] = L"\\BaseNamedObjects\\"; //aLLOCATE BUFFER for name of shared memory

PVOID pShardSection = NULL;
PVOID pSectionObj = NULL;
HANDLE hsection = NULL;



SECURITY_DESCRIPTOR SecDescriptor;
HANDLE sectionHandle; //!Handle to a section object. This handle is created by a successful call to ZwCreateSection 
PVOID SharedSection = NULL; //!Pointer to a variable that receives the base address of the view
PVOID Sharedoutputvar = NULL;
ULONG DaclLength;
PACL Dacl; // problem mentioned by author

// trigger driver loop
HANDLE SharedEventHandle_trigger = NULL;
PKEVENT SharedEvent_trigger = NULL;
UNICODE_STRING EventName_trigger;

//ReadyRead
HANDLE SharedEventHandle_ReadyRead = NULL;
PKEVENT SharedEvent_RaeyRead = NULL;
UNICODE_STRING EventName_trigger;

//data arrived as write data to hkernel driver
HANDLE SharedEventHandle_dt = NULL;
PKEVENT SharedEvent_dt = NULL;
UNICODE_STRING Eventname_dt; 



