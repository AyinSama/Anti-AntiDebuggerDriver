#pragma once
#include "hook.hpp"

constexpr char DebugTargetPrefix[] = "target";

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemKernelDebuggerInformation = 0x23,
	SystemCodeIntegrityInformation = 0x67,
	SystemKernelDebuggerInformationEx = 0x95
} SYSTEM_INFORMATION_CLASS;

typedef NTSTATUS (NTAPI* FnNtQueryInformationProcess)(
	IN HANDLE ProcessHandle,
	IN PROCESSINFOCLASS InformationClass,
	OUT PVOID ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength OPTIONAL
);

typedef NTSTATUS (NTAPI* FnNtSetInformationThread)(
	IN HANDLE ThreadHandle,
	IN THREADINFOCLASS ThreadInformaitonClass,
	IN PVOID ThreadInformation,
	IN ULONG ThreadInformationLength
);

typedef NTSTATUS (NTAPI* FnNtClose)(
	IN HANDLE Handle
);

typedef NTSTATUS (NTAPI* FnNtQuerySystemInformation)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
);

typedef NTSTATUS (NTAPI* FnNtQueryInformationThread)(
	HANDLE          ThreadHandle,
	THREADINFOCLASS ThreadInformationClass,
	PVOID           ThreadInformation,
	ULONG           ThreadInformationLength,
	PULONG          ReturnLength
);

extern "C" NTKERNELAPI UCHAR * PsGetProcessImageFileName(__in PEPROCESS Process);
VOID __fastcall InfHookCallback(unsigned long SystemCallIndex, void** SystemCallFunction);
extern "C" NTSTATUS DriverEntry(DRIVER_OBJECT* pDriver, UNICODE_STRING* pRegistryPath);
VOID DrvUnload(DRIVER_OBJECT* pDriver);
BOOLEAN IsCurrentProcessTargetProcess();

NTSTATUS NTAPI HkNtQueryInformationProcess(
	IN HANDLE ProcessHandle,
	IN PROCESSINFOCLASS InformationClass,
	OUT PVOID ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength OPTIONAL
);

NTSTATUS NTAPI HkNtSetInformationThread(
	IN HANDLE ThreadHandle,
	IN THREADINFOCLASS ThreadInformaitonClass,
	IN PVOID ThreadInformation,
	IN ULONG ThreadInformationLength
);

NTSTATUS NTAPI HkFnNtClose(
	IN HANDLE Handle
);

NTSTATUS NTAPI HkNtQuerySystemInformation(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
);

NTSTATUS NTAPI HkNtQueryInformationThread(
	HANDLE          ThreadHandle,
	THREADINFOCLASS ThreadInformationClass,
	PVOID           ThreadInformation,
	ULONG           ThreadInformationLength,
	PULONG          ReturnLength
);
