#include "Main.h"

FnNtQueryInformationProcess			g_NtQueryInformationProcess;
FnNtSetInformationThread			g_NtSetInformationThread;
FnNtClose							g_NtClose;
FnNtQuerySystemInformation			g_NtQuerySystemInformation;
FnNtQueryInformationThread			g_NtQueryInformationThread;

VOID __fastcall InfHookCallback(unsigned long SystemCallIndex, void** SystemCallFunction) {
	UNREFERENCED_PARAMETER(SystemCallIndex);

	if (*SystemCallFunction == g_NtQueryInformationProcess)
		*SystemCallFunction = HkNtQueryInformationProcess;
	else if (*SystemCallFunction == g_NtSetInformationThread)
		*SystemCallFunction = HkNtSetInformationThread;
	else if (*SystemCallFunction == g_NtClose)
		*SystemCallFunction = HkFnNtClose;
	else if (*SystemCallFunction == g_NtQuerySystemInformation)
		*SystemCallFunction = HkNtQuerySystemInformation;
	else if (*SystemCallFunction == g_NtQueryInformationThread)
		*SystemCallFunction = HkNtQueryInformationThread;

}

extern "C" NTSTATUS DriverEntry(DRIVER_OBJECT* pDriver, UNICODE_STRING* pRegistryPath) {
	UNREFERENCED_PARAMETER(pDriver);
	UNREFERENCED_PARAMETER(pRegistryPath);

	NTSTATUS status = STATUS_SUCCESS;
	pDriver->DriverUnload = DrvUnload;
	DbgPrintEx(0, 0, "[ADF] Driver loaded.\n");

	UNICODE_STRING szFnNtQueryInformationProcess = RTL_CONSTANT_STRING(L"NtQueryInformationProcess");
	g_NtQueryInformationProcess = (FnNtQueryInformationProcess)MmGetSystemRoutineAddress(&szFnNtQueryInformationProcess);
	KdPrintEx((0, 0, "[ADF] NtQueryInformation Address: %p\n", g_NtQueryInformationProcess));
	
	UNICODE_STRING szFnNtSetInformationThread = RTL_CONSTANT_STRING(L"NtSetInformationThread");
	g_NtSetInformationThread = (FnNtSetInformationThread)MmGetSystemRoutineAddress(&szFnNtSetInformationThread);
	KdPrintEx((0, 0, "[ADF] NtSetInformationThread Address: %p\n", g_NtSetInformationThread));
	
	UNICODE_STRING szFnNtClose = RTL_CONSTANT_STRING(L"NtClose");
	g_NtClose = (FnNtClose)MmGetSystemRoutineAddress(&szFnNtClose);
	KdPrintEx((0, 0, "[ADF] NtClose Address: %p\n", g_NtClose));
	
	UNICODE_STRING szFnNtQuerySystemInformation = RTL_CONSTANT_STRING(L"NtQuerySystemInformation");
	g_NtQuerySystemInformation = (FnNtQuerySystemInformation)MmGetSystemRoutineAddress(&szFnNtQuerySystemInformation);
	KdPrintEx((0, 0, "[ADF] NtQuerySystemInformation Address: %p\n", g_NtQuerySystemInformation));

	UNICODE_STRING szFnNtQueryInformationThread = RTL_CONSTANT_STRING(L"NtQueryInformationThread");
	g_NtQueryInformationThread = (FnNtQueryInformationThread)MmGetSystemRoutineAddress(&szFnNtQueryInformationThread);
	KdPrintEx((0, 0, "[ADF] NtQueryInformationThread Address: %p\n", g_NtQueryInformationThread));


	if (g_NtQueryInformationProcess && g_NtSetInformationThread) {
		if (k_hook::initialize(InfHookCallback)) {
			DbgPrintEx(0, 0, "[ADF] Hook initialized.\n");
			if (k_hook::start()) {
				DbgPrintEx(0, 0, "[ADF] Hook started.\n");
				return STATUS_SUCCESS;
			}
			else {
				DbgPrintEx(0, 0, "[ADF] Hook start failed.\n");
				return STATUS_UNSUCCESSFUL;
			}
		}
		else {
			DbgPrintEx(0, 0, "[ADF] Hook initialize failed.\n");
			return status;
		}
	}

	DbgPrintEx(0, 0, "[ADF] Cannot get the function address.\n");
	return STATUS_UNSUCCESSFUL;
}

VOID DrvUnload(DRIVER_OBJECT* pDriver) {
	UNREFERENCED_PARAMETER(pDriver);

	k_hook::stop();
	DbgPrintEx(0, 0, "[ADF] Hook stopped.\n");
	DbgPrintEx(0, 0, "[ADF] Driver Unloaded.\n");
}

BOOLEAN IsCurrentProcessTargetProcess() {
	if (ExGetPreviousMode() != UserMode)
		return FALSE;
	UCHAR* procFileName = PsGetProcessImageFileName(PsGetCurrentProcess());
	return RtlEqualMemory((LPCSTR)procFileName, DebugTargetPrefix, strlen(DebugTargetPrefix));
}

NTSTATUS NTAPI HkNtQueryInformationProcess(
	IN HANDLE ProcessHandle,
	IN PROCESSINFOCLASS InformationClass,
	OUT PVOID ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength OPTIONAL
) {
	
	if (!IsCurrentProcessTargetProcess())
		goto origin;

	if (ProcessInformationLength != 0) {
		__try {
			ProbeForRead(ProcessInformation, ProcessInformationLength, 4);
			if (ReturnLength != 0)
				ProbeForWrite(ReturnLength, 4, 1);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			DbgPrintEx(0, 0, "[ADF] NtQueryInformationProcess ProbeForRead/Write failed. Code: %X\n", GetExceptionCode());
			return GetExceptionCode();
		}
	}

	if (InformationClass == ProcessDebugPort) {

		DbgPrintEx(0, 0, "[ADF] NtQueryInformationProcess ProcessDebugPort Hit.\n");

		__try {
			*(ULONG64*)ProcessInformation = 0;
			if (ReturnLength)
				*ReturnLength = sizeof(ULONG64);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			return GetExceptionCode();
		}
		
		return STATUS_SUCCESS;
	}
	else if (InformationClass == ProcessDebugObjectHandle) {

		DbgPrintEx(0, 0, "[ADF] NtQueryInformationProcess ProcessDebugObjectHandle Hit.\n");
		
		__try {
			*(ULONG64*)ProcessInformation = 0;
			if (ReturnLength)
				*ReturnLength = sizeof(ULONG64);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			return GetExceptionCode();
		}

		return STATUS_PORT_NOT_SET;
	}
	else if (InformationClass == ProcessDebugFlags) {
		
		DbgPrintEx(0, 0, "[ADF] NtQueryInformationProcess ProcessDebugFlags Hit.\n");

		__try {
			*(ULONG*)ProcessInformation = 0;
			if (ReturnLength)
				*ReturnLength = sizeof(ULONG);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			DbgPrintEx(0, 0, "[ADF] Fail to handle NtQueryInformationProcess ProcessDebugFlags. Code: %X\n", GetExceptionCode());
			return GetExceptionCode();
		}

		return STATUS_SUCCESS;
	}
	else if (InformationClass == ProcessBreakOnTermination) {
		
		DbgPrintEx(0, 0, "[ADF] NtQueryInformationProcess ProcessBreakOnTermination Hit.\n");

		__try {
			*(ULONG*)ProcessInformation = 0;
			if (ReturnLength)
				*ReturnLength = sizeof(ULONG);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			DbgPrintEx(0, 0, "[ADF] Fail to handle NtQueryInformationProcess ProcessBreakOnTermination. Code: %X\n", GetExceptionCode());
			return GetExceptionCode();
		}

		return STATUS_SUCCESS;
	}

origin:
	return g_NtQueryInformationProcess(ProcessHandle, InformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
}

NTSTATUS NTAPI HkNtSetInformationThread(
	IN HANDLE ThreadHandle,
	IN THREADINFOCLASS ThreadInformaitonClass,
	IN PVOID ThreadInformation,
	IN ULONG ThreadInformationLength
) {

	if (!IsCurrentProcessTargetProcess())
		goto origin;
	
	if (ThreadInformaitonClass == ThreadHideFromDebugger) {

		DbgPrintEx(0, 0, "[ADF] NtSetInformationThread ThreadHideFromDebugger Hit.\n");
		
		ThreadInformaitonClass = ThreadBasePriority;
		goto origin;
	}

origin:
	return g_NtSetInformationThread(ThreadHandle, ThreadInformaitonClass, ThreadInformation, ThreadInformationLength);
}

NTSTATUS NTAPI HkFnNtClose(
	IN HANDLE Handle
) {

	if (!IsCurrentProcessTargetProcess())
		goto origin;
	
	if (Handle == (HANDLE)0xDEADC0DE) {

		DbgPrintEx(0, 0, "[ADF] NtClose 0xDEADC0DE Hit.\n");

		Handle = 0;
		goto origin;
	}

origin:
	return g_NtClose(Handle);
}

NTSTATUS NTAPI HkNtQuerySystemInformation(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
) {

	if (!IsCurrentProcessTargetProcess())
		goto origin;
		
	if (SystemInformationClass == SystemKernelDebuggerInformation
		|| SystemInformationClass == SystemKernelDebuggerInformationEx
		|| SystemInformationClass == SystemCodeIntegrityInformation
		|| SystemInformationClass == ProcessDebugObjectHandle
		) {
		
		switch (SystemInformationClass) {
		case SystemKernelDebuggerInformation:
			DbgPrintEx(0, 0, "[ADF] NtQuerySystemInformation SystemKernelDebuggerInformation Hit.\n");
			break;
		case SystemKernelDebuggerInformationEx:
			DbgPrintEx(0, 0, "[ADF] NtQuerySystemInformation SystemKernelDebuggerInformationEx Hit.\n");
			break;
		case SystemCodeIntegrityInformation:
			DbgPrintEx(0, 0, "[ADF] NtQuerySystemInformation SystemCodeIntegrityInformation Hit.\n");
			break;
		default:
			DbgPrintEx(0, 0, "[ADF] NtQuerySystemInformation ProcessDebugObjectHandle Hit.\n");
			break;
		}

		return STATUS_UNSUCCESSFUL;

	}

origin:
	return g_NtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
}

NTSTATUS NTAPI HkNtQueryInformationThread(
	HANDLE          ThreadHandle,
	THREADINFOCLASS ThreadInformationClass,
	PVOID           ThreadInformation,
	ULONG           ThreadInformationLength,
	PULONG          ReturnLength
) {

	if (!IsCurrentProcessTargetProcess())
		goto origin;

	if (ThreadInformationLength != 0) {
		__try {
			ProbeForRead(ThreadInformation, ThreadInformationLength, 4);
			if (ReturnLength != 0)
				ProbeForWrite(ReturnLength, 4, 1);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			DbgPrintEx(0, 0, "[ADF] NtQueryInformationThread ProbeForRead/Write failed. Code: %X\n", GetExceptionCode());
			return GetExceptionCode();
		}
	}

	if (ThreadInformationClass == ThreadHideFromDebugger) {
		
		DbgPrintEx(0, 0, "[ADF] NtQueryInformationThread ThreadHideFromDebugger Hit.\n");

		__try {
			*(BOOLEAN*)ThreadInformation = FALSE;
			if (ReturnLength)
				*ReturnLength = sizeof(BOOLEAN);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			DbgPrintEx(0, 0, "[ADF] Fail to handle NtQueryInformationThread ThreadHideFromDebugger. Code: %X\n", GetExceptionCode());
			return GetExceptionCode();
		}

		return STATUS_SUCCESS;
	}

origin:
	return g_NtQueryInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength);
}
