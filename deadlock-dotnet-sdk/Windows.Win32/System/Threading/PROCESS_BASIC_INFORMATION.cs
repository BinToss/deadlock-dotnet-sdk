/// This file supplements code generated by CsWin32
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using PInvoke;
using Win32Exception = System.ComponentModel.Win32Exception;

namespace Windows.Win32.System.Threading;

/// <summary>This struct is not fully emitted by Win32Metadata. The definition in ntddk.h of Windows SDK 10.0.22621.0 has many more documented fields which are included in this manual definition
/// See https://github.com/winsiderss/systeminformer@master/-/blob/phnt/include/ntpsapi.h
/// </summary>
public readonly struct PROCESS_BASIC_INFORMATION
{
    public NTSTATUS ExitStatus { get; }
    /// <summary>
    /// The address of the PEB relative to its process's memory. Read object via <see cref="Peb"/>
    /// </summary>
    public unsafe PEB* PebBaseAddress { get; }
    public UIntPtr AffinityMask { get; }
    public KPRIORITY BasePriority { get; }
    private readonly nuint uniqueProcessId;
    private readonly UIntPtr inheritedFromUniqueProcessId;

    /// <summary>The process's ID. Backed by a pointer-sized integer field.</summary>
    public uint ProcessId => (uint)uniqueProcessId;
    /// <summary>The ID of the parent process. Backed by a pointer-sized unsigned integer field.</summary>
    public uint ParentProcessId => (uint)inheritedFromUniqueProcessId;

    /// <summary>
    /// Create an instance of PROCESS_BASIC_INFORMATION with data acquired by passing
    /// a handle for a process with the PROCESS_VM_READ and
    /// PROCESS_QUERY_LIMITED_INFORMATION rights to NtQueryInformationProcess
    /// </summary>
    /// <param name="hProcess">A Process handle with the PROCESS_VM_READ and PROCESS_QUERY_LIMITED_INFORMATION rights. This handle must remain open for the PEB pointer to be readable.</param>
    /// <remarks>If UniqueProcessId does not match the current process's ID, read all pointers with NtQueryVirtualMemory</remarks>
    /// <exception cref="NTStatusException">NtQueryInformationProcess returned an error code</exception>
    // TODO: wrap in object containing an object of this Type, a process handle for NtQueryVirtualMemory, and a wrapper method for calling that function
    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntqueryvirtualmemory
    public PROCESS_BASIC_INFORMATION(SafeProcessHandle hProcess)
    {
        NTSTATUS status;
        uint returnLength = default;
        unsafe
        {
            fixed (PROCESS_BASIC_INFORMATION* pThis = &this)
                status = PInvoke.NtQueryInformationProcess(hProcess, PROCESSINFOCLASS.ProcessBasicInformation, pThis, (uint)Marshal.SizeOf(this), ref returnLength);
        }

        status.ThrowOnError();
    }

    /// <summary>
    /// Get a SafeProcessHandle with rights suitable for accessing PEB pointers via NtQueryVirtualMemory
    /// </summary>
    /// <param name="processId"></param>
    /// <returns></returns>
    /// <exception cref="Win32Exception">Failed to open Handle to process with VM_READ and QUERY_LIMITED_INFORMATION rights</exception>
    public static SafeProcessHandle GetProcessHandle(uint processId)
    {
        try
        {
            if (!PInvoke.IsDebugModeEnabled())
                Process.EnterDebugMode();
        }
        catch (Win32Exception)
        { }

        var hProcess = PInvoke.OpenProcess(PROCESS_ACCESS_RIGHTS.PROCESS_VM_READ | PROCESS_ACCESS_RIGHTS.PROCESS_QUERY_LIMITED_INFORMATION, true, processId);

        if (hProcess.IsNull)
            throw new Win32Exception();
        else
            return new SafeProcessHandle(hProcess, true);
    }

    /// <summary>
    /// Invoke ReadProcessMemory to copy the target process's PEB to our memory
    /// </summary>
    /// <value></value>
    /// <exception cref="Win32Exception">Failed to read process memory. Check Win32 error and message for more info.</exception>
    public unsafe PEB GetPeb()
    {
        if (ProcessId == Environment.ProcessId)
            return *PebBaseAddress;

        SafeProcessHandle hProcess = GetProcessHandle(ProcessId);
        PEB peb;
        nuint bytesRead;
        return !PInvoke.ReadProcessMemory(hProcess, PebBaseAddress, &peb, (nuint)Marshal.SizeOf<PEB>(), &bytesRead)
            ? throw new Win32Exception()
            : peb;
    }

    public unsafe PEB_Ex GetPebEx() => new(ProcessId, GetPeb());
}
