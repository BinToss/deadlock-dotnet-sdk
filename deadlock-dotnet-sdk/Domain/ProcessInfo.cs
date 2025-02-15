using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using PInvoke;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.System.SystemInformation;
using Windows.Win32.System.Threading;
using static Windows.Win32.PInvoke;
using static Windows.Win32.PS_PROTECTION.PS_PROTECTED_TYPE;
using Code = PInvoke.NTSTATUS.Code;
using Env = System.Environment;
using NTSTATUS = Windows.Win32.Foundation.NTSTATUS;
using Win32Exception = PInvoke.Win32Exception;

namespace deadlock_dotnet_sdk.Domain;

public partial class ProcessInfo
{
    private bool canGetQueryLimitedInfoHandle;
    private bool canGetReadMemoryHandle;
    private (bool? v, Exception? ex) is32BitEmulatedProcess;
    private (int? v, Exception?) parentId;
    private (ProcessAndHostOSArch? arch, Exception? ex) processAndHostOSArch;
    private (ProcessBasicInformation? v, Exception? ex) processBasicInformation;
    private (string? v, Exception? ex) processCommandLine;
    private (ProcessQueryHandle? v, Exception? ex) processHandle;
    private (string? v, Exception? ex) processMainModulePath;
    private (string? v, Exception? ex) processName;
    private (PS_PROTECTION? v, Exception? ex) processProtection;
    private readonly int processId;

    internal ProcessInfo(int processId)
    {
        Process = null;
        this.processId = processId;
    }

    public ProcessInfo(Process process)
    {
        Process = process;
    }

    /// <summary>
    /// <para>
    ///     TRUE if the process is...<br/>
    ///     <ul>
    ///         <li>...running under WOW64 on an Intel64, x64, AMD64, or ARM64 processor.</li><br/>
    ///         <li>...a 32-bit application running under 64-bit Windows 10 on ARM.</li><br/>
    ///     </ul>
    /// </para>
    /// <para>
    ///     FALSE if the process is...<br/>
    ///     <ul>
    ///         <li>...running under 32-bit Windows.</li><br/>
    ///         <li>...a 64-bit application running under 64-bit Windows.</li><br/>
    ///     </ul>
    /// </para>
    /// </summary>
    /// <remarks>This property's P/Invoke of IsWow64Process(HANDLE, BOOL) requires a process handle with <see cref="PROCESS_ACCESS_RIGHTS.PROCESS_QUERY_INFORMATION"/> or <see cref="PROCESS_ACCESS_RIGHTS.PROCESS_QUERY_LIMITED_INFORMATION"/>.</remarks>
    public (bool? v, Exception? ex) Is32BitEmulatedProcess
    {
        get
        {
            if (is32BitEmulatedProcess is (null, null))
            {
                if (ProcessHandle.v is null)
                {
                    InvalidOperationException ex = new("Unable to query Is32BitEmulatedProcess; Failed to open a process handle with the necessary access.", processHandle.ex);
                    processAndHostOSArch = (null, ex);
                    return is32BitEmulatedProcess = (null, ex);
                }
                else if ((ProcessHandle.v.AccessRights & (PROCESS_ACCESS_RIGHTS.PROCESS_QUERY_INFORMATION | PROCESS_ACCESS_RIGHTS.PROCESS_QUERY_LIMITED_INFORMATION)) is 0)
                {
                    UnauthorizedAccessException ex = new("Unable to query Is32BitEmulatedProcess; A process handle was opened, but lacked the necessary access rights ", ProcessHandle.ex);
                    processAndHostOSArch = (null, ex);
                    return is32BitEmulatedProcess = (null, ex);
                }
                else if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 10586))
                {
                    unsafe
                    {
                        IMAGE_FILE_MACHINE pNativeMachine = default;
                        /** if UNKNOWN, then process architecture is the same as host architecture i.e. process is ARM64 and host is ARM64
                             * So, pProcessMachine will never be I386 or ARM when the host is either of those.
                             * Because the purpose of this property and function call is to determine if we need to use 32-bit or 64-bit definitions, we only care about the following return values:
                             *   IMAGE_FILE_MACHINE_UNKNOWN - The process is running natively. No emulation is taking place.
                             *   IMAGE_FILE_MACHINE_I386    - The process is running through an emulation layer. The host is probably either ARM64 or AMD64.
                             *   IMAGE_FILE_MACHINE_ARM     - The process is running through an emulation layer. The host is probably either ARM64 or AMD64. If it's a Windows ARM32 PE, then it's a UWP app.
                             */
                        if (IsWow64Process2(ProcessHandle.v.Handle, out IMAGE_FILE_MACHINE pProcessMachine, &pNativeMachine))
                        {
                            processAndHostOSArch = ((pProcessMachine, pNativeMachine), null);
                            return is32BitEmulatedProcess = (pProcessMachine is IMAGE_FILE_MACHINE.IMAGE_FILE_MACHINE_I386 or IMAGE_FILE_MACHINE.IMAGE_FILE_MACHINE_ARM, null);
                        }
                        else
                        {
                            Exception ex = new("Failed to query Is32BitEmulatedProcess.", new Win32Exception());
                            processAndHostOSArch = (null, ex);
                            return is32BitEmulatedProcess = (null, ex);
                        }
                    }
                }
                else if (!Windows.Win32.PInvoke.IsWow64Process(ProcessHandle.v.Handle, out BOOL IsWow64Process))
                {
                    return is32BitEmulatedProcess = (IsWow64Process, null);
                }
                else
                {
                    return is32BitEmulatedProcess = (null, new Win32Exception());
                }
            }
            else
            {
                return is32BitEmulatedProcess;
            }
        }
    }

    /// <summary>The base Process object this instance expands upon.</summary>
    public Process? Process { get; }

    public int ProcessId => Process?.Id ?? processId;

    /// <summary>
    /// The target ISA of the process and the ISA of the host OS.<br/>
    /// -OR-<br/>
    /// The exception thrown when attempting to get these values.
    /// </summary>
    /// <remarks>The value of this property is provided during Get accessor of Is32BitEmulatedProcess</remarks>
    public (ProcessAndHostOSArch? v, Exception? ex) ProcessAndHostOSArch
    {
        get
        {
            if (processAndHostOSArch is (null, null))
                _ = Is32BitEmulatedProcess;
            return processAndHostOSArch;
        }
    }

    public (ProcessQueryHandle? v, Exception? ex) ProcessHandle
    {
        get
        {
            if (processHandle is (null, null))
            {
                const string errUnableMsg = "Unable to open handle; ";
                // We can't lookup the ProcessProtection without opening a process handle to check the process protection.
                //PROCESS_ACCESS_RIGHTS access = ProcessProtection.v?.Type is PS_PROTECTION.PS_PROTECTED_TYPE.PsProtectedTypeProtected ? PROCESS_ACCESS_RIGHTS.PROCESS_QUERY_LIMITED_INFORMATION : PROCESS_ACCESS_RIGHTS.PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_ACCESS_RIGHTS.PROCESS_VM_READ;

                try
                {
                    ProcessQueryHandle h = ProcessQueryHandle.OpenProcessHandle(ProcessId, PROCESS_ACCESS_RIGHTS.PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_ACCESS_RIGHTS.PROCESS_VM_READ);
                    canGetQueryLimitedInfoHandle = true;
                    canGetReadMemoryHandle = true;
                    return processHandle = (h, null);
                }
                catch (Win32Exception ex) when (ex.NativeErrorCode is Win32ErrorCode.ERROR_ACCESS_DENIED)
                {
                    // Before assuming anything, try without PROCESS_VM_READ. Without it, we don't need Debug privilege, but the PEB and all of its recursive members (e.g. Command Line) will be unavailable.
                    const string exAccessMsg = errUnableMsg + " The requested permissions were denied.";
                    const string exPermsFirst = "\r\nFirst attempt's requested permissions: " + nameof(PROCESS_ACCESS_RIGHTS.PROCESS_QUERY_LIMITED_INFORMATION) + ", " + nameof(PROCESS_ACCESS_RIGHTS.PROCESS_VM_READ);

                    try
                    {
                        ProcessQueryHandle h = ProcessQueryHandle.OpenProcessHandle(ProcessId, PROCESS_ACCESS_RIGHTS.PROCESS_QUERY_LIMITED_INFORMATION);
                        canGetQueryLimitedInfoHandle = true;
                        return processHandle = (h, null);
                    }
                    catch (Win32Exception ex2) when (ex.NativeErrorCode is Win32ErrorCode.ERROR_ACCESS_DENIED)
                    {
                        // Debug Mode could not be enabled? Was SE_DEBUG_NAME denied to user or is current process not elevated?
                        const string exPermsSecond = "\r\nSecond attempt's requested permissions: " + nameof(PROCESS_ACCESS_RIGHTS.PROCESS_QUERY_LIMITED_INFORMATION);
                        return processHandle = (null, new UnauthorizedAccessException(exAccessMsg + exPermsFirst + exPermsSecond, ex2));
                    }
                    catch (Exception ex2)
                    {
                        return processHandle = (null, new AggregateException(errUnableMsg + " Permissions were denied and an unknown error occurred.", new Exception[] { ex, ex2 }));
                    }
                }
                catch (Win32Exception ex) when (ex.NativeErrorCode is Win32ErrorCode.ERROR_INVALID_PARAMETER)
                {
                    return processHandle = (null, new ArgumentException(errUnableMsg + " A process with ID " + ProcessId + " could not be found. The process may have exited.", ex));
                }
                catch (Exception ex)
                {
                    // unknown error
                    return processHandle = (null, new Exception(errUnableMsg + " An unknown error occurred.", ex));
                }
            }
            else
            {
                return processHandle;
            }
        }
    }

    /// <summary>
    /// Using a SafeProcessHandle with PROCESS_QUERY_LIMITED_INFORMATION access, copy the target process's PROCESS_BASIC_INFORMATION.<br/>
    /// If the operation succeeds and SafeProcessHandle also has PROCESS_READ_VM access, additional data (e.g. CommandLine) is copied.
    /// </summary>
    /// TODO: implement custom Exception types
    public unsafe void GetPropertiesViaProcessHandle()
    {
        if (ProcessHandle.v is null || ProcessHandle.ex is not null)
        {
            var ex = new Exception("Unable to query process info; Failed to open a process handle with the necessary access rights.", ProcessHandle.ex);
            processBasicInformation = (null, ex);
            parentId = (null, ex);
            processCommandLine = (null, ex);
            return;
        }

        canGetQueryLimitedInfoHandle = (ProcessHandle.v.AccessRights & PROCESS_ACCESS_RIGHTS.PROCESS_QUERY_LIMITED_INFORMATION) != 0;
        canGetReadMemoryHandle = (ProcessHandle.v.AccessRights & PROCESS_ACCESS_RIGHTS.PROCESS_VM_READ) != 0;

        if (!canGetQueryLimitedInfoHandle)
            throw new Exception("Unable to query process info with access right 'PROCESS_QUERY_LIMITED_INFORMATION'; The access right was denied to this process.");

        if (Is32BitEmulatedProcess.v is null || Is32BitEmulatedProcess.ex is not null)
            throw new Exception("Unable to query process's basic information; failed to determine process's targeted CPU architecture.", Is32BitEmulatedProcess.ex);

        // allocate one buffer large enough for either 64-bit or 32-bit interop.
        uint returnLength = 0;
        NTSTATUS status;

        /** If Win8.1 or later */

        if (OperatingSystem.IsWindowsVersionAtLeast(6, 3) && processCommandLine is (null, null))
        {
            try
            {
                const uint ProcessCommandLineInformation = 60u;
                uint bufferLength = (uint)Marshal.SizeOf<UNICODE_STRING>() + 2048u;
                using SafeBuffer<byte> bufferCmdLine = new(numBytes: bufferLength);

                status = NtQueryInformationProcess(
                    ProcessHandle.v,
                    (PROCESSINFOCLASS)ProcessCommandLineInformation,
                    (void*)bufferCmdLine.DangerousGetHandle(),
                    (uint)bufferCmdLine.ByteLength,
                    ref returnLength
                    );

                while ((status = NtQueryInformationProcess(ProcessHandle.v, (PROCESSINFOCLASS)ProcessCommandLineInformation, (void*)bufferCmdLine.DangerousGetHandle(), bufferLength, ref returnLength))
                    .Code is Code.STATUS_INFO_LENGTH_MISMATCH)
                {
#if DEBUG
                    Trace.TraceInformation(
                        "bufferLength: " + bufferCmdLine.ByteLength + "\r\n" +
                        "returnLength: " + returnLength);
#endif
                    // !WARNING may throw OutOfMemoryException; ReAllocHGlobal received a null pointer, but didn't check the error code
                    // the native call to LocalReAlloc (via Marshal.ReAllocHGlobal) sometimes returns a null pointer. This is a Legacy function. Why does .NET not use malloc/realloc?
                    if (returnLength < bufferCmdLine.ByteLength)
                        bufferCmdLine.Reallocate(numBytes: (nuint)(bufferCmdLine.ByteLength * 2));
                    else bufferCmdLine.Reallocate(numBytes: returnLength);
                    // none of these helped debug that internal error...
                    //var pinerr = Marshal.GetLastPInvokeError();
                    //var syserr = Marshal.GetLastSystemError();
                    //var winerr = Marshal.GetLastWin32Error();
                }

                processCommandLine = status.IsSuccessful
                    ? (bufferCmdLine.Read<UNICODE_STRING>(0).ToStringLength() ?? string.Empty, null)
                    : throw new NTStatusException(status); // thrown, not assigned. Is the stack trace assigned if the exception is not thrown?
            }
            catch (Exception ex)
            {
                processCommandLine = (null, ex);
            }
        }

        try
        {
            using SafeBuffer<byte> bufferPBI = new(numBytes: (uint)Marshal.SizeOf<PROCESS_BASIC_INFORMATION64>());
            /** // ! this code will break if the host or process architecture isn't ARM32, AARCH64 (ARM64), i386 (x86), or AMD64/x86_x64.
             *  IA64 (Intel Itanium) and ARMNT (ARM32 Thumb-2 Little Endian) are the most likely culprits.
             */
            /* Do we need to call NtWow64QueryInformationProcess64? */
            if (Env.Is64BitOperatingSystem && !Env.Is64BitProcess && Is32BitEmulatedProcess.v is false) // yes
            {
                while ((status = NtWow64QueryInformationProcess64(ProcessHandle.v, PROCESSINFOCLASS.ProcessBasicInformation, (void*)bufferPBI.DangerousGetHandle(), (uint)bufferPBI.ByteLength, &returnLength)).Code is Code.STATUS_INFO_LENGTH_MISMATCH or Code.STATUS_BUFFER_TOO_SMALL or Code.STATUS_BUFFER_OVERFLOW)
                {
                    if (returnLength < bufferPBI.ByteLength)
                        bufferPBI.Reallocate(numBytes: (nuint)(bufferPBI.ByteLength * 2));
                    else bufferPBI.Reallocate(numBytes: returnLength);
                }

                if (status.Code is not Code.STATUS_SUCCESS)
                    throw new NTStatusException(status, "NtWow64QueryInformationProcess64 failed to query a process's basic information; " + status.Message);

                processBasicInformation = (new ProcessBasicInformation(bufferPBI.Read<PROCESS_BASIC_INFORMATION64>(0)), null);
            }
            else
            {
                while ((status = NtQueryInformationProcess(ProcessHandle.v, PROCESSINFOCLASS.ProcessBasicInformation, (void*)bufferPBI.DangerousGetHandle(), (uint)bufferPBI.ByteLength, ref returnLength)).Code is Code.STATUS_INFO_LENGTH_MISMATCH or Code.STATUS_BUFFER_TOO_SMALL or Code.STATUS_BUFFER_OVERFLOW)
                {
                    if (returnLength < bufferPBI.ByteLength)
                        bufferPBI.Reallocate((nuint)(bufferPBI.ByteLength * 2));
                    else bufferPBI.Reallocate((returnLength is 0 ? returnLength = (uint)(Marshal.SizeOf<PROCESS_BASIC_INFORMATION64>() * 2) : returnLength) + (uint)IntPtr.Size);
                }

                if (status.Code is not Code.STATUS_SUCCESS)
                    throw new NTStatusException(status, "NtQueryInformationProcess failed to query a process's basic information; " + status.Message);

                if ((Env.Is64BitOperatingSystem && Is32BitEmulatedProcess.v is true) || (!Env.Is64BitOperatingSystem)) // that process is 32-bit
                    processBasicInformation = (new ProcessBasicInformation(bufferPBI.Read<PROCESS_BASIC_INFORMATION32>(0)), null);
                else
                    processBasicInformation = (new ProcessBasicInformation(bufferPBI.Read<PROCESS_BASIC_INFORMATION64>(0)), null);
            }
        }
        catch (Exception ex)
        {
            processBasicInformation = (null, ex);
        }

        if (processBasicInformation.v is not null)
        {
            /// fields/props to assign to if default and ProcessHandle has PROCESS_READ_VM:
            /// <see cref="parentId"/>, <see cref="processCommandLine"/>
            if (parentId is (null, null))
                parentId = ((int)processBasicInformation.v.ParentProcessId, null);

            // if any field requires PROCESS_READ_VM and ProcessHandle lacks it, assign the exception here.
            if (!canGetReadMemoryHandle)
            {
                try
                {
                    throw new UnauthorizedAccessException("Unable to copy process's PEB and child objects; Failed to open SafeProcessHandle with PROCESS_VM_READ access.", ProcessHandle.ex);
                }
                catch (Exception ex)
                {
                    if (processCommandLine is (null, null))
                        processCommandLine = (null, ex);
                }
            }
            else
            {
                try
                {
                    //var peb = processBasicInformation.v.GetPEB(ProcessHandle.v);
                    //var procParams = peb.GetUserProcessParameters(ProcessHandle.v);
                    var procParams = processBasicInformation.v.GetPEB(ProcessHandle.v).GetUserProcessParameters(ProcessHandle.v);

                    if (processCommandLine is (null, null))
                        processCommandLine = (procParams.GetCommandLine(ProcessHandle.v), null);
                }
                catch (Exception ex)
                {
                    if (processCommandLine is (null, null))
                        processCommandLine = (null, ex);
                }
            }
        }
        else
        {
            try
            {
                throw new NullReferenceException("Unable to retrieve data; This process's ProcessBasicInformation could not be retrieved.");
            }
            catch (Exception ex)
            {
                if (parentId is (null, null))
                    parentId = (null, ex);
                if (processCommandLine is (null, null))
                    processCommandLine = (null, ex);
            }
        }
    }

    /// <summary>
    /// The ID of the process that created/started this object's Process. Used for building tree-leaf UIs.<br/>
    /// Source: PROCESS_BASIC_INFORMATION (this.ProcessBasicInformation)
    /// </summary>
    /// <remarks>'v' will only be null for fake processes i.e. System Idle Process, Interrupts. Check if 'ex' is null to determine successful operation.</remarks>
    /// TODO: ProcessBasicInformation
    /// TODO: check field PROCESS_BASIC_INFORMATION.inheritedFromUniqueProcessId
    public (int? v, Exception? ex) ParentId
    {
        get
        {
            if (parentId is (null, null))
                GetPropertiesViaProcessHandle();

            return parentId;
        }
    }

    //public bool ProcessIs64Bit { get; } // unused, for now

    public unsafe (PS_PROTECTION? v, Exception? ex) ProcessProtection
    {
        get
        {
            if (processProtection is (null, null))
            {
                const uint ProcessProtectionInformation = 61; // Retrieves a BYTE value indicating the type of protected process and the protected process signer.
                PS_PROTECTION protection = default;
                uint retLength = 0;

                using SafeProcessHandle? hProcess = OpenProcess_SafeHandle(PROCESS_ACCESS_RIGHTS.PROCESS_QUERY_LIMITED_INFORMATION, false, (uint)ProcessId);
                NTSTATUS status = NtQueryInformationProcess(hProcess, (PROCESSINFOCLASS)ProcessProtectionInformation, &protection, 1, ref retLength);

                if (status.Code is not Code.STATUS_SUCCESS)
                    return processProtection = (null, new NTStatusException(status));
                else
                    return processProtection = (protection, null);
            }
            else
            {
                return processProtection;
            }
        }
    }

    internal (ProcessBasicInformation? v, Exception? ex) ProcessBasicInformation
    {
        get
        {
            if (processBasicInformation is (null, null))
                GetPropertiesViaProcessHandle();

            return processBasicInformation;
        }
    }

    /// <summary>
    /// The string used to start the process (e.g. <c>\??\C:\WINDOWS\system32\conhost.exe 0x4</c>, <c>C:\WINDOWS\System32\svchost.exe -k netsvcs -p -s ShellHWDetection</c>).
    /// </summary>
    /// TODO: rework for ProcessBasicInformation
    public (string? v, Exception? ex) ProcessCommandLine
    {
        get
        {
            if (processCommandLine is (null, null))
            {
                if (ProcessId == Env.ProcessId)
                    return processCommandLine = (Env.CommandLine, null);
                GetPropertiesViaProcessHandle();
            }

            return processCommandLine;
        }
    }

    /// <summary>
    /// The full file path of the handle-owning process's main module (the executable file) or an exception if the Get operation failed.
    /// </summary>
    /// <value>
    /// v: If the query succeeded, the full file path of the process's main module, the executable file.<br/>
    /// ex: If the query failed, the error encountered when attempting to query the full file path of the process's main module.
    /// </value>
    /// <remarks>If ProcessProtection.v is null, returns InvalidOperationException. If Protected, returns UnauthorizedAccessException. The queryable details of protected processes (System, Registry, etc.) are limited..</remarks>
    public (string? v, Exception? ex) ProcessMainModulePath
    {
        get
        {
            if (processMainModulePath is (null, null))
            {
                if (ProcessProtection.v is null)
                    return processMainModulePath = (null, new InvalidOperationException("Unable to query ProcessMainModulePath; Failed to query the process's protection:\r\n" + ProcessProtection.ex, ProcessProtection.ex));

                if (ProcessProtection.v.Value.Type is PsProtectedTypeProtected)
                    return processMainModulePath = (null, new UnauthorizedAccessException("Unable to query ProcessMainModulePath; The process is protected."));

                try
                {
                    return processMainModulePath = (GetFullProcessImageName((uint)ProcessId), null);
                }
                catch (Win32Exception ex) when (ex.NativeErrorCode is Win32ErrorCode.ERROR_GEN_FAILURE)
                {
                    return processMainModulePath = (null, new InvalidOperationException("Process has exited, but some of its handles are still open. The requested information is not available.", ex));
                }
                catch (Exception ex)
                {
                    return processMainModulePath = (null, ex);
                }
            }
            else
            {
                return processMainModulePath;
            }
        }
    }

    public (string? v, Exception? ex) ProcessName
    {
        get
        {
            if (processName is (null, null))
            {
                try
                {
                    Process proc = Process.GetProcessById(ProcessId);
                    if (proc.HasExited)
                        return processName = (null, new InvalidOperationException("Process has exited so the requested information is not available."));
                    else return processName = (proc.ProcessName, null);
                }
                catch (Exception ex)
                {
                    return processName = (null, ex);
                }
            }
            else
            {
                return processName;
            }
        }
    }

    //public bool ProcessIs64Bit { get; } // unused, for now

    /// <summary>
    /// A wrapper for QueryFullProcessImageName, a system function that circumvents 32-bit process limitations when permitted the PROCESS_QUERY_LIMITED_INFORMATION right.
    /// </summary>
    /// <param name="processId">The ID of the process to open. The resulting SafeProcessHandle is opened with <see cref="PROCESS_ACCESS_RIGHTS.PROCESS_QUERY_LIMITED_INFORMATION"/></param>
    /// <returns>The path to the executable image.</returns>
    /// <exception cref="ArgumentException">The process handle <paramref name="hProcess"/> is invalid</exception>
    /// <exception cref="Win32Exception">QueryFullProcessImageName failed. See Exception message for details.</exception>
    /// <exception cref="UnauthorizedAccessException">Failed to open process handle for processId; </exception>
    private unsafe string GetFullProcessImageName(uint processId)
    {
        //TODO: inline
        uint size = 260 + 1;
        char[] array = new char[size];
        const string errUnableMsg = "Unable to query " + nameof(ProcessMainModulePath) + "; ";

        if (ProcessHandle.v is null)
            throw new InvalidOperationException(errUnableMsg + "Failed to open ProcessHandle.", ProcessHandle.ex);
        if ((ProcessHandle.v.AccessRights & PROCESS_ACCESS_RIGHTS.PROCESS_QUERY_LIMITED_INFORMATION) is 0)
            throw new UnauthorizedAccessException(errUnableMsg + nameof(ProcessHandle) + " was opened with insufficient access rights to perform this operation.");

        SafeBuffer<char> buffer = new(numElements: size);
        if (QueryFullProcessImageName(ProcessHandle.v, PROCESS_NAME_FORMAT.PROCESS_NAME_WIN32, lpExeName: buffer.DangerousGetHandle(), ref size))
        {
            buffer.ReadArray(0, array, 0, (int)size);
            return new string(array);
        }
        else if (buffer.ByteLength < size)
        {
            buffer.Reallocate((nuint)(size * Marshal.SizeOf<char>()));
            if (QueryFullProcessImageName(
                            ProcessHandle.v,
                            PROCESS_NAME_FORMAT.PROCESS_NAME_WIN32,
                            buffer.DangerousGetHandle(),
                            ref size))
            {
                buffer.ReadArray(0, array, 0, (int)size);
                return new string(array);
            }
        }
        // this constructor calls Marshal.GetLastPInvokeError() and Marshal.GetPInvokeErrorMessage(int)
        throw new Win32Exception();
    }
}
