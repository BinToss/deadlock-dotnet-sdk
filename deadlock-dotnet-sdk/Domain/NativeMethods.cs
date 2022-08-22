using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Reflection.Metadata;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security;
using System.Text;
using deadlock_dotnet_sdk.Exceptions;
using Microsoft.Win32.SafeHandles;
using static System.Runtime.InteropServices.UnmanagedType;
using static deadlock_dotnet_sdk.Domain.NativeMethods.SystemInformationClass;
using KPRIORITY = System.Diagnostics.ProcessPriorityClass;

namespace deadlock_dotnet_sdk.Domain;
internal unsafe class NativeMethods
{
    #region Variables

    //TODO: move out of NativeMethods
    public static List<Exception> ExceptionLog { get; set; } = new();

    private const int RmRebootReasonNone = 0;
    private const int CchRmMaxAppName = 255;
    private const int CchRmMaxSvcName = 63;

    #endregion Variables

    #region Methods

    /// <summary>
    /// Find the processes that are locking a file
    /// </summary>
    /// <param name="path">Path to the file</param>
    /// <param name="rethrowExceptions">True if inner exceptions should be rethrown, otherwise false</param>
    /// <returns>A collection of processes that are locking a file</returns>
    internal static IEnumerable<Process> FindLockingProcesses(string path, bool rethrowExceptions)
    {
        string key = Guid.NewGuid().ToString();
        List<Process> processes = new();

        int res = RmStartSession(out var handle, 0, key);
        if (res != 0)
        {
            throw new StartSessionException();
        }

        try
        {
            const int errorMoreData = 234;
            uint pnProcInfo = 0;
            uint lpdwRebootReasons = RmRebootReasonNone;

            string[] resources = { path };
            res = RmRegisterResources(handle, (uint)resources.Length, resources, 0, null, 0, null);

            if (res != 0)
            {
                throw new RegisterResourceException();
            }

            res = RmGetList(handle, out var pnProcInfoNeeded, ref pnProcInfo, null, ref lpdwRebootReasons);

            if (res == errorMoreData)
            {
                RmProcessInfo[] processInfo = new RmProcessInfo[pnProcInfoNeeded];
                pnProcInfo = pnProcInfoNeeded;

                res = RmGetList(handle, out pnProcInfoNeeded, ref pnProcInfo, processInfo, ref lpdwRebootReasons);
                if (res == 0)
                {
                    processes = new List<Process>((int)pnProcInfo);

                    for (int i = 0; i < pnProcInfo; i++)
                    {
                        try
                        {
                            processes.Add(Process.GetProcessById(processInfo[i].Process.dwProcessId));
                        }
                        catch (ArgumentException)
                        {
                            if (rethrowExceptions) throw;
                        }
                    }
                }
                else
                {
                    throw new RmListException();
                }
            }
            else if (res != 0)
            {
                throw new UnauthorizedAccessException();
            }
        }
        finally
        {
            _ = RmEndSession(handle);
        }

        return processes;
    }

    /// <summary>
    /// TODO
    /// </summary>
    /// <param name="path"></param>
    /// <param name="rethrowExceptions"></param>
    /// <param name="possessHandlesDangerously">
    ///     Take possession of the file handles for the purpose of dangerously closing them.<br/>
    ///     If a process tries to use a closed handle, they will (more often than not) throw an error and terminate.
    /// </param>
    /// <returns>A generic collection of SafeFileHandle objects.</returns>
    /// <exception cref="StartSessionException"></exception>
    /// <exception cref="RegisterResourceException"></exception>
    /// <exception cref="RmListException"></exception>
    /// <exception cref="UnauthorizedAccessException"></exception>
    /// <remarks></remarks>
    /// TODO: update List asynchronously
    internal static List<SafeFileHandleEx> FindLockingHandles(string path, bool rethrowExceptions)
    {
        List<SafeHandleEx> handles = GetSystemHandleInfoEx().ToArray().Cast<SafeHandleEx>().ToList();
        List<SafeFileHandleEx> fileHandles = new();
        foreach (var handle in handles)
        {
            try
            {
                fileHandles.Add(new SafeFileHandleEx(handle, false));
                // TODO: Query the command line of each handle's parent process
            }
            catch (InvalidCastException)
            { }
            catch (Exception ex)
            {

            }
        }


        //~~TODO: get filepath from handle
        // Get Filename of handle by first getting

    }

    private static Span<SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX> GetSystemHandleInfoEx()
    {
        const uint STATUS_INFO_LENGTH_MISMATCH = 0xC0000004;
        const uint PH_LARGE_BUFFER_SIZE = 256 * 1024 * 1024; // 256 Mebibytes
        const uint STATUS_INSUFFICIENT_RESOURCES = 0xC000009A;
        uint systemInformationLength = (uint)sizeof(SYSTEM_HANDLE_INFORMATION_EX);
        SYSTEM_HANDLE_INFORMATION_EX* pSysInfoBuffer = (SYSTEM_HANDLE_INFORMATION_EX*)Marshal.AllocHGlobal(sizeof(SYSTEM_HANDLE_INFORMATION_EX));

        NTSTATUS status = NtQuerySystemInformation(
            SystemInformationClass: SystemExtendedHandleInformation,
            SystemInformation: pSysInfoBuffer,
            SystemInformationLength: systemInformationLength,
            ReturnLength: out uint* pReturnLength
            );

        for (uint attempts = 0; status == STATUS_INFO_LENGTH_MISMATCH && attempts < 10; attempts++)
        {
            systemInformationLength = *pReturnLength;
            pSysInfoBuffer = (SYSTEM_HANDLE_INFORMATION_EX*)Marshal.ReAllocHGlobal((IntPtr)pSysInfoBuffer, (IntPtr)systemInformationLength);

            status = NtQuerySystemInformation(
                SystemExtendedHandleInformation,
                pSysInfoBuffer,
                systemInformationLength,
                out pReturnLength
                );
        }

        if (!status.IsSuccess)
        {
            // Fall back to using the previous code that we've used since Windows XP (dmex)
            systemInformationLength = 0x10000;
            Marshal.FreeHGlobal((IntPtr)pSysInfoBuffer);
            pSysInfoBuffer = (SYSTEM_HANDLE_INFORMATION_EX*)Marshal.ReAllocHGlobal((IntPtr)pSysInfoBuffer, (IntPtr)systemInformationLength);

            while ((status = NtQuerySystemInformation(
                SystemInformationClass: SystemExtendedHandleInformation,
                SystemInformation: pSysInfoBuffer,
                SystemInformationLength: systemInformationLength,
                ReturnLength: out pReturnLength
                )) == STATUS_INFO_LENGTH_MISMATCH)
            {
                Marshal.FreeHGlobal((IntPtr)pSysInfoBuffer);
                systemInformationLength *= 2;

                // Fail if we're resizing the buffer to something very large.
                if (systemInformationLength > PH_LARGE_BUFFER_SIZE)
                {
                    throw new Win32Exception(unchecked((int)STATUS_INSUFFICIENT_RESOURCES));
                }

                pSysInfoBuffer = (SYSTEM_HANDLE_INFORMATION_EX*)Marshal.AllocHGlobal((int)systemInformationLength);
            }
        }

        if (!status.IsSuccess)
        {
            Marshal.FreeHGlobal((IntPtr)pSysInfoBuffer);
            Marshal.FreeHGlobal((IntPtr)pReturnLength);
            throw new Win32Exception((int)status);
        }

        SYSTEM_HANDLE_INFORMATION_EX retVal = *pSysInfoBuffer;

        Marshal.FreeHGlobal((IntPtr)pSysInfoBuffer);
        Marshal.FreeHGlobal((IntPtr)pReturnLength);

        return retVal.AsSpan();
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="processId">
    /// The identifier of the local process to be opened.
    /// If the specified process is the System Idle Process(0x00000000),
    ///  the function fails and the last error code is ERROR_INVALID_PARAMETER.
    /// If the specified process is the System process or one of the Client Server Run-Time Subsystem(CSRSS) processes,
    ///  this function fails and the last error code is ERROR_ACCESS_DENIED because their access restrictions prevent user-level code from opening them.
    /// </param>
    /// <returns>The path to the executable image.</returns>
    /// <exception cref="Exception">Call to <see cref="OpenProcess(uint, bool, uint)"/> or <see cref="QueryFullProcessImageName(SafeProcessHandle, uint, out string, ref uint)"/> failed.</exception>
    private static string GetFullProcessImageName(uint processId)
    {
        uint size = 0x1000u;
        SafeProcessHandle hProcess;

        if ((hProcess = OpenProcess(
            dwDesiredAccess: ACCESS_MASK.PROCESS_QUERY_LIMITED_INFORMATION,
            bInheritHandle: false,
            dwProcessId: processId)).IsInvalid)
        {
            throw new Win32Exception()!;
        }

        if (!QueryFullProcessImageName(
            hProcess: hProcess,
            dwFlags: 0,
            lpExeName: out string buffer,
            lpdwSize: ref size))
        {
            throw new Win32Exception()!;
        }

        hProcess.Close();
        return buffer;
    }

    #endregion Methods

    #region DllImport

    [DllImport("Kernel32.dll"), SupportedOSPlatform("windows")]
    private static extern bool CloseHandle(HANDLE hObject);

    /// <summary>
    /// Retrieves the final path for the specified file.
    /// </summary>
    /// <param name="hFile">A handle to a file or directory.</param>
    /// <param name="lpszFilePath">A pointer to a buffer that receives the path of hFile.</param>
    /// <param name="cchFilePath">The size of lpszFilePath, in TCHARs. This value must include a NULL termination character.</param>
    /// <param name="dwFlags">
    /// The type of result to return. This parameter can be one of the following values.<br/>
    /// - FILE_NAME_NORMALIZED (0x0): Return the normalized drive name. This is the default.<br/>
    /// - FILE_NAME_OPENED     (0x8): Return the opened file name (not normalized).<br/>
    /// This parameter can also include one of the following values.<br/>
    /// - VOLUME_NAME_DOS      (0x0): Return the path with the drive letter. This is the default.<br/>
    /// - VOLUME_NAME_GUID     (0x1): Return the path with a volume GUID path instead of the drive name.<br/>
    /// - VOLUME_NAME_NONE     (0x4): Return the path with no drive information.<br/>
    /// - VOLUME_NAME_NT       (0x2): Return the path with the volume device path.<br/>
    /// </param>
    /// <returns>
    /// <para>
    ///  If the function succeeds, the return value is the length of the string received by lpszFilePath, in TCHARs.
    ///  This value does not include the size of the terminating null character.</para>
    /// <para>
    ///  If the function fails because lpszFilePath is too small to hold the string
    ///  plus the terminating null character, the return value is the required buffer size, in TCHARs.
    ///  This value includes the size of the terminating null character.
    /// </para>
    /// <para>
    ///  If the function fails for any other reason, the return value is zero.
    ///  To get extended error information, call GetLastError.
    /// </para>
    /// <para>
    ///  ERROR_PATH_NOT_FOUND: Can be returned if you are searching for a drive letter and one does not exist.
    ///  For example, the handle was opened on a drive that is not currently mounted,
    ///  or if you create a volume and do not assign it a drive letter.<br/>
    ///  If a volume has no drive letter, you can use the volume GUID path to identify it.
    ///  This return value can also be returned if you are searching for a volume GUID path on a network share.
    ///  Volume GUID paths are not created for network shares.
    /// </para>
    /// <para>ERROR_NOT_ENOUGH_MEMORY: Insufficient memory to complete the operation.</para>
    /// <para>ERROR_INVALID_PARAMETER: Invalid flags were specified for dwFlags. </para>
    /// </returns>
    [DllImport("Kernel32", ExactSpelling = true, EntryPoint = "GetFinalPathNameByHandleW", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [SupportedOSPlatform("windows6.0.6000")]
    private static extern uint GetFinalPathNameByHandle(
        SafeFileHandle hFile,
        [MarshalAs(LPWStr)] ref string lpszFilePath,
        uint cchFilePath,
        FILE_NAME dwFlags
    );

    /// <summary>
    /// Retrieves the full name of the executable image for the specified process.
    /// </summary>
    /// <param name="hProcess"></param>
    /// <param name="dwFlags">
    /// This parameter can be one of the following values.
    /// Value                   | Meaning
    /// 0                       | The name should use the Win32 path format.
    /// PROCESS_NAME_NATIVE (1) | The name should use the native system path format.
    /// </param>
    /// <param name="lpExeName">The path to the executable image. If the function succeeds, this string is null-terminated.</param>
    /// <param name="lpdwSize">On input, specifies the size of the lpExeName buffer, in characters. On success, receives the number of characters written to the buffer, not including the null-terminating character.</param>
    /// <returns></returns>
    [DllImport("Kernel32.dll", CharSet = CharSet.Unicode), SupportedOSPlatform("windows6.0")]
    private static extern bool QueryFullProcessImageName(
        SafeProcessHandle hProcess,
        uint dwFlags,
        [MarshalAs(LPWStr)] out string lpExeName,
        ref uint lpdwSize
    );

    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    private static extern int RmRegisterResources(uint pSessionHandle, uint nFiles, string[] rgsFilenames,
        uint nApplications, [In] RmUniqueProcess[] rgApplications, uint nServices, string[] rgsServiceNames);

    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    private static extern int RmStartSession(out uint pSessionHandle, int dwSessionFlags, string strSessionKey);

    [DllImport("rstrtmgr.dll")]
    private static extern int RmEndSession(uint pSessionHandle);

    [DllImport("rstrtmgr.dll")]
    private static extern int RmGetList(uint dwSessionHandle, out uint pnProcInfoNeeded, ref uint pnProcInfo,
        [In, Out] RmProcessInfo[] rgAffectedApps, ref uint lpdwRebootReasons);

    /// <summary>Retrieves the specified system information.</summary>
    /// <param name="SystemInformationClass">
    /// <para>One of the values enumerated in SYSTEM_INFORMATION_CLASS, which indicate the kind of system information to be retrieved. These include the following values.</para>
    /// <para><see href="https://docs.microsoft.com/windows/win32/api//winternl/nf-winternl-ntquerysysteminformation#parameters">Read more on docs.microsoft.com</see>.</para>
    /// </param>
    /// <param name="SystemInformation">
    /// <para>A pointer to a buffer that receives the requested information. The size and structure of this information varies depending on the value of the <i>SystemInformationClass</i> parameter:</para>
    /// <para><see href="https://docs.microsoft.com/windows/win32/api//winternl/nf-winternl-ntquerysysteminformation#parameters">Read more on docs.microsoft.com</see>.</para>
    /// </param>
    /// <param name="SystemInformationLength">The size of the buffer pointed to by the <i>SystemInformation</i>parameter, in bytes.</param>
    /// <param name="ReturnLength">
    /// <para>An optional pointer to a location where the function  writes the actual size of the information requested. If that size is less than or equal to the <i>SystemInformationLength</i> parameter, the function copies the information into the <i>SystemInformation</i> buffer; otherwise, it returns an NTSTATUS error code and returns in <i>ReturnLength</i> the size of buffer required to receive the requested information.</para>
    /// <para><see href="https://docs.microsoft.com/windows/win32/api//winternl/nf-winternl-ntquerysysteminformation#parameters">Read more on docs.microsoft.com</see>.</para>
    /// </param>
    /// <returns>
    /// <para>Returns an NTSTATUS success or error code. The forms and significance of NTSTATUS error codes are listed in the Ntstatus.h header file available in the DDK, and are described in the DDK documentation.</para>
    /// </returns>
    /// <remarks>
    /// <para><see href="https://docs.microsoft.com/windows/win32/api//winternl/nf-winternl-ntquerysysteminformation">Learn more about this API from docs.microsoft.com</see>.</para>
    /// </remarks>
    [DllImport("NtDll.dll")]
    private static extern NTSTATUS NtQuerySystemInformation(
        SystemInformationClass SystemInformationClass,
        void* SystemInformation,
        uint SystemInformationLength,
        [Optional] out uint* ReturnLength
    );

    [DllImport("NtDll.dll")]
    private static extern NTSTATUS NtQueryObject(
        HANDLE ObjectHandle,
        ObjectInformationClass ObjectInformationClass,
        void* ObjectInformation,
        uint ObjectInformationLength,
        uint* ReturnLength
    );

    /// <summary>
    ///     Opens an existing local process object.
    /// </summary>
    /// <param name="dwDesiredAccess">
    ///     The access to the process object. This access right is checked against the security descriptor for the process. This parameter can be one or more of the process access rights.
    ///     If the caller has enabled the SeDebugPrivilege privilege, the requested access is granted regardless of the contents of the security descriptor.
    /// </param>
    /// <param name="bInheritHandle">
    ///     If this value is TRUE, processes created by this process will inherit the handle. Otherwise, the processes do not inherit this handle.
    /// </param>
    /// <param name="dwProcessId">
    ///     The identifier of the local process to be opened.
    ///     If the specified process is the System Idle Process(0x00000000), the function fails and the last error code is ERROR_INVALID_PARAMETER.If the specified process is the System process or one of the Client Server Run-Time Subsystem(CSRSS) processes, this function fails and the last error code is ERROR_ACCESS_DENIED because their access restrictions prevent user-level code from opening them.
    ///     If you are using GetCurrentProcessId as an argument to this function, consider using GetCurrentProcess instead of OpenProcess, for improved performance.
    /// </param>
    /// <returns>
    /// If the function succeeds, an open handle to the specified process. Else, null. To get extended error information, call <see cref="Win32Exception()"/>.
    /// </returns>
    /// <remarks>
    ///     To open a handle to another local process and obtain full access rights, you must enable the SeDebugPrivilege privilege. For more information, see Changing Privileges in a Token.
    ///     The handle returned by the OpenProcess function can be used in any function that requires a handle to a process, such as the wait functions, provided the appropriate access rights were requested.
    ///     When you are finished with the handle, be sure to close it using the CloseHandle function.
    /// </remarks>
    [DllImport("Kernel32.dll")]
    private static extern SafeProcessHandle OpenProcess(
        uint dwDesiredAccess,
        bool bInheritHandle,
        uint dwProcessId
    );

    #endregion DllImport

    #region Enums

    private enum FILE_NAME : uint
    {
        FILE_NAME_NORMALIZED = 0U,
        FILE_NAME_OPENED = 8U,
    }
    private enum ObjectInformationClass : uint
    {
        ObjectBasicInformation = 0,
        ObjectNameInformation = 1,
        ObjectTypeInformation = 2
    }

    /// <summary>
    /// <see href="https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ne-wdm-_pool_type"/>
    /// </summary>
    public enum POOL_TYPE
    {
        NonPagedPool,
        PagedPool,
        NonPagedPoolMustSucceed = NonPagedPool + 2,
        DontUseThisType,
        NonPagedPoolCacheAligned = NonPagedPool + 4,
        PagedPoolCacheAligned,
        NonPagedPoolCacheAlignedMustS = NonPagedPool + 6
    }

    /// <summary>
    /// Used in 2D array which holds before and after count of number of handles in a process
    /// </summary>
    public enum PROCESS_ARRAY { PROCESS_ARRAY_INDEX, PROCESS_ARRAY_COUNT_START_CYCLE, PROCESS_ARRAY_COUNT_END_CYCLE };

    private enum RmAppType
    {
        // ReSharper disable once UnusedMember.Local
        RmUnknownApp = 0,

        // ReSharper disable once UnusedMember.Local
        RmMainWindow = 1,

        // ReSharper disable once UnusedMember.Local
        RmOtherWindow = 2,

        // ReSharper disable once UnusedMember.Local
        RmService = 3,

        // ReSharper disable once UnusedMember.Local
        RmExplorer = 4,

        // ReSharper disable once UnusedMember.Local
        RmConsole = 5,

        // ReSharper disable once UnusedMember.Local
        RmCritical = 1000
    }

    public enum SystemInformationClass
    {
        SystemProcessInformation = 0x5,
        SystemHandleInformation = 0x10,
        SystemExtendedHandleInformation = 0x40
    }

    #endregion Enums

    #region Structs



    /// <summary>
    /// A simple placeholder for dotnet/PInvoke's complex ACCESS_MASK struct
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Size = 32 / 8)] // 4 bytes
    public struct ACCESS_MASK
    {
        public uint Access;

        public static implicit operator ACCESS_MASK(uint v) => new() { Access = v };
        public static implicit operator uint(ACCESS_MASK v) => v.Access;

        public const uint PROCESS_DUP_HANDLE = 0x0040;
        public const uint PROCESS_QUERY_INFORMATION = 0x0400;
        public const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
        public const uint DELETE = 0x00010000;
        public const uint READ_CONTROL = 0x00020000;
        public const uint WRITE_DAC = 0x00040000;
        public const uint WRITE_OWNER = 0x00080000;
        public const uint SYNCHRONIZE = 0x00100000;

        #region StandardAccess
        public const uint STANDARD_RIGHTS_REQUIRED = DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER;

        public const uint STANDARD_RIGHTS_READ = READ_CONTROL;
        public const uint STANDARD_RIGHTS_WRITE = READ_CONTROL;
        public const uint STANDARD_RIGHTS_EXECUTE = READ_CONTROL;

        public const uint STANDARD_RIGHTS_ALL = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE;

        #endregion StandardAccess

        public const uint SPECIFIC_RIGHTS_ALL = 0x0000FFFF;

        /// <summary>
        /// AccessSystemAcl access type
        /// </summary>
        public const uint ACCESS_SYSTEM_SECURITY = 0x01000000;

        /// <summary>These are the generic rights.</summary>
        #region GenericRights
        public const uint GENERIC_READ = 0x80000000;
        public const uint GENERIC_WRITE = 0x40000000;
        public const uint GENERIC_EXECUTE = 0x20000000;
        public const uint GENERIC_ALL = 0x10000000;

        #endregion GenericRights
        /// <summary>
        /// MaximumAllowed access type
        /// </summary>
        public const uint MAXIMUM_ALLOWED = 0x02000000;
    }

    /// <summary>
    /// A simple placeholder for Microsoft/CsWin32's HANDLE struct
    /// </summary>
    public struct HANDLE : IDisposable
    {
        public nuint value;

        public static implicit operator HANDLE(nuint v) => new() { value = v };
        public static implicit operator nuint(HANDLE v) => v.value;

        public static implicit operator HANDLE(nint v) => new() { value = (nuint)v };
        public static implicit operator nint(HANDLE v) => (nint)v.value;
        public bool Close() => CloseHandle(this);

        void IDisposable.Dispose() => Close();
    }

    [StructLayout(LayoutKind.Sequential, Size = 32 * 4 / 8)] // 16 bytes
    public struct GENERIC_MAPPING
    {
        public ACCESS_MASK GenericRead;
        public ACCESS_MASK GenericWrite;
        public ACCESS_MASK GenericExecute;
        public ACCESS_MASK GenericAll;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LIST_ENTRY
    {
        public LIST_ENTRY* Flink;
        public LIST_ENTRY* Blink;
    }

    /// <summary>
    ///  A simple placeholder for dotnet/PInvoke's complex NTSTATUS struct
    /// </summary>
    public struct NTSTATUS
    {
        public uint Status;

        public bool IsSuccess => (int)Status >= 1;

        public static implicit operator NTSTATUS(uint v) => new() { Status = v };
        public static implicit operator uint(NTSTATUS v) => v.Status;

        public static implicit operator NTSTATUS(int v) => new() { Status = (uint)v };
        public static implicit operator int(NTSTATUS v) => (int)v.Status;

        public static explicit operator NTSTATUS(bool v) => new() { Status = v ? 1u : 0 };
        public static implicit operator bool(NTSTATUS v) => v.IsSuccess;
    }

    // TODO: C#10 and below do not support fixed arrays of pointers
    private struct PEB_32
    {
        public fixed byte Reserved1[2]; // 2 bytes
        public byte BeingDebugged; // 1 byte
        public byte Reserved2; // 1 byte
        public void* Reserved3_0; // IntPtr.Size
        public void* Reserved3_1; // IntPtr.Size
        public PEB_LDR_DATA* Ldr; // IntPtr.Size
        public RTL_USER_PROCESS_PARAMETERS* ProcessParameters; // IntPtr.Size
        private void* Reserved4_0; // IntPtr.Size
        private void* Reserved4_1; // IntPtr.Size
        private void* Reserved4_2; // IntPtr.Size
        public void* AtlThunkSListPtr; // IntPtr.Size
        private void* Reserved5; // IntPtr.Size
        private uint Reserved6; // 4 bytes
        private void* Reserved7; // IntPtr.Size
        private uint Reserved8; // 4 bytes
        public uint AtlThunkSListPtr32; // 32 bytes
        public fixed void* Reserved9[45]; //TODO: invalid syntax. C#10 and below only allow blittable primitives for fixed arrays // ((IntPtr.Size) * 45) bytes
        public fixed byte Reserved10[96]; // 96 bytes
        public void* PostProcessInitRoutine;  // PPS_POST_PROCESS_INIT_ROUTINE // IntPtr.Size
        public fixed byte Reserved11[128]; // 128 bytes
        public nint Reserved12; // IntPtr.Size
        public uint SessionId; // 4 bytes
    }

    // TODO: Refactor
    // TODO: This *should* be merged with the 32-bit struct if possible. Otherwise, we have to make additional 32/64-bit parent structs
    private struct PEB_64
    {
        private fixed byte Reserved1[2]; // 2 bytes
        public byte BeingDebugged; // 1 byte
        private fixed byte Reserved2[21]; // 21 bytes
        public PEB_LDR_DATA* LoaderData; // IntPtr.Size
        public RTL_USER_PROCESS_PARAMETERS* ProcessParameters; // IntPtr.Size
        private fixed byte Reserved3[520]; // 520 bytes
        public void* PostProcessInitRoutine; // PPS_POST_PROCESS_INIT_ROUTINE // IntPtr.Size
        private fixed byte Reserved4[136]; // 136 bytes
        public uint SessionId; // 4 bytes
    }

    private struct PEB_LDR_DATA
    {
        private fixed byte Reserved1[8];
        private nint Reserved2_0;
        private nint Reserved2_1;
        private nint Reserved2_2;
        public LIST_ENTRY InMemoryOrderModuleList;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_BASIC_INFORMATION
    {
        public NTSTATUS ExitStatus;
        public PEB* PebBaseAddress;
        public nuint AffinityMask;
        public KPRIORITY BasePriority;
        public nuint UniqueProcessId;
        public nuint InheritedFromUniqueProcessId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PUBLIC_OBJECT_TYPE_INFORMATION
    {
        public UNICODE_STRING TypeName;
        public fixed uint Reserved[22];
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    internal struct RmProcessInfo
    {
        internal RmUniqueProcess Process;

        [MarshalAs(ByValTStr, SizeConst = CchRmMaxAppName + 1)]
        private readonly string strAppName;

        [MarshalAs(ByValTStr, SizeConst = CchRmMaxSvcName + 1)]
        private readonly string strServiceShortName;

        private readonly RmAppType ApplicationType;
        private readonly uint AppStatus;
        private readonly uint TSSessionId;
        [MarshalAs(Bool)] private readonly bool bRestartable;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct RmUniqueProcess
    {
        internal readonly int dwProcessId;
        private readonly System.Runtime.InteropServices.ComTypes.FILETIME ProcessStartTime;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct RTL_USER_PROCESS_PARAMETERS
    {
        public fixed byte Reserved1[16];
        public fixed void* Reserved2[10]; //TODO: invalid syntax. C#10 and below only allow blittable primitives for fixed arrays // ((IntPtr.Size) * 45) bytes
        public UNICODE_STRING ImagePathName;
        public UNICODE_STRING CommandLine;
    }

    /// <summary>
    /// The <see href="https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/handle_ex.htm"><c>SYSTEM_HANDLE_INFORMATION_EX</c></see>
    /// struct is 0x24 or 0x38 bytes in 32-bit and 64-bit Windows, respectively. However, Handles is a variable-length array.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct SYSTEM_HANDLE_INFORMATION_EX
    {
        /// <summary>
        /// As documented unofficially, NumberOfHandles is a 4-byte or 8-byte ULONG_PTR in 32-bit and 64-bit Windows, respectively.<br/>
        /// This is not to be confused with uint* or ulong*.
        /// </summary>
        public UIntPtr NumberOfHandles;
        public UIntPtr Reserved;
        public SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX* Handles;

        public Span<SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX> AsSpan() => new(Handles, (int)NumberOfHandles);
        public static implicit operator Span<SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX>(SYSTEM_HANDLE_INFORMATION_EX value) => value.AsSpan();
    }

    /// <summary><para>
    /// The <see href="https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/handle_table_entry_ex.htm">
    /// SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX</see>
    /// structure is a recurring element in the <see href="https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/handle_ex.htm">
    /// SYSTEM_HANDLE_INFORMATION_EX </see>
    /// struct that a successful call to <see href="https://docs.microsoft.com/en-us/windows/win32/sysinfo/zwquerysysteminformation">
    /// ZwQuerySystemInformation</see>
    /// or <see href="https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation">
    /// NtQuerySystemInformation</see>
    /// produces in its output buffer when given the information class <see cref="SystemHandleInformation">
    /// SystemHandleInformation (0x10)</see>.</para>
    /// This inline doc was supplemented by ProcessHacker's usage of this struct.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
    {
        /// <summary>
        /// <para>Unofficial docs specify the type as <c>void*</c>. This is somewhat interchangeable with dotnet's IntPtr.
        /// Use type-casting when necessary.</para>
        /// </summary>
        public nint Object;
        public nuint UniqueProcessId; // ULONG_PTR
        public nuint HandleValue; // ULONG_PTR
        /// <summary>
        /// This is a bitwise "Flags" data type.
        /// See the "Granted Access" column in the Handles section of a process properties window in ProcessHacker.
        /// </summary>
        public ACCESS_MASK GrantedAccess; // ULONG
        public ushort CreatorBackTraceIndex; // USHORT
        /// <summary>ProcessHacker defines a little over a dozen handle-able object types.</summary>
        public ushort ObjectTypeIndex; // USHORT
        /// <summary><see href="https://docs.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-_object_attributes#members"/></summary>
        public uint HandleAttributes; // ULONG
        public uint Reserved;

        public void Close() => CloseHandle(HandleValue);

        /// <summary>
        /// Get the Type of the object as a string
        /// </summary>
        /// <exception cref="Exception">P/Invoke function NtQueryObject failed. See Exception data.</exception>
        /// <returns>The Type of the object as a string.</returns>
        public string GetObjectType()
        {
            /* Query the object type */
            string typeName;
            PUBLIC_OBJECT_TYPE_INFORMATION* objectTypeInfo = (PUBLIC_OBJECT_TYPE_INFORMATION*)(IntPtr)GCHandle.Alloc(new PUBLIC_OBJECT_TYPE_INFORMATION(), GCHandleType.Pinned); //(PUBLIC_OBJECT_TYPE_INFORMATION*)Marshal.AllocHGlobal(sizeof(PUBLIC_OBJECT_TYPE_INFORMATION));
            if (NtQueryObject(HandleValue, ObjectInformationClass.ObjectTypeInformation, objectTypeInfo, (uint)sizeof(PUBLIC_OBJECT_TYPE_INFORMATION), null).IsSuccess)
            {
                typeName = objectTypeInfo->TypeName.ToStringLength();
                GCHandle.FromIntPtr((IntPtr)objectTypeInfo).Free();
            }
            else
            {
                GCHandle.FromIntPtr((IntPtr)objectTypeInfo).Free();
                throw new Win32Exception();
            }
            return typeName;
        }

        /// <summary>Invokes <see cref="GetObjectType()"/> and checks if the result is "File".</summary>
        /// <returns>True if the handle is for a file or directory.</returns>
        /// <remarks>Based on source of C/C++ projects <see href="https://www.x86matthew.com/view_post?id=hijack_file_handle">Hijack File Handle</see> and <see href="https://github.com/adamkramer/handle_monitor">Handle Monitor</see></remarks>
        /// <exception cref="Exception">Failed to determine if this handle's object is a file/directory. Error when calling NtQueryObject. See InnerException for details.</exception>
        public bool IsFileHandle()
        {
            try
            {
                string type = GetObjectType();
                return !string.IsNullOrWhiteSpace(type) && string.CompareOrdinal(type, "File") == 0;
            }
            catch (Exception e)
            {
                throw new Exception("Failed to determine if this handle's object is a file/directory. Error when calling NtQueryObject. See InnerException for details.", e);
            }
        }

        /// <summary>
        /// Try to cast this handle's <see cref="HandleValue"/> to a SafeFileHandle;
        /// </summary>
        /// <returns>A <see cref="SafeFileHandle"/> if this handle's object is a data/directory File.</returns>
        /// <exception cref="Exception">The handle's object is not a File -OR- perhaps NtQueryObject() failed. See <see cref="Exception.InnerException"/> for details.</exception>
        public SafeFileHandle ToSafeFileHandle()
        {
            return IsFileHandle()
                ? (new((nint)HandleValue, (int)UniqueProcessId == Environment.ProcessId))
                : throw new Exception("The handle's object is not a File -OR- NtQueryObject() failed. See InnerException for details.");
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SYSTEM_PROCESS_INFORMATION
    {
        public uint NextEntryOffset;
        public uint NumberOfThreads;
        public long WorkingSetPrivateSize; // since VISTA
        public uint HardFaultCount; // since WIN7
        public uint NumberOfThreadsHighWatermark; // since WIN7
        public ulong CycleTime; // since WIN7
        public long CreateTime;
        public long UserTime;
        public long KernelTime;
        public UNICODE_STRING ImageName;
        public KPRIORITY BasePriority;
        public HANDLE UniqueProcessId;
        public HANDLE InheritedFromUniqueProcessId;
        public uint HandleCount;
        public uint SessionId;
        public nuint UniqueProcessKey; // since VISTA (requires SystemExtendedProcessInformation)
        public nuint PeakVirtualSize;
        public nuint VirtualSize;
        public uint PageFaultCount;
        public nuint PeakWorkingSetSize;
        public nuint WorkingSetSize;
        public nuint QuotaPeakPagedPoolUsage;
        public nuint QuotaPagedPoolUsage;
        public nuint QuotaPeakNonPagedPoolUsage;
        public nuint QuotaNonPagedPoolUsage;
        public nuint PagefileUsage;
        public nuint PeakPagefileUsage;
        public nuint PrivatePageCount;
        public long ReadOperationCount;
        public long WriteOperationCount;
        public long OtherOperationCount;
        public long ReadTransferCount;
        public long WriteTransferCount;
        public long OtherTransferCount;
        public SYSTEM_THREAD_INFORMATION* Threads;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SYSTEM_THREAD_INFORMATION
    {

    }

    [StructLayout(LayoutKind.Sequential)] // Size == (16 * 2 + (32 or 64)) / 8;
    public struct UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public char* Buffer;

        /// <summary>
        /// Allocates a managed string and copies a specified number of characters from an unmanaged Unicode string into it.
        /// </summary>
        /// <returns></returns>
        public string ToStringLength() => Marshal.PtrToStringUni((IntPtr)Buffer, Length);
        public string? ToStringZ() => Marshal.PtrToStringUni((IntPtr)Buffer);
        public static implicit operator string(UNICODE_STRING v) => v.ToStringLength();
    }

    #endregion Structs

    #region Classes

    internal class SafeHandleEx : SafeHandleZeroOrMinusOneIsInvalid
    {
        public readonly SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX SysHandleEx;

        public SafeHandleEx(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX sysHandleEx, bool ownsHandle = false) : base(ownsHandle)
        {
            SysHandleEx = sysHandleEx;
            ProcessName = Process.GetProcessById((int)ProcessId).ProcessName;
            ProcessMainModulePath = GetFullProcessImageName((uint)ProcessId);
            try
            {
                // TODO: Get (mutable) command line from other process's PEB
                //NtQuerySystemInformation(SystemProcessInformation, )
            }
            catch (Exception)
            {
                throw;
            }
        }

        public nint Object => SysHandleEx.Object;
        public nuint ProcessId => SysHandleEx.UniqueProcessId;
        public nuint HandleValue => SysHandleEx.HandleValue;
        public ushort CreatorBackTraceIndex => SysHandleEx.CreatorBackTraceIndex;
        /// <inheritdoc cref="SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX.GrantedAccess"/>
        public ACCESS_MASK GrantedAccess => SysHandleEx.GrantedAccess;
        public ushort ObjectTypeIndex => SysHandleEx.ObjectTypeIndex;
        /// <inheritdoc cref="SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX.HandleAttributes"/>
        public uint HandleAttributes => SysHandleEx.HandleAttributes;

        public readonly string? ProcessName;
        public readonly string? ProcessMainModulePath;
        public readonly string? ProcessCommandLine;

        public void CloseDangerously()
        {
            SysHandleEx.Close();
            Close();
        }

        public string GetObjectType() => SysHandleEx.GetObjectType();

        /// <summary>
        /// Try casting the current <see cref="SafeHandleEx"/> to a <see cref="SafeFileHandleEx"/>
        /// </summary>
        /// <returns>A <see cref="SafeFileHandleEx"/></returns>
        public SafeFileHandleEx AsFileHandle() => (SafeFileHandleEx)this;

        protected override bool ReleaseHandle()
        {
            Close();
            return IsClosed;
        }
    }

    internal class SafeFileHandleEx : SafeHandleEx
    {
        public SafeFileHandleEx(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX sysHandleEx, bool ownsHandle) : base(sysHandleEx: sysHandleEx, ownsHandle: ownsHandle)
        {
            bool? isFileHandle;
            try
            {
                isFileHandle = sysHandleEx.IsFileHandle();
            }
            catch (Exception)
            {
                isFileHandle = null;
                // IsFileHandle failed
            }
            if (isFileHandle == true)
            {
                FullPath = TryGetFinalPath();
                if (FullPath != null)
                {
                    Name = Path.GetFileName(FullPath);
                    IsDirectory = (File.GetAttributes(FullPath) & FileAttributes.Directory) == FileAttributes.Directory;
                }
            }
            else
            {
                throw new InvalidCastException("Cannot cast non-file handle to file handle!");
            }
        }

        public readonly string? FullPath;
        public readonly string? Name;
        public readonly bool? IsDirectory;

        /// <summary>
        /// Try to get the absolute path of the file. Traverses filesystem links (e.g. symbolic, junction) to get the 'real' path.
        /// </summary>
        /// <returns>If successful, returns a path string formatted as 'X:\dir\file.ext' or 'X:\dir'</returns>
        /// <exception cref="FileNotFoundException(string, string)">The path '{fullName}' was not found when querying a file handle.</exception>
        /// <exception cref="OutOfMemoryException(string)">Failed to query path from file handle. Insufficient memory to complete the operation.</exception>
        /// <exception cref="ArgumentException">Failed to query path from file handle. Invalid flags were specified for dwFlags.</exception>
        private string TryGetFinalPath()
        {
            /// Return the normalized drive name. This is the default.
            const uint FILE_NAME_NORMALIZED = 0x0;
            string fullName = new('\0', 2048);
            bool success = GetFinalPathNameByHandle(SysHandleEx.ToSafeFileHandle(), ref fullName, (uint)fullName.Length, FILE_NAME_NORMALIZED) != 0;
            if (success)
            {
                return fullName;
            }
            else
            {
                int error = Marshal.GetLastWin32Error();
                const int ERROR_PATH_NOT_FOUND = 3;
                const int ERROR_NOT_ENOUGH_MEMORY = 8;
                const int ERROR_INVALID_PARAMETER = 87; // 0x57

                throw error switch
                {
                    ERROR_PATH_NOT_FOUND => new FileNotFoundException($"The path '{fullName}' was not found when querying a file handle.", fullName), // Removable storage, deleted item, network shares, et cetera
                    ERROR_NOT_ENOUGH_MEMORY => new OutOfMemoryException("Failed to query path from file handle. Insufficient memory to complete the operation."), // unlikely, but possible if system has little free memory
                    ERROR_INVALID_PARAMETER => new ArgumentException("Failed to query path from file handle. Invalid flags were specified for dwFlags."), // possible only if FILE_NAME_NORMALIZED (0) is invalid
                    _ => new Exception($"An undocumented error ({error}) was returned when querying a file handle for its path."),
                };
            }
        }
    }

    #endregion Classes
}
