using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using PInvoke;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.Storage.FileSystem;
using Windows.Win32.System.Threading;
using static Windows.Win32.PInvoke;

// Re: StructLayout
// "C#, Visual Basic, and C++ compilers apply the Sequential layout value to structures by default."
// https://docs.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.structlayoutattribute?view=net-6.0#remarks

// new Win32Exception() is defined as
// public Win32Exception() : this(Marshal.GetLastPInvokeError())
// {
// }

namespace deadlock_dotnet_sdk.Domain;
/// <summary>
/// A SafeFileHandle-like wrapper for the undocumented Windows type "SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX"
/// </summary>
public class SafeFileHandleEx : SafeHandleEx
{
    private (bool? v, Exception? ex) isDirectory;
    private (bool? v, Exception? ex) isFileHandle;
    private (bool? v, Exception? ex) isFilePathRemote;
    private (string? v, Exception? ex) fileFullPath;
    private (FileType? v, Exception? ex) fileHandleType;
    private (string? v, Exception? ex) fileName;
    private (string? v, Exception? ex) fileNameInfo;

    // TODO: there's gotta be a better way to cast a base class to an implementing class
    internal SafeFileHandleEx(SafeHandleEx safeHandleEx) : this(safeHandleEx.SysHandleEx)
    { }

    /// <summary>Initialize</summary>
    /// <param name="sysHandleEx"></param>
    internal SafeFileHandleEx(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX sysHandleEx) : base(sysHandleEx: sysHandleEx)
    {
        if (IsFileHandle.v is true)
        {
            try
            {
                if (ProcessInfo.ProcessProtection.v?.Type is PS_PROTECTION.PS_PROTECTED_TYPE.PsProtectedTypeProtected)
                {
                    if (ProcessInfo.ProcessName.v is "smss")
                        ExceptionLog.Add(new UnauthorizedAccessException($"The Handle's Name is inaccessible because the handle is owned by Windows Session Manager SubSystem ({ProcessInfo.ProcessName}, PID {ProcessId})"));
                    else
                        ExceptionLog.Add(new UnauthorizedAccessException($"The Handle's Name is inaccessible because the handle is owned by {ProcessInfo.ProcessName} (PID {ProcessId})"));
                }
            }
            catch (Exception e)
            {
                ExceptionLog.Add(e);
            }
        }
        else
        {
            ExceptionLog.Add(new InvalidCastException("Cannot cast non-file handle to file handle!"));
        }
    }

    #region Properties

    public (bool? v, Exception? ex) IsDirectory
    {
        get
        {
            if (isDirectory is (null, null))
            {
                if (FileFullPath != default && FileFullPath.v != null) // The comparison *should* cause FileFullPath to initialize.
                {
                    try
                    {
                        return isDirectory = ((File.GetAttributes(FileFullPath.v) & FileAttributes.Directory) == FileAttributes.Directory, null);
                    }
                    catch (Exception ex)
                    {
                        return isDirectory = (null, ex);
                    }
                }

                return isDirectory = (null, new InvalidOperationException("Unable to query IsDirectory; This operation requires FileFullPath."));
            }
            else
            {
                return isDirectory;
            }
        }
    }

    public (bool? v, Exception? ex) IsFileHandle => isFileHandle is (null, null)
                ? HandleObjectType.v == "File"
                    ? (isFileHandle = (true, null))
                    : (isFileHandle = (null, new Exception("Failed to determine if this handle's object is a file/directory; Failed to query the object's type.", HandleObjectType.ex)))
                : isFileHandle;

    /// <summary>
    /// TRUE if the file object's path is a network path i.e. SMB2 network share. FALSE if the file was opened via a local disk path.
    /// -OR-
    /// Exception encountered because GetFileInformationByHandleEx failed
    /// </summary>
    /// <remarks>
    ///     <para>
    ///         GetFileInformationByHandleEx is another poorly documented win32
    ///         function due to the variety of parameters and conditional return
    ///         values. When <see cref="FILE_INFO_BY_HANDLE_CLASS.FileRemoteProtocolInfo"/>
    ///         is passed to the function, it will try to write a
    ///         <see cref="FILE_REMOTE_PROTOCOL_INFO"/> to the supplied buffer.
    ///         If the file handle's path is not remote, then the function
    ///         returns <see cref="Win32ErrorCode.ERROR_INVALID_PARAMETER"/>.
    ///     </para>
    ///     <para>
    ///         For the particulars of GetFileInformationByHandleEx, see...<br/>
    ///         * <seealso href="https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getfileinformationbyhandleex">GetFileInformationByHandleEx function (winbase.h) | Microsoft Learn</seealso><br/>
    ///         * <seealso href="https://stackoverflow.com/a/70466900/14894786">c++ - Detect if file is open locally or over share - Stack Overflow</seealso><br/>
    ///         * <seealso href="https://web.archive.org/web/20190123140707/https://blogs.msdn.microsoft.com/winsdk/2015/06/04/filesystemwatcher-fencingpart-1/">FileSystemWatcher Fencing(Part 1) – Windows SDK Support Team Blog</seealso><br/>
    ///     </para>
    /// </remarks>
    public (bool? v, Exception? ex) IsFilePathRemote
    {
        get
        {
            if (isFilePathRemote is (null, null))
            {
                Win32ErrorCode err;
                FILE_REMOTE_PROTOCOL_INFO info;
                unsafe
                {
                    return GetFileInformationByHandleEx(this, FILE_INFO_BY_HANDLE_CLASS.FileRemoteProtocolInfo, &info, (uint)Marshal.SizeOf(info))
                        ? (isFilePathRemote = (true, null))
                        : (err = (Win32ErrorCode)Marshal.GetLastPInvokeError()) is Win32ErrorCode.ERROR_INVALID_PARAMETER
                            ? (isFilePathRemote = (false, null))
                            : (isFilePathRemote = (null, new Win32Exception(err)));
                }
            }
            else
            {
                return isFilePathRemote;
            }
        }
    }

    /// <summary>
    /// Try to get the absolute path of the file. Traverses filesystem links (e.g. symbolic, junction) to get the 'real' path.
    /// </summary>
    /// <returns>If successful, returns a path string formatted as 'X:\dir\file.ext' or 'X:\dir'</returns>
    /// <remarks>GetFinalPathNameByHandle will sometimes hang when querying the Name of a Pipe.</remarks>
    public unsafe (string? v, Exception? ex) FileFullPath
    {
        get
        {
            if (fileFullPath is (null, null))
            {
                try
                {
                    const string errUnableMsg = "Unable to query " + nameof(FileFullPath) + "; ";
                    const string errFailMsg = "Failed to query " + nameof(FileFullPath) + "; ";
                    if (ProcessInfo.ProcessProtection.v is null)
                        return fileFullPath = (null, new InvalidOperationException(errUnableMsg + "Failed to query the process's protection.", ProcessInfo.ProcessProtection.ex));
                    if (ProcessInfo.ProcessProtection.v?.Type is PS_PROTECTION.PS_PROTECTED_TYPE.PsProtectedTypeProtected)
                        return fileFullPath = (null, new UnauthorizedAccessException(errUnableMsg + "The process is protected."));
                    if (HandleObjectType.v is null)
                        return fileFullPath = (null, new InvalidOperationException(errUnableMsg + "Failed to query handle object type.", HandleObjectType.ex));
                    if (IsFileHandle.v is false)
                        return fileFullPath = (null, new ArgumentException(errUnableMsg + "The handle's object is not a File.", nameof(IsFileHandle)));
                    if (FileHandleType.v is not FileType.Disk)
                        return fileFullPath = (null, new ArgumentException(errUnableMsg + "The File object is not a Disk-type File.", nameof(FileHandleType)));

                    uint bufLength = (uint)short.MaxValue;
                    using PWSTR buffer = new((char*)Marshal.AllocHGlobal((int)bufLength));
                    uint length = 0;
                    const uint LengthIndicatesError = 0;

                    // Try without duplicating. If it fails, try duplicating the handle.
                    Stopwatch sw = Stopwatch.StartNew();
                    try
                    {
                        GETFINALPATHNAMEBYHANDLE_FLAGS flags = IsFilePathRemote.v is true ? GETFINALPATHNAMEBYHANDLE_FLAGS.FILE_NAME_OPENED : GETFINALPATHNAMEBYHANDLE_FLAGS.FILE_NAME_NORMALIZED;
                        Win32ErrorCode errorCode = Win32ErrorCode.ERROR_SUCCESS;
                        length = GetFinalPathNameByHandle(handle, buffer, bufLength, flags);

                        if (length is not LengthIndicatesError)
                        {
                            if (length <= bufLength)
                            {
                                return fileFullPath = (buffer.ToString(), null);
                            }
                            else if (length > bufLength)
                            {
                                using PWSTR newBuffer = new((char*)Marshal.AllocHGlobal((int)length));
                                if ((length = GetFinalPathNameByHandle(handle, newBuffer, length, flags)) is not LengthIndicatesError)
                                    return fileFullPath = (newBuffer.ToString(), null);
                            }
                        }
                        else
                        {
                            errorCode = (Win32ErrorCode)Marshal.GetLastPInvokeError();

                            Trace.TraceError(errorCode.GetMessage());

                            return fileFullPath = (null, errorCode switch
                            {
                                // Removable storage, deleted item, network shares, et cetera
                                Win32ErrorCode.ERROR_PATH_NOT_FOUND => new FileNotFoundException(errFailMsg + $"The path '{buffer}' was not found when querying a file handle.", fileName: buffer.ToString(), new Win32Exception(errorCode)),
                                // unlikely, but possible if system has little free memory
                                Win32ErrorCode.ERROR_NOT_ENOUGH_MEMORY => new OutOfMemoryException(errFailMsg + "Insufficient memory to complete the operation.", new Win32Exception(errorCode)),
                                // possible only if FILE_NAME_NORMALIZED (0) is invalid
                                Win32ErrorCode.ERROR_INVALID_PARAMETER => new ArgumentException("Failed to query path from file handle. Invalid flags were specified for dwFlags.", new Win32Exception(errorCode)),
                                _ => new Exception($"An undocumented error ({errorCode}) was returned when querying a file handle for its path.", new Win32Exception(errorCode))
                            });
                        }
                    }
                    catch (Exception ex)
                    {
                        return fileFullPath = (null, ex);
                    }
                    finally
                    {
                        sw.Stop();
                        Console.WriteLine($"(handle 0x{handle:X}) TryGetFinalPath time: {sw.Elapsed}");
                    }

                    /// Return the normalized drive name. This is the default.
                    using SafeProcessHandle processHandle = OpenProcess_SafeHandle(PROCESS_ACCESS_RIGHTS.PROCESS_DUP_HANDLE, false, ProcessId);
                    if (processHandle is null || processHandle?.IsInvalid == true)
                        throw new Win32Exception();

                    if (!DuplicateHandle(processHandle, this, Process.GetCurrentProcess().SafeHandle, out SafeFileHandle dupHandle, 0, false, DUPLICATE_HANDLE_OPTIONS.DUPLICATE_SAME_ACCESS))
                        throw new Win32Exception();

                    length = GetFinalPathNameByHandle(dupHandle, buffer, bufLength, GETFINALPATHNAMEBYHANDLE_FLAGS.FILE_NAME_NORMALIZED);

                    if (length != 0)
                    {
                        if (length <= bufLength)
                            return fileFullPath = (buffer.ToString(), null);

                        {
                            // buffer was too small. Reallocate buffer with size matched 'length' and try again
                            using PWSTR newBuffer = new((char*)Marshal.AllocHGlobal((int)length));
                            bufLength = GetFinalPathNameByHandle(dupHandle, buffer, bufLength, GETFINALPATHNAMEBYHANDLE_FLAGS.FILE_NAME_NORMALIZED);
                            return fileFullPath = (newBuffer.ToString(), null);
                        }
                    }
                    else
                    {
                        Win32ErrorCode error = (Win32ErrorCode)Marshal.GetLastWin32Error();
                        Trace.TraceError(error.GetMessage());

                        return (null, error switch
                        {
                            // Removable storage, deleted item, network shares, et cetera
                            Win32ErrorCode.ERROR_PATH_NOT_FOUND => new FileNotFoundException($"The path '{buffer}' was not found when querying a file handle.", fileName: buffer.ToString(), new Win32Exception(error)),
                            // unlikely, but possible if system has little free memory
                            Win32ErrorCode.ERROR_NOT_ENOUGH_MEMORY => new OutOfMemoryException("Failed to query path from file handle. Insufficient memory to complete the operation.", new Win32Exception(error)),
                            // possible only if FILE_NAME_NORMALIZED (0) is invalid
                            Win32ErrorCode.ERROR_INVALID_PARAMETER => new ArgumentException("Failed to query path from file handle. Invalid flags were specified for dwFlags.", new Win32Exception(error)),
                            _ => new Exception($"An undocumented error ({error}) was returned when querying a file handle for its path.", new Win32Exception(error))
                        });
                    }
                }
                catch (Exception ex)
                {
                    return fileFullPath = (null, ex);
                }
            }
            else
            {
                return fileFullPath;
            }
        }
    }

    /// <summary>
    /// If the handle object's Type is "File", the type of the File object<br/>
    /// -OR-<br/>
    /// An exception if the P/Invoke operation failed or the object's Type is not "File".
    /// </summary>
    public (FileType? v, Exception? ex) FileHandleType
    {
        get
        {
            if (fileHandleType is (null, null))
            {
                const string unableErr = "Unable to query FileHandleType; ";
                if (ProcessInfo.ProcessProtection.ex is not null)
                    return fileHandleType = (null, new NullReferenceException(unableErr + "Failed to query the process's protection level."));
                if (ProcessInfo.ProcessProtection.ex is not null)
                    return fileHandleType = (null, new UnauthorizedAccessException(unableErr + "The process's protection prohibits this operation."));
                if (IsFileHandle.v is not true)
                    return fileHandleType = (null, new InvalidOperationException(unableErr + "This operation is only valid on File handles."));

                FileType type = (FileType)GetFileType(handle);
                if (type is FileType.Unknown)
                {
                    Win32Exception err = new();
                    return err.NativeErrorCode is Win32ErrorCode.ERROR_SUCCESS ? (fileHandleType = (null, err)) : (fileHandleType = (type, null));
                }
                else
                {
                    return fileHandleType = (type, null);
                }
            }
            else
            {
                return fileHandleType;
            }
        }
    }

    // TODO: leverage GetFileInformationByHandleEx
    public (string? v, Exception? ex) FileName
    {
        get
        {
            if (fileName is (null, null))
            {
                if (FileFullPath.v is not null)
                {
                    return fileName = (Path.GetFileName(FileFullPath.v), null);
                }
                else if (ObjectName.v is not null)
                {
                    return fileName = (Path.GetFileName(ObjectName.v), null);
                }
                else
                {
                    return fileName = (null, new InvalidOperationException("Unable to query FileName; This operation requires FileFullPath."));
                }
            }
            else
            {
                return fileName;
            }
        }
    }

    public unsafe (string? v, Exception? ex) FileNameInfo
    {
        get
        {
            if (fileNameInfo is (null, null))
            {
                const string unableErrMsg = "Unable to query " + nameof(FileNameInfo) + "; ";
                if (ProcessInfo.ProcessProtection.ex is not null)
                    return fileNameInfo = (null, new NullReferenceException(unableErrMsg + "Failed to query the process's protection level.", ProcessInfo.ProcessProtection.ex));
                if (ProcessInfo.ProcessProtection.v?.Type is not PS_PROTECTION.PS_PROTECTED_TYPE.PsProtectedTypeNone)
                    return fileNameInfo = (null, new UnauthorizedAccessException(unableErrMsg + "The process's protection prohibits querying a file handle's FILE_NAME_INFO."));
                if (FileHandleType.v is not FileType.Disk)
                    return fileNameInfo = (null, new InvalidOperationException(unableErrMsg + "FileNameInfo can only be queried for disk-type file handles."));

                /** Get fni.FileNameLength */
                FILE_NAME_INFO fni = default;
                _ = GetFileInformationByHandleEx(this, FILE_INFO_BY_HANDLE_CLASS.FileNameInfo, &fni, (uint)Marshal.SizeOf(fni));

                /** Get FileNameInfo */
                int fniSize = Marshal.SizeOf(fni);
                int bufferLength = (int)(fni.FileNameLength + fniSize);
                FILE_NAME_INFO* buffer = (FILE_NAME_INFO*)Marshal.AllocHGlobal(bufferLength);
                using SafeBuffer<FILE_NAME_INFO> safeBuffer = new(numBytes: (nuint)bufferLength);

                if (GetFileInformationByHandleEx(this, FILE_INFO_BY_HANDLE_CLASS.FileNameInfo, buffer, (uint)bufferLength))
                {
                    UNICODE_STRING str = new()
                    {
                        Buffer = new PWSTR((char*)safeBuffer.DangerousGetHandle()),
                        Length = (ushort)fni.FileNameLength,
                        MaximumLength = (ushort)bufferLength
                    };

                    /* The string conversion copies the data to a new string in the managed heap before freeing safeBuffer and leaving this context. */
                    return fileNameInfo = ((string)str, null);
                }
                else
                {
                    return fileNameInfo = (null, new Exception("Failed to query FileNameInfo; GetFileInformationByHandleEx encountered an error.", new Win32Exception()));
                }
            }
            else
            {
                return fileNameInfo;
            }
        }
    }

    #endregion Properties

    public enum FileType : uint
    {
        /// <summary>Either the type of the specified file is unknown, or the function failed.</summary>
        Unknown = FILE_TYPE.FILE_TYPE_UNKNOWN,
        /// <summary>The specified file is a disk file.</summary>
        Disk = FILE_TYPE.FILE_TYPE_DISK,
        /// <summary>The specified file is a character file, typically an LPT device or a console.</summary>
        Char = FILE_TYPE.FILE_TYPE_CHAR,
        /// <summary>The specified file is a socket, a named pipe, or an anonymous pipe.</summary>
        Pipe = FILE_TYPE.FILE_TYPE_PIPE,
    }

    public override string ToString() => ToString(true);

    /// <summary>
    /// Get the string representation of this SafeFileHandleEx object.
    /// </summary>
    /// <param name="init">If TRUE, get values from Properties. If FALSE, get values from Properties' backing fields.</param>
    /// <returns>The string representation of this SafeFileHandleEx object.</returns>
    public string ToString(bool init)
    {
        string[] exLog = ExceptionLog.ConvertAll(ex => ex.ToString()).ToArray();
        for (int i = 0; i < exLog.Length; i++)
        {
            exLog[i] = $" {exLog[i]}".Replace("\n", "\n    ") + "\r\n";
        }

        return @$"{nameof(SafeFileHandleEx)} hash:{GetHashCode()}
        {nameof(CreatorBackTraceIndex)}             : {CreatorBackTraceIndex}
        {nameof(FileFullPath)}                      : {(init ? (FileFullPath.v ?? FileFullPath.ex?.ToString()) : (fileFullPath.v ?? fileFullPath.ex?.ToString()))}
        {nameof(FileHandleType)}                    : {(init ? (FileHandleType.v?.ToString() ?? FileFullPath.ex?.ToString()) : (fileHandleType.v?.ToString() ?? fileHandleType.ex?.ToString()))}
        {nameof(FileName)}                          : {(init ? (FileName.v ?? FileName.ex?.ToString()) : (fileName.v ?? fileName.ex?.ToString()))}
        {nameof(GrantedAccess)}                     : {SysHandleEx.GrantedAccessString}
        {nameof(HandleObjectType)}                  : {(init ? (HandleObjectType.v ?? HandleObjectType.ex?.ToString()) : (handleObjectType.v ?? handleObjectType.ex?.ToString()))}
        {nameof(HandleValue)}                       : {HandleValue} (0x{HandleValue:X})
        {nameof(IsClosed)}                          : {IsClosed}
        {nameof(IsDirectory)}                       : {(init ? (IsDirectory.v?.ToString() ?? IsDirectory.ex?.ToString()) : (isDirectory.v?.ToString() ?? isDirectory.ex?.ToString()))}
        {nameof(IsFileHandle)}                      : {(init ? (IsFileHandle.v?.ToString() ?? IsFileHandle.ex?.ToString()) : (isFileHandle.v?.ToString() ?? isFileHandle.ex?.ToString()))}
        {nameof(IsInvalid)}                         : {IsInvalid}
        {nameof(ObjectAddress)}                     : {ObjectAddress} (0x{ObjectAddress:X})
        {nameof(ObjectName)}                        : {(init ? (ObjectName.v ?? ObjectName.ex?.ToString()) : (objectName.v ?? objectName.ex?.ToString()))}
        {nameof(ProcessId)}                         : {ProcessId}
        {nameof(ProcessInfo.ParentId)}              : {ProcessInfo.ParentId.v?.ToString() ?? ProcessInfo.ParentId.ex?.ToString() ?? string.Empty}
        {nameof(ProcessInfo.ProcessCommandLine)}    : {ProcessInfo.ProcessCommandLine.v ?? ProcessInfo.ProcessCommandLine.ex?.ToString()}
        {nameof(ProcessInfo.ProcessMainModulePath)} : {ProcessInfo.ProcessMainModulePath.v ?? ProcessInfo.ProcessMainModulePath.ex?.ToString()}
        {nameof(ProcessInfo.ProcessName)}           : {ProcessInfo.ProcessName.v ?? ProcessInfo.ProcessName.ex?.ToString()}
        {nameof(ProcessInfo.ProcessProtection)}     : {ProcessInfo.ProcessProtection.v?.ToString() ?? ProcessInfo.ProcessProtection.ex?.ToString() ?? string.Empty}
        {nameof(ExceptionLog)}                      : ...
        " + string.Concat(exLog);
    }
}
