using System.ComponentModel;
using System.Diagnostics;
using deadlock_dotnet_sdk;
using deadlock_dotnet_sdk.Domain;
using PInvoke;
using static deadlock_dotnet_sdk.Domain.FileLockerEx.HandlesFilter;

if (!UACHelper.UACHelper.IsElevated)
{
    Console.WriteLine("Administrative permissions required for operation.");
}
else
{
    const string filePath = @"C:\new.txt";
    Console.WriteLine("Hello, World!");
    Console.WriteLine(@"Opening file handle for C:\new.txt");
    Console.WriteLine("TODO: Why does Console.WriteLine seem to do nothing when called on a worker thread (async)?");
    using FileStream file0 = File.Open(filePath, FileMode.OpenOrCreate, FileAccess.ReadWrite);

    DeadLock? dl = new(false);
    FileLockerEx? fileLockerEx = null;

    var sw = Stopwatch.StartNew();
    try
    {
        fileLockerEx = dl.FindLockingHandles(filePath: filePath, FilesOnly/*  | IncludeFailedTypeQuery | IncludeNonFiles | IncludeProtectedProcesses */, out WarningException? warningException);
        sw.Stop();
        Console.WriteLine(sw.Elapsed);
        if (warningException is not null)
            Console.WriteLine(warningException.ToString());
    }
    catch (Exception e)
    {
        sw.Stop();
        Console.WriteLine(e.ToString());
        dl.RethrowExceptions = false;
    }

    if (fileLockerEx is not null)
    {
        const string n_fileLockerEx = nameof(fileLockerEx);
        const string n_Path = n_fileLockerEx + "." + nameof(fileLockerEx.Path);
        const string n_Lockers = n_fileLockerEx + "." + nameof(fileLockerEx.Lockers);
        const string n_Count = n_Lockers + "." + nameof(fileLockerEx.Lockers.Count);

        Console.WriteLine(n_fileLockerEx + " (" + fileLockerEx.GetHashCode() + ") is not null.");
        Console.WriteLine(n_Path + ": " + fileLockerEx.Path);
        Console.WriteLine(n_Count + ": " + fileLockerEx.Lockers.Count);

        // https://learn.microsoft.com/en-us/dotnet/standard/serialization/system-text-json/source-generation
        foreach (var locker in fileLockerEx.Lockers)
        {
            Console.WriteLine("Blindly attempting to close the following handle...\r\n" + locker.ToString());
            bool success = false;

            try
            {
                success = locker.CloseSourceHandle(true);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(ex.ToString());
            }

            Console.WriteLine("Attempt succeeded? [" + success + "]");
        }

        try
        {
            Console.WriteLine("Double-checking the test handles status...");

            var type = Windows.Win32.PInvoke.GetFileType(file0.SafeFileHandle);
            var err = (Win32ErrorCode)System.Runtime.InteropServices.Marshal.GetLastPInvokeError(); //DevSkim: ignore DS104456 // This DevSkim rule prohibits use of the Marshal class. Why? https://sourcegraph.com/github.com/microsoft/DevSkim@main/-/blob/rules/default/security/control_flow/permission_evelation.json?L29-55

            Console.WriteLine(type is Windows.Win32.Storage.FileSystem.FILE_TYPE.FILE_TYPE_UNKNOWN && err is Win32ErrorCode.ERROR_INVALID_HANDLE
                ? "The operation succeeded. GetFileType says the handle is invalid/closed."
                : "The operation failed; " + (err is Win32ErrorCode.ERROR_SUCCESS ? "The handle is still open." : err.GetMessage()));
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex);
        }
    }

    Console.WriteLine("Does this look right?");
}
