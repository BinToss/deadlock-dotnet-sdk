using System.ComponentModel;
using System.Diagnostics;
using deadlock_dotnet_sdk;
using deadlock_dotnet_sdk.Domain;
using static deadlock_dotnet_sdk.Domain.FileLockerEx.HandlesFilter;

if (!UACHelper.UACHelper.IsElevated)
{
    Console.WriteLine("Administrative permissions required for operation.");
}
else
{
    Console.WriteLine("Hello, World!");
    Console.WriteLine(@"Opening file handle for C:\new.txt");
    Console.WriteLine("TODO: Why does Console.WriteLine seem to do nothing when called on a worker thread (async)?");
    File.Open(@"C:\new.txt", FileMode.OpenOrCreate, FileAccess.ReadWrite);

    DeadLock? dl = new(false);
    FileLockerEx? fileLockerEx = null;

    var sw = Stopwatch.StartNew();
    try
    {
        fileLockerEx = dl.FindLockingHandles(filePath: @"C:\new.txt", FilesOnly/*  | IncludeFailedTypeQuery | IncludeNonFiles | IncludeProtectedProcesses */, out WarningException? warningException);
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
        Console.WriteLine($"{nameof(fileLockerEx)} is not null.");
        Console.WriteLine(fileLockerEx.Path);

        // https://learn.microsoft.com/en-us/dotnet/standard/serialization/system-text-json/source-generation
        foreach (var locker in fileLockerEx.Lockers)
        {
            Console.WriteLine(locker);
        }
    }

    Console.WriteLine("Does this look right?");
}
