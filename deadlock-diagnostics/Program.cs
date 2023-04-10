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

    DeadLock? dl = new(false);
    FileLockerEx? fileLockerEx = default;

    var sw = Stopwatch.StartNew();
    try
    {
        Process.EnterDebugMode();
        fileLockerEx = dl.FindLockingHandles(filePath: @"C:\", FilesOnly | IncludeFailedTypeQuery | IncludeNonFiles, out WarningException? warningException);
        sw.Stop();
        Console.WriteLine(sw.Elapsed);
        if (warningException is not null) Console.WriteLine(warningException.ToString());
    }
    catch (Exception e)
    {
        Console.WriteLine(e.ToString());
        dl.RethrowExceptions = false;
    }

    if (fileLockerEx is not null)
    {
        Console.WriteLine($"{nameof(fileLockerEx)} is not null.");
        Console.WriteLine(fileLockerEx.Path);

        // https://learn.microsoft.com/en-us/dotnet/standard/serialization/system-text-json/source-generation
        Console.WriteLine(fileLockerEx.Lockers.ToString());
    }

    Console.WriteLine("Does this look right?");
}
