// This file is used to extend the partial definitions generated by CsWin32

using System.ComponentModel;
using System.Runtime.InteropServices;
using Windows.Win32.System.Threading;

namespace Windows.Win32
{
    namespace Foundation
    {
        internal partial struct HANDLE : IComparable<HANDLE>
        {
            public static implicit operator HANDLE(nuint v) => new((nint)v);
            public static implicit operator nuint(HANDLE v) => (nuint)(nint)v.Value;

            public static implicit operator HANDLE(nint v) => new(v);
            public static implicit operator nint(HANDLE v) => v.Value;

            /// <summary>
            /// Close the handle via the CloseHandle function
            /// </summary>
            /// <exception cref="Win32Exception">
            /// If the application is running under a debugger, the function will throw an
            /// exception if it receives either a handle value that is not valid or a
            /// pseudo-handle value. This can happen if you close a handle twice, or if you
            /// call CloseHandle on a handle returned by the FindFirstFile function instead
            /// of calling the FindClose function.
            /// </exception>
            public void Close()
            {
                if (!PInvoke.CloseHandle(this))
                    throw new Win32Exception();
            }

            public int CompareTo(HANDLE other) => Value.CompareTo(other);
        }

        internal readonly partial struct NTSTATUS
        {
            public bool IsSuccessful => SeverityCode == Severity.Success;

            public NTStatusException GetNTStatusException() => new(this);

            public static implicit operator NTSTATUS_plus(NTSTATUS v) => new(v.Value);
            public static implicit operator NTSTATUS(NTSTATUS_plus v) => new(v.AsInt32);
        }

        internal unsafe readonly partial struct PWSTR : IDisposable
        {
            /// <summary>
            /// Free the PWSTR's memory with Marshal.FreeHGlobal(IntPtr)
            /// </summary>
            public void Dispose() => Marshal.FreeHGlobal((IntPtr)Value);

            public static implicit operator PWSTR(IntPtr v) => new((char*)v);
        }

        internal partial struct UNICODE_STRING
        {
            /// <summary>
            /// Allocates a managed string and copies a specified number of characters from an unmanaged Unicode string into it.
            /// </summary>
            public unsafe string ToStringLength() => Marshal.PtrToStringUni((IntPtr)Buffer.Value, Length);
            public string? ToStringZ() => Buffer.ToString();
            public static explicit operator string(UNICODE_STRING v) => v.ToStringLength();
        }
    }

    namespace Security
    {
        /// <summary>
        /// A simple placeholder for dotnet/PInvoke's ACCESS_MASK struct
        /// </summary>
        /// <remarks>Process access modifiers are found in Windows.Win32.System.Threading.PROCESS_ACCESS_RIGHTS</remarks>
        internal struct ACCESS_MASK
        {
            public ACCESS_MASK(uint v)
            {
                Value = v;
            }

            public uint Value;
            public PROCESS_ACCESS_RIGHTS ProcessAccess => (PROCESS_ACCESS_RIGHTS)Value;

            public static implicit operator ACCESS_MASK(uint v) => new(v);
            public static implicit operator uint(ACCESS_MASK v) => v.Value;

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
    }

    namespace System.WindowsProgramming
    {
        // generated definition lacks SystemHandleInformation, SystemExtendedHandleInformation
        internal enum SYSTEM_INFORMATION_CLASS
        {
            SystemBasicInformation = 0,
            SystemPerformanceInformation = 2,
            SystemTimeOfDayInformation = 3,
            SystemProcessInformation = 5,
            SystemProcessorPerformanceInformation = 8,
            SystemHandleInformation = 16,
            SystemInterruptInformation = 23,
            SystemExceptionInformation = 33,
            SystemRegistryQuotaInformation = 37,
            SystemLookasideInformation = 45,
            SystemExtendedHandleInformation = 64,
            SystemCodeIntegrityInformation = 103,
            SystemPolicyInformation = 134
        }

        internal enum OBJECT_INFORMATION_CLASS
        {
            ObjectBasicInformation = 0,
            ObjectNameInformation = 1,
            ObjectTypeInformation = 2,
        }
    }

    namespace System.Threading
    {
        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        internal unsafe delegate void PS_POST_PROCESS_INIT_ROUTINE();

        // Function Pointer workaround. C# 9's function pointers are only allowed in local scope.
        internal struct PPS_POST_PROCESS_INIT_ROUTINE : IEquatable<PPS_POST_PROCESS_INIT_ROUTINE>
        {
            public IntPtr Value;

            public static explicit operator PPS_POST_PROCESS_INIT_ROUTINE(IntPtr v)
            {
                try
                {
                    _ = Marshal.GetDelegateForFunctionPointer<PS_POST_PROCESS_INIT_ROUTINE>(v);
                    return new() { Value = v };
                }
                catch (Exception)
                {
                    // not a delegate or open generic type
                    // or ptr is null
                    return new() { Value = IntPtr.Zero };
                }
            }

            public bool Equals(PPS_POST_PROCESS_INIT_ROUTINE other) => Value == other.Value;

            public override bool Equals(object obj)
                => obj is PPS_POST_PROCESS_INIT_ROUTINE pPS_POST_PROCESS_INIT_ROUTINE && Equals(pPS_POST_PROCESS_INIT_ROUTINE);
        }

        [global::System.CodeDom.Compiler.GeneratedCode("Microsoft.Windows.CsWin32", "0.2.46-beta+0e9cbfc7b9")]
        internal struct PROCESS_BASIC_INFORMATION
        {
            internal unsafe void* Reserved1;
            internal unsafe PEB* PebBaseAddress;
            internal __IntPtr_2 Reserved2;
            internal nuint UniqueProcessId;
            internal unsafe void* Reserved3;

            internal struct __IntPtr_2
            {
                internal IntPtr _0, _1;

                /// <summary>Always <c>2</c>.</summary>
                internal readonly int Length => 2;

                /// <summary>
                /// Gets a ref to an individual element of the inline array.
                /// ⚠ Important ⚠: When this struct is on the stack, do not let the returned reference outlive the stack frame that defines it.
                /// </summary>
                internal ref IntPtr this[int index] => ref AsSpan()[index];

                /// <summary>
                /// Gets this inline array as a span.
                /// </summary>
                /// <remarks>
                /// ⚠ Important ⚠: When this struct is on the stack, do not let the returned span outlive the stack frame that defines it.
                /// </remarks>
                internal Span<IntPtr> AsSpan() => MemoryMarshal.CreateSpan(ref _0, 2);
            }
        }
    }
}
