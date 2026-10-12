using System.Runtime.InteropServices;
using System.Text;

namespace Rudy.Evidence;

/// <summary>Length-delimited UTF-8 JSON API. Load only a trusted native library.</summary>
public static class Evidence
{
    [StructLayout(LayoutKind.Sequential)]
    private struct Buffer { public IntPtr Data; public nuint Size; }

    static Evidence()
    {
        NativeLibrary.SetDllImportResolver(typeof(Evidence).Assembly, (name, assembly, path) =>
        {
            if (name != "rudy_evidence") return IntPtr.Zero;
            string? location = Environment.GetEnvironmentVariable("RUDY_EVIDENCE_LIBRARY");
            if (string.IsNullOrEmpty(location) || !Path.IsPathFullyQualified(location))
                throw new InvalidOperationException("Set RUDY_EVIDENCE_LIBRARY to an absolute trusted library path.");
            return NativeLibrary.Load(location);
        });
        if (AbiVersion() != 1) throw new InvalidOperationException("Unsupported Rudy Evidence C ABI.");
    }

    [DllImport("rudy_evidence", EntryPoint = "re_abi_version", CallingConvention = CallingConvention.Cdecl)]
    private static extern uint AbiVersion();
    [DllImport("rudy_evidence", EntryPoint = "re_process", CallingConvention = CallingConvention.Cdecl)]
    private static extern int ProcessNative(byte[] request, nuint length, ref Buffer result, ref Buffer error);
    [DllImport("rudy_evidence", EntryPoint = "re_free", CallingConvention = CallingConvention.Cdecl)]
    private static extern void Free(ref Buffer buffer);

    private static string Read(Buffer buffer)
    {
        int count = checked((int)buffer.Size);
        byte[] data = new byte[count];
        if (count > 0) Marshal.Copy(buffer.Data, data, 0, count);
        return new UTF8Encoding(false, true).GetString(data);
    }

    /// <summary>Process one JSON request; throws ArgumentException for rejected input.</summary>
    public static string Process(string request)
    {
        byte[] bytes = new UTF8Encoding(false, true).GetBytes(request);
        Buffer result = default, error = default;
        try
        {
            int status = ProcessNative(bytes, (nuint)bytes.Length, ref result, ref error);
            if (status != 0) throw new ArgumentException(error.Data == IntPtr.Zero ? "Native API call failed." : Read(error));
            return Read(result);
        }
        finally { Free(ref result); Free(ref error); }
    }
}
