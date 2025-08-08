using System.Reflection;
using System.Runtime.InteropServices;

namespace nebulae.dotXChaCha20Poly1305;

internal static class XChaCha20Poly1305Library
{
    private static bool _isLoaded;

    internal static void Init()
    {
        if (_isLoaded) return;
        NativeLibrary.SetDllImportResolver(typeof(XChaCha20Poly1305Library).Assembly, Resolve);
        _isLoaded = true;
    }

    private static IntPtr Resolve(string libraryName, Assembly assembly, DllImportSearchPath? searchPath)
    {
        if (libraryName != "xchacha20poly1305")
            return IntPtr.Zero;

        var libName = GetPlatformLibraryName();
        var assemblyDir = Path.GetDirectoryName(typeof(XChaCha20Poly1305Library).Assembly.Location)!;
        var fullPath = Path.Combine(assemblyDir, libName);

        if (!File.Exists(fullPath))
            throw new DllNotFoundException($"Could not find native XChaCha20Poly1305 library at {fullPath}");

        return NativeLibrary.Load(fullPath);
    }

    private static string GetPlatformLibraryName()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return Path.Combine("runtimes", "win-x64", "native", "xchacha20poly1305.dll");

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            return Path.Combine("runtimes", "linux-x64", "native", "libxchacha20poly1305.so");

        if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            if (RuntimeInformation.ProcessArchitecture == Architecture.Arm64)
                return Path.Combine("runtimes", "osx-arm64", "native", "libxchacha20poly1305.dylib");

            return Path.Combine("runtimes", "osx-x64", "native", "libxchacha20poly1305.dylib");
        }

        throw new PlatformNotSupportedException("Unsupported platform");
    }
}
