using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

static class Native
{
    public const int NETWORK = 0;
    public const int FLOW = 2;
    public const ulong SNIFF = 0x0001;
    public const ulong RECV_ONLY = 0x0004;
    public const int FLOW_ESTABLISHED = 1;
    public const int FLOW_DELETED = 2;
    public static readonly IntPtr INVALID_HANDLE = new IntPtr(-1);

    [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    public static extern IntPtr WinDivertOpen(string filter, int layer, short priority, ulong flags);

    [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertRecv(IntPtr handle, byte[] packet, uint packetLen, out uint recvLen, byte[] address);

    [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertSend(IntPtr handle, byte[] packet, uint packetLen, out uint sendLen, byte[] address);

    [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertClose(IntPtr handle);

    [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertHelperCalcChecksums(byte[] packet, uint packetLen, byte[] address, ulong flags);
}

sealed class FlowKey : IEquatable<FlowKey>
{
    public readonly byte Protocol;
    public readonly ushort LocalPort;
    public readonly ushort RemotePort;
    public readonly string LocalAddr;
    public readonly string RemoteAddr;

    public FlowKey(byte protocol, ushort localPort, ushort remotePort, byte[] localAddr, byte[] remoteAddr)
    {
        Protocol = protocol;
        LocalPort = localPort;
        RemotePort = remotePort;
        LocalAddr = BitConverter.ToString(localAddr);
        RemoteAddr = BitConverter.ToString(remoteAddr);
    }

    public bool Equals(FlowKey other)
    {
        return other != null &&
               Protocol == other.Protocol &&
               LocalPort == other.LocalPort &&
               RemotePort == other.RemotePort &&
               LocalAddr == other.LocalAddr &&
               RemoteAddr == other.RemoteAddr;
    }

    public override bool Equals(object obj) { return Equals(obj as FlowKey); }

    public override int GetHashCode()
    {
        unchecked
        {
            int h = 17;
            h = h * 31 + Protocol;
            h = h * 31 + LocalPort;
            h = h * 31 + RemotePort;
            h = h * 31 + LocalAddr.GetHashCode();
            h = h * 31 + RemoteAddr.GetHashCode();
            return h;
        }
    }

    public override string ToString()
    {
        return string.Format("{0} {1}:{2} -> {3}:{4}",
            Protocol == 6 ? "TCP" : "UDP", LocalAddr, LocalPort, RemoteAddr, RemotePort);
    }
}

sealed class FlowInfo
{
    public int Pid;
    public string Name;
}

sealed class PacketInfo
{
    public byte Protocol;
    public int PayloadOffset;
    public int PayloadLength;
    public ushort SrcPort;
    public ushort DstPort;
    public byte[] SrcAddr;
    public byte[] DstAddr;

    public FlowKey Key()
    {
        return new FlowKey(Protocol, SrcPort, DstPort, SrcAddr, DstAddr);
    }
}

static class Parser
{
    public static bool TryParse(byte[] p, int len, out PacketInfo info)
    {
        info = null;
        if (len < 20) return false;

        int version = p[0] >> 4;
        if (version == 4) return ParseV4(p, len, out info);
        if (version == 6) return ParseV6(p, len, out info);
        return false;
    }

    static ushort U16(byte[] p, int i)
    {
        return (ushort)((p[i] << 8) | p[i + 1]);
    }

    static bool ParseV4(byte[] p, int len, out PacketInfo info)
    {
        info = null;
        int ihl = (p[0] & 0x0F) * 4;
        if (ihl < 20 || ihl + 8 > len) return false;

        byte proto = p[9];
        if (proto != 6 && proto != 17) return false;

        ushort frag = U16(p, 6);
        if ((frag & 0x1FFF) != 0) return false;

        int transport = ihl;
        ushort sp = U16(p, transport);
        ushort dp = U16(p, transport + 2);
        int payload = transport + 8;

        if (proto == 6)
        {
            int th = (p[transport + 12] >> 4) * 4;
            if (th < 20 || transport + th > len) return false;
            payload = transport + th;
        }

        byte[] src = new byte[16];
        byte[] dst = new byte[16];
        src[10] = 0xFF; src[11] = 0xFF;
        dst[10] = 0xFF; dst[11] = 0xFF;
        Buffer.BlockCopy(p, 12, src, 12, 4);
        Buffer.BlockCopy(p, 16, dst, 12, 4);

        info = new PacketInfo
        {
            Protocol = proto,
            PayloadOffset = payload,
            PayloadLength = len - payload,
            SrcPort = sp,
            DstPort = dp,
            SrcAddr = src,
            DstAddr = dst
        };
        return true;
    }

    static bool ParseV6(byte[] p, int len, out PacketInfo info)
    {
        info = null;
        if (len < 48) return false;

        byte next = p[6];
        int o = 40;

        for (int guard = 0; guard < 8; guard++)
        {
            if (next == 6 || next == 17) break;

            if (next == 0 || next == 43 || next == 60)
            {
                if (o + 2 > len) return false;
                int ext = (p[o + 1] + 1) * 8;
                if (o + ext > len) return false;
                next = p[o];
                o += ext;
                continue;
            }

            if (next == 44)
            {
                if (o + 8 > len) return false;
                ushort f = U16(p, o + 2);
                if ((f & 0xFFF8) != 0) return false;
                next = p[o];
                o += 8;
                continue;
            }

            if (next == 51)
            {
                if (o + 2 > len) return false;
                int ext = (p[o + 1] + 2) * 4;
                if (o + ext > len) return false;
                next = p[o];
                o += ext;
                continue;
            }

            return false;
        }

        if (next != 6 && next != 17) return false;
        if (o + 8 > len) return false;

        ushort sp = U16(p, o);
        ushort dp = U16(p, o + 2);
        int payload = o + 8;

        if (next == 6)
        {
            int th = (p[o + 12] >> 4) * 4;
            if (th < 20 || o + th > len) return false;
            payload = o + th;
        }

        byte[] src = new byte[16];
        byte[] dst = new byte[16];
        Buffer.BlockCopy(p, 8, src, 0, 16);
        Buffer.BlockCopy(p, 24, dst, 0, 16);

        info = new PacketInfo
        {
            Protocol = next,
            PayloadOffset = payload,
            PayloadLength = len - payload,
            SrcPort = sp,
            DstPort = dp,
            SrcAddr = src,
            DstAddr = dst
        };
        return true;
    }
}

sealed class Editor
{
    readonly string targetExe;
    readonly ConcurrentDictionary<FlowKey, FlowInfo> flows =
        new ConcurrentDictionary<FlowKey, FlowInfo>();
    readonly CancellationTokenSource cts = new CancellationTokenSource();
    IntPtr flowHandle = IntPtr.Zero;
    IntPtr netHandle = IntPtr.Zero;

    public Editor(string exe)
    {
        targetExe = Path.GetFileName(exe ?? "");
    }

    public void Run(string launch)
    {
        EnsureAdmin();

        flowHandle = Native.WinDivertOpen(
            "true", Native.FLOW, 0, Native.SNIFF | Native.RECV_ONLY);

        if (flowHandle == Native.INVALID_HANDLE)
            throw new InvalidOperationException(
                "Could not open WinDivert FLOW handle. Error " +
                Marshal.GetLastWin32Error());

        netHandle = Native.WinDivertOpen(
            "outbound and (tcp or udp)", Native.NETWORK, 0, 0);

        if (netHandle == Native.INVALID_HANDLE)
            throw new InvalidOperationException(
                "Could not open WinDivert NETWORK handle. Error " +
                Marshal.GetLastWin32Error());

        Console.Title = "PacketEditor";
        Console.WriteLine("============================================================");
        Console.WriteLine(" PacketEditor - process-aware packet interceptor");
        Console.WriteLine("============================================================");
        Console.WriteLine("[+] Target: " + targetExe);

        Task ft = Task.Run(FlowLoop);
        Task nt = Task.Run(NetworkLoop);

        if (!string.IsNullOrWhiteSpace(launch))
        {
            string full = Path.GetFullPath(launch);
            Console.WriteLine("[+] Launching: " + full);
            Process.Start(new ProcessStartInfo
            {
                FileName = full,
                UseShellExecute = true,
                WorkingDirectory = Path.GetDirectoryName(full) ?? Environment.CurrentDirectory
            });
        }

        Console.WriteLine("[+] Running. Ctrl+C stops PacketEditor.");
        Console.CancelKeyPress += delegate(object s, ConsoleCancelEventArgs e)
        {
            e.Cancel = true;
            cts.Cancel();
        };

        try
        {
            Task.WaitAll(ft, nt);
        }
        catch
        {
        }
        finally
        {
            Cleanup();
        }
    }

    void FlowLoop()
    {
        byte[] addr = new byte[80];
        byte[] dummy = new byte[1];

        while (!cts.IsCancellationRequested)
        {
            uint recv;
            Array.Clear(addr, 0, addr.Length);

            bool ok = Native.WinDivertRecv(
                flowHandle, dummy, 0, out recv, addr);

            if (!ok)
            {
                if (cts.IsCancellationRequested) break;
                continue;
            }

            int layer = addr[8];
            int evt = addr[9];
            if (layer != Native.FLOW) continue;

            try
            {
                int pid = BitConverter.ToInt32(addr, 32);
                byte proto = addr[72];

                byte[] local = new byte[16];
                byte[] remote = new byte[16];
                Buffer.BlockCopy(addr, 36, local, 0, 16);
                Buffer.BlockCopy(addr, 52, remote, 0, 16);

                ushort lp = ParserPort(addr, 68);
                ushort rp = ParserPort(addr, 70);

                FlowKey key = new FlowKey(proto, lp, rp, local, remote);

                if (evt == Native.FLOW_ESTABLISHED)
                {
                    string name;
                    if (IsTarget(pid, out name))
                    {
                        flows[key] = new FlowInfo { Pid = pid, Name = name };
                        Console.WriteLine("[FLOW +] PID " + pid + " " + name +
                                          ": " + key);
                    }
                }
                else if (evt == Native.FLOW_DELETED)
                {
                    FlowInfo removed;
                    if (flows.TryRemove(key, out removed))
                    {
                        Console.WriteLine("[FLOW -] PID " + removed.Pid +
                                          " " + removed.Name + ": " + key);
                    }
                }
            }
            catch
            {
            }
        }
    }

    static ushort ParserPort(byte[] b, int o)
    {
        return (ushort)((b[o] << 8) | b[o + 1]);
    }

    bool IsTarget(int pid, out string name)
    {
        name = "?";
        try
        {
            using (Process p = Process.GetProcessById(pid))
            {
                name = p.ProcessName + ".exe";
                return string.Equals(name, targetExe,
                    StringComparison.OrdinalIgnoreCase);
            }
        }
        catch
        {
            return false;
        }
    }

    void NetworkLoop()
    {
        byte[] packet = new byte[65535];
        byte[] addr = new byte[80];

        while (!cts.IsCancellationRequested)
        {
            uint recv;
            Array.Clear(addr, 0, addr.Length);

            bool ok = Native.WinDivertRecv(
                netHandle, packet, (uint)packet.Length, out recv, addr);

            if (!ok)
            {
                if (cts.IsCancellationRequested) break;
                continue;
            }

            int len = checked((int)recv);

            try
            {
                PacketInfo info;
                if (!Parser.TryParse(packet, len, out info))
                {
                    Pass(packet, len, addr);
                    continue;
                }

                FlowInfo owner;
                if (info.PayloadLength <= 0 ||
                    !flows.TryGetValue(info.Key(), out owner))
                {
                    Pass(packet, len, addr);
                    continue;
                }

                byte[] edited = new byte[len];
                Buffer.BlockCopy(packet, 0, edited, 0, len);

                Decision d = Prompt(owner, info, edited);

                if (d == Decision.Drop)
                {
                    Console.WriteLine("  [DROP]");
                    continue;
                }

                Native.WinDivertHelperCalcChecksums(
                    edited, (uint)len, addr, 0);

                Pass(edited, len, addr);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Packet error: " + ex.Message);
                try { Pass(packet, len, addr); } catch { }
            }
        }
    }

    enum Decision { Send, Drop }

    Decision Prompt(FlowInfo owner, PacketInfo info, byte[] packet)
    {
        byte[] payload = new byte[info.PayloadLength];
        Buffer.BlockCopy(packet, info.PayloadOffset, payload, 0, payload.Length);

        Console.WriteLine();
        Console.WriteLine("[INTERCEPT] PID " + owner.Pid + " " + owner.Name +
                          " | " + info.Key() +
                          " | payload=" + payload.Length + " bytes");

        int n = Math.Min(payload.Length, 160);
        string hex = BitConverter.ToString(payload, 0, n).Replace("-", " ");
        string asc = new string(
            payload.Take(n).Select(delegate(byte b)
                { return b >= 32 && b <= 126 ? (char)b : '.'; }).ToArray());

        Console.WriteLine("  HEX: " + hex);
        Console.WriteLine("  ASC: " + asc);
        if (payload.Length > n)
            Console.WriteLine("  ... " + (payload.Length - n) + " more bytes");

        Console.Write("  edit> ");
        string line = (Console.ReadLine() ?? "").Trim();

        if (line.Length == 0)
            return Decision.Send;

        if (line.Equals("d", StringComparison.OrdinalIgnoreCase))
            return Decision.Drop;

        if (line.StartsWith("set ", StringComparison.OrdinalIgnoreCase))
        {
            if (!ApplyHex(payload, line.Substring(4)))
                Console.WriteLine("  [!] Invalid edit; packet passes unchanged.");
        }
        else if (line.StartsWith("text ", StringComparison.OrdinalIgnoreCase))
        {
            if (!ApplyText(payload, line.Substring(5)))
                Console.WriteLine("  [!] Invalid edit; packet passes unchanged.");
        }
        else
        {
            Console.WriteLine("  [!] Unknown command; packet passes unchanged.");
        }

        Buffer.BlockCopy(payload, 0, packet, info.PayloadOffset, payload.Length);
        return Decision.Send;
    }

    static bool ApplyHex(byte[] payload, string args)
    {
        string[] parts = args.Trim().Split(
            new[] { ' ', '\\t' }, 2,
            StringSplitOptions.RemoveEmptyEntries);

        if (parts.Length != 2) return false;

        int offset;
        if (!int.TryParse(parts[0], out offset) ||
            offset < 0 || offset >= payload.Length)
            return false;

        string hex = parts[1].Replace(" ", "").Replace("-", "");
        if (hex.Length == 0 || (hex.Length & 1) != 0) return false;

        int count = hex.Length / 2;
        if (offset + count > payload.Length) return false;

        try
        {
            for (int i = 0; i < count; i++)
                payload[offset + i] =
                    Convert.ToByte(hex.Substring(i * 2, 2), 16);
            return true;
        }
        catch
        {
            return false;
        }
    }

    static bool ApplyText(byte[] payload, string args)
    {
        string[] parts = args.Trim().Split(
            new[] { ' ', '\\t' }, 2,
            StringSplitOptions.RemoveEmptyEntries);

        if (parts.Length != 2) return false;

        int offset;
        if (!int.TryParse(parts[0], out offset) ||
            offset < 0 || offset >= payload.Length)
            return false;

        byte[] text = Encoding.UTF8.GetBytes(parts[1]);
        if (offset + text.Length > payload.Length) return false;

        Buffer.BlockCopy(text, 0, payload, offset, text.Length);
        return true;
    }

    void Pass(byte[] packet, int len, byte[] addr)
    {
        uint sent;
        if (!Native.WinDivertSend(
            netHandle, packet, (uint)len, out sent, addr))
        {
            throw new InvalidOperationException(
                "WinDivertSend failed: " + Marshal.GetLastWin32Error());
        }
    }

    void Cleanup()
    {
        try { cts.Cancel(); } catch { }

        if (flowHandle != IntPtr.Zero &&
            flowHandle != Native.INVALID_HANDLE)
        {
            try { Native.WinDivertClose(flowHandle); } catch { }
            flowHandle = IntPtr.Zero;
        }

        if (netHandle != IntPtr.Zero &&
            netHandle != Native.INVALID_HANDLE)
        {
            try { Native.WinDivertClose(netHandle); } catch { }
            netHandle = IntPtr.Zero;
        }
    }

    static void EnsureAdmin()
    {
        using (var id = System.Security.Principal.WindowsIdentity.GetCurrent())
        {
            var p = new System.Security.Principal.WindowsPrincipal(id);
            if (!p.IsInRole(
                System.Security.Principal.WindowsBuiltInRole.Administrator))
            {
                throw new UnauthorizedAccessException(
                    "PacketEditor must run as Administrator.");
            }
        }
    }
}

static class Program
{
    public static int Main(string[] args)
    {
        string target = null;
        string launch = null;

        for (int i = 0; i < args.Length; i++)
        {
            if (args[i].Equals("-Target", StringComparison.OrdinalIgnoreCase) &&
                i + 1 < args.Length)
            {
                target = args[++i];
            }
            else if (args[i].Equals("-Launch", StringComparison.OrdinalIgnoreCase) &&
                     i + 1 < args.Length)
            {
                launch = args[++i];
            }
            else if (args[i].Equals("-Help", StringComparison.OrdinalIgnoreCase) ||
                     args[i].Equals("/?"))
            {
                Help();
                return 0;
            }
        }

        if (string.IsNullOrWhiteSpace(target))
        {
            Help();
            return 2;
        }

        try
        {
            new Editor(target).Run(launch);
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("ERROR: " + ex.Message);
            return 1;
        }
    }

    static void Help()
    {
        Console.WriteLine("PacketEditor");
        Console.WriteLine();
        Console.WriteLine("Usage:");
        Console.WriteLine("  PacketEditor.exe -Target test.exe");
        Console.WriteLine("  PacketEditor.exe -Target test.exe -Launch C:\\Lab\\test.exe");
        Console.WriteLine();
        Console.WriteLine("Commands:");
        Console.WriteLine("  Enter                  pass packet");
        Console.WriteLine("  d                      drop packet");
        Console.WriteLine("  set <offset> <hex>     replace bytes in-place");
        Console.WriteLine("  text <offset> <text>   replace UTF-8 bytes in-place");
    }
}
