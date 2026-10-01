# PacketEditor

Process-aware Windows packet editor for controlled/lab traffic inspection.

The project uses WinDivert's FLOW layer to associate a process ID with a network 5-tuple, then uses the NETWORK layer for outbound TCP/UDP packet capture, editing, dropping, and reinjection.

The executable is published as a self-contained x64 Windows application and requests Administrator privileges through its application manifest.

WinDivert runtime files are separate from this project's executable:
- WinDivert.dll
- WinDivert64.sys

Usage:
PacketEditor.exe -Target test.exe
PacketEditor.exe -Target test.exe -Launch C:\Lab\test.exe

Interactive commands:
Enter                    pass unchanged
d                        drop packet
set <offset> <hex>       replace bytes in-place
text <offset> <text>     replace UTF-8 bytes in-place

Packet edits are restricted to the existing payload length so TCP sequence state is not silently changed.
