$lines = [System.IO.File]::ReadAllText($p) -split "`r?`n"
$b64 = @($lines | Where-Object { $_ -match '^[A-Za-z0-9+/]+={0,2}$' })
$all = $b64 -join ''
"Linhas base64 : $($b64.Count)"
"Chars base64  : $($all.Length)"
"Padding '='   : " + ($all.Length - $all.TrimEnd('=').Length)
$bytes = [Convert]::FromBase64String($all)
"Bytes cifrados: $($bytes.Length)"
"Multiplo de 16: $(($bytes.Length % 16) -eq 0)"