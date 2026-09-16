$p = 'C:\caminho\para\arquivo.key'
$fi = Get-Item -LiteralPath $p
"Tamanho   : $($fi.Length) bytes"
"Atributos : $($fi.Attributes)"
$raw = [System.IO.File]::ReadAllBytes($p)
"Primeiros 8 bytes: " + (($raw[0..7]  | ForEach-Object { $_.ToString('X2') }) -join ' ')
"Ultimos 8 bytes  : " + (($raw[-8..-1] | ForEach-Object { $_.ToString('X2') }) -join ' ')
$txt = [System.Text.Encoding]::ASCII.GetString($raw)
"CRLF      : " + ([regex]::Matches($txt, "`r`n").Count)
"LF sozinho: " + ([regex]::Matches($txt, "(?<!`r)`n").Count)
$lines = $txt -split "`r?`n"
"Total de linhas: $($lines.Count)"
for ($i=0; $i -lt $lines.Count; $i++) {
    if ($lines[$i] -like '*-----*') { "  L$($i+1): [$($lines[$i])]" }
}
"Comprimentos: " + (($lines | ForEach-Object { $_.Length }) -join ', ')