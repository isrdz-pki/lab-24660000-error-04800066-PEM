$src = 'C:\caminho\arquivo_original.key'
$dst = 'C:\caminho\chave_corrigida.key'

$l = [System.IO.File]::ReadAllText($src) -split "`r?`n"

$begin = @($l | Where-Object { $_ -like '-----BEGIN*' })[0]
$hdr   = @($l | Where-Object { $_ -match '^(Proc-Type|DEK-Info):' })
$b64   = @($l | Where-Object { $_ -match '^[A-Za-z0-9+/]+={0,2}$' })
$end   = @($l | Where-Object { $_ -like '-----END*' })[0]

if ($hdr.Count -gt 0) {
    $new = @($begin) + $hdr + @('') + $b64 + @($end)   # cifrado: cabeçalhos + branco
} else {
    $new = @($begin) + $b64 + @($end)                  # sem senha: nada entre BEGIN e dados
}

[System.IO.File]::WriteAllText($dst, ($new -join "`n") + "`n")
"gerado: $dst"