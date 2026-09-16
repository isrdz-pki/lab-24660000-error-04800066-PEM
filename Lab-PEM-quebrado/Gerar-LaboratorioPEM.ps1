<#
.SYNOPSIS
    Gera uma bancada de treino com chaves privadas PEM defeituosas, para praticar
    diagnostico e correcao de arquivos .key recusados pelo OpenSSL.

.DESCRIPTION
    Gera uma chave RSA integra em PKCS#1 tradicional cifrado - o mesmo formato do
    caso real que originou este laboratorio (Proc-Type + DEK-Info, AES-128-CFB,
    tipico de emissor Java/BouncyCastle) - e dela deriva variantes, cada uma com
    UM unico defeito isolado.

    Ao final, testa cada arquivo com DOIS comandos diferentes e grava um gabarito
    com o erro real observado em cada um. Os dois comandos sao usados de proposito:

      - openssl asn1parse : usa o leitor PEM classico. Da o erro PRECISO da camada
                            de moldura (bad end line, no start line, bad base64).
      - openssl rsa       : no OpenSSL 3.x passa pelo OSSL_STORE/DECODER, que
                            MASCARA o erro de moldura atras de mensagens genericas
                            do tipo "unsupported". Serve para mostrar por que
                            diagnosticar so com 'openssl rsa' leva a conclusao errada.

.PARAMETER Destino
    Pasta onde a bancada sera criada. Padrao: .\lab-pem

.PARAMETER Senha
    Senha da chave gerada. Padrao: LabPem2026

.PARAMETER Bits
    Tamanho da chave RSA: 2048

.PARAMETER Cifra
    Algoritmo do PEM tradicional. Padrao: aes-128-cfb (reproduz o BouncyCastle).
    Outros uteis: aes-256-cbc (padrao OpenSSL), des-ede3-cbc (legado).

.PARAMETER SemGabarito
    Nao gera o GABARITO.md. Use para treinar sem consultar a resposta.

.EXAMPLE
    .\Gerar-LaboratorioPEM.ps1
    .\Gerar-LaboratorioPEM.ps1 -Destino C:\lab -Cifra aes-256-cbc -SemGabarito
#>

[CmdletBinding()]
param(
    [string] $Destino = ".\lab-pem",
    [string] $Senha   = "LabPem2026",
    [int]    $Bits    = 2048,
    [string] $Cifra   = "aes-128-cfb",
    [switch] $SemGabarito
)

$ErrorActionPreference = 'Stop'

# ------------------------------------------------------------------ utilitarios

# Toda chamada ao openssl passa por cmd /c com redirecionamento para ARQUIVO.
# Motivo: o openssl escreve progresso e erros no stderr; no PowerShell 5.1,
# redirecionar stderr de executavel nativo (2>&1 ou 2>$null) gera NativeCommandError
# mesmo com exit code 0, e com $ErrorActionPreference='Stop' isso aborta o script.
# Deixar o cmd resolver o redirecionamento contorna o problema por completo.
function Invoke-OpenSsl {
    param([string] $Argumentos)

    $id  = [guid]::NewGuid().ToString('N')
    $out = Join-Path $env:TEMP "pemlab_o_$id.txt"
    $err = Join-Path $env:TEMP "pemlab_e_$id.txt"

    cmd /c "openssl $Argumentos > `"$out`" 2> `"$err`"" | Out-Null

    $saidaErro = if (Test-Path -LiteralPath $err) { Get-Content -LiteralPath $err -Raw } else { '' }
    [System.IO.File]::Delete($out)
    [System.IO.File]::Delete($err)

    return $saidaErro
}

# Extrai a parte util da mensagem do OpenSSL, descartando codigo hexadecimal e
# caminho do arquivo-fonte, que so poluem a leitura.
function Resumir-Erro {
    param([string] $Saida)

    if ([string]::IsNullOrWhiteSpace($Saida)) { return 'OK - carregou sem erro' }

    $linhas = $Saida -split "`r?`n"
    $comCodigo = @($linhas | Where-Object { $_ -match ':error:' } | Select-Object -First 1)

    if ($comCodigo.Count -gt 0) {
        $m = ($comCodigo[0] -split ':error:')[1]
        $m = $m -replace '^[0-9A-F]+:', ''
        $m = $m -replace '\.\./openssl[^:]*:[0-9]+:', ''
        return $m.Trim().TrimEnd(':')
    }

    $primeira = @($linhas | Where-Object { $_.Trim() -ne '' } | Select-Object -First 1)
    if ($primeira.Count -gt 0) { return $primeira[0].Trim() + ' (sem codigo de erro)' }
    return 'OK - carregou sem erro'
}

# ------------------------------------------------------------------- preparacao

if (-not (Get-Command openssl -ErrorAction SilentlyContinue)) {
    throw "openssl nao encontrado no PATH."
}

if (-not (Test-Path -LiteralPath $Destino)) {
    New-Item -ItemType Directory -Path $Destino -Force | Out-Null
}
$Destino = (Resolve-Path -LiteralPath $Destino).Path

$versao = (cmd /c "openssl version 2>&1")

Write-Host "Bancada : $Destino"
Write-Host "OpenSSL : $versao"
Write-Host "Cifra   : $Cifra"
Write-Host "Senha   : $Senha"
Write-Host ""

$bruto   = Join-Path $Destino '_material_bruto_descartavel.key'
$integra = Join-Path $Destino '00-chave-integra.key'

Invoke-OpenSsl "genrsa -out `"$bruto`" $Bits" | Out-Null

# -traditional e obrigatorio: sem ele, o OpenSSL 3.x grava PKCS#8
# (-----BEGIN ENCRYPTED PRIVATE KEY-----), que NAO tem Proc-Type/DEK-Info e
# portanto nao reproduz o formato do caso real.
Invoke-OpenSsl "rsa -in `"$bruto`" -traditional -$Cifra -passout pass:$Senha -out `"$integra`"" | Out-Null

if (-not (Test-Path -LiteralPath $integra)) {
    throw "Falha ao gerar a chave integra. A cifra '$Cifra' pode nao ser suportada."
}

# -------------------------------------------------------- decomposicao do PEM

$linhas = [System.IO.File]::ReadAllText($integra) -split "`r?`n"
$BEGIN  = @($linhas | Where-Object { $_ -like '-----BEGIN*' })[0]
$HDR    = @($linhas | Where-Object { $_ -match '^(Proc-Type|DEK-Info):' })
$B64    = @($linhas | Where-Object { $_ -match '^[A-Za-z0-9+/]+={0,2}$' })
$END    = @($linhas | Where-Object { $_ -like '-----END*' })[0]

function Salvar {
    param([string] $Nome, [string[]] $Linhas, [switch] $ComBom)

    $caminho = Join-Path $Destino $Nome
    $texto = ($Linhas -join "`n") + "`n"
    if ($ComBom) {
        [System.IO.File]::WriteAllText($caminho, $texto, (New-Object System.Text.UTF8Encoding($true)))
    } else {
        [System.IO.File]::WriteAllText($caminho, $texto)
    }
    return $caminho
}

# ---------------------------------------------------------------- as variantes

$casos = @()

$casos += @{ arquivo='01-linha-em-branco-apos-begin.key'
             camada='Moldura'
             defeito='Linha em branco entre o BEGIN e o Proc-Type (o caso real)'
             linhas=@($BEGIN) + @('') + $HDR + @('') + $B64 + @($END) }

$casos += @{ arquivo='02-rotulo-final-divergente.key'
             camada='Moldura'
             defeito='Abre com RSA PRIVATE KEY e fecha com PRIVATE KEY'
             linhas=@($BEGIN) + $HDR + @('') + $B64 + @('-----END PRIVATE KEY-----') }

$casos += @{ arquivo='03-sem-separador-cabecalho-dados.key'
             camada='Moldura'
             defeito='Falta a linha em branco entre o DEK-Info e o payload'
             linhas=@($BEGIN) + $HDR + $B64 + @($END) }

$casos += @{ arquivo='04-espaco-antes-do-begin.key'
             camada='Moldura'
             defeito='Tres espacos de indentacao antes do -----BEGIN-----'
             linhas=@('   ' + $BEGIN) + $HDR + @('') + $B64 + @($END) }

$casos += @{ arquivo='05-sem-linha-end.key'
             camada='Moldura'
             defeito='Marcador -----END----- ausente'
             linhas=@($BEGIN) + $HDR + @('') + $B64 }

$casos += @{ arquivo='06-lixo-depois-do-end.key'
             camada='Moldura'
             defeito='Linha em branco e um espaco solto DEPOIS do END'
             linhas=@($BEGIN) + $HDR + @('') + $B64 + @($END) + @('') + @(' ') }

# payload reagrupado em 40 colunas
$b64Junto = ($B64 -join '')
$b40 = @()
for ($i = 0; $i -lt $b64Junto.Length; $i += 40) {
    $b40 += $b64Junto.Substring($i, [Math]::Min(40, $b64Junto.Length - $i))
}
$casos += @{ arquivo='07-payload-reagrupado-em-40-colunas.key'
             camada='Payload'
             defeito='Payload rebobinado em linhas de 40 caracteres em vez de 64'
             linhas=@($BEGIN) + $HDR + @('') + $b40 + @($END) }

# um caractere invalido no meio do payload
$b64Sujo = @($B64)
$meio = [int]($b64Sujo.Count / 2)
$b64Sujo[$meio] = $b64Sujo[$meio].Substring(0,30) + '#' + $b64Sujo[$meio].Substring(31)
$casos += @{ arquivo='08-caractere-invalido-no-payload.key'
             camada='Payload'
             defeito='Um # substituindo um caractere base64 no meio do bloco'
             linhas=@($BEGIN) + $HDR + @('') + $b64Sujo + @($END) }

# truncamento real
$corte = [int]($B64.Count / 2)
$casos += @{ arquivo='09-payload-truncado-na-metade.key'
             camada='Material'
             defeito='Metade final do payload removida (truncamento real)'
             linhas=@($BEGIN) + $HDR + @('') + @($B64[0..($corte-1)]) + @($END) }

# DEK-Info mentindo sobre o algoritmo
$hdrErrado = @($HDR | ForEach-Object { $_ -replace 'DEK-Info: .*?,', 'DEK-Info: AES-256-CBC,' })
$casos += @{ arquivo='10-dek-info-com-algoritmo-errado.key'
             camada='Criptografia'
             defeito='DEK-Info declara AES-256-CBC, mas o payload foi cifrado com outro algoritmo'
             linhas=@($BEGIN) + $hdrErrado + @('') + $B64 + @($END) }

$casos += @{ arquivo='11-bom-utf8-no-inicio.key'
             camada='Moldura'
             defeito='Arquivo integro, porem gravado com BOM UTF-8'
             linhas=@($BEGIN) + $HDR + @('') + $B64 + @($END)
             bom=$true }

# UMA unica linha curta no meio de um payload de 64 colunas.
# Este e o caso que revela o mecanismo por tras do bad end line.
$quebrado = @()
$m2 = [int]($B64.Count / 2)
for ($i = 0; $i -lt $B64.Count; $i++) {
    if ($i -eq $m2) { $quebrado += $B64[$i].Substring(0,60); $quebrado += $B64[$i].Substring(60) }
    else            { $quebrado += $B64[$i] }
}
$casos += @{ arquivo='12-uma-linha-curta-no-meio-do-payload.key'
             camada='Payload'
             defeito='Uma unica linha de 60 caracteres no meio de um payload de 64'
             linhas=@($BEGIN) + $HDR + @('') + $quebrado + @($END) }

foreach ($c in $casos) {
    if ($c.bom) { Salvar -Nome $c.arquivo -Linhas $c.linhas -ComBom | Out-Null }
    else        { Salvar -Nome $c.arquivo -Linhas $c.linhas          | Out-Null }
}

[System.IO.File]::Delete($bruto)

# ------------------------------------------------------------- teste de cada um

Write-Host "Testando cada variante com asn1parse e com rsa..." -ForegroundColor Cyan
Write-Host ""

function Diagnosticar {
    param([string] $Caminho, [string] $Pass)
    [pscustomobject]@{
        Asn1 = Resumir-Erro (Invoke-OpenSsl "asn1parse -in `"$Caminho`"")
        Rsa  = Resumir-Erro (Invoke-OpenSsl "rsa -in `"$Caminho`" -passin pass:$Pass -noout")
    }
}

$resultados = @()

$d = Diagnosticar -Caminho $integra -Pass $Senha
$resultados += [pscustomobject]@{ Arquivo='00-chave-integra.key'; Camada='Controle'
                                  Defeito='Nenhum - referencia'; Asn1=$d.Asn1; Rsa=$d.Rsa }

foreach ($c in $casos) {
    $d = Diagnosticar -Caminho (Join-Path $Destino $c.arquivo) -Pass $Senha
    $resultados += [pscustomobject]@{ Arquivo=$c.arquivo; Camada=$c.camada
                                      Defeito=$c.defeito; Asn1=$d.Asn1; Rsa=$d.Rsa }
}

$d = Diagnosticar -Caminho $integra -Pass 'senha-errada-de-proposito'
$resultados += [pscustomobject]@{ Arquivo='00-chave-integra.key (senha errada)'; Camada='Criptografia'
                                  Defeito='Arquivo perfeito, senha incorreta'; Asn1=$d.Asn1; Rsa=$d.Rsa }

$resultados | Format-Table Arquivo, Camada, Asn1 -AutoSize -Wrap

# ------------------------------------------------------------------- gabarito

if (-not $SemGabarito) {
    $md = @()
    $md += "# Gabarito da bancada de PEM quebrado"
    $md += ""
    $md += "Gerado em $(Get-Date -Format 'yyyy-MM-dd HH:mm') com $versao."
    $md += ""
    $md += "- Cifra do PEM: ``$Cifra``"
    $md += "- Senha: ``$Senha``"
    $md += "- Chave: RSA $Bits"
    $md += ""
    $md += "## Resultado medido"
    $md += ""
    $md += "| Arquivo | Camada | Defeito injetado | ``openssl asn1parse`` | ``openssl rsa`` |"
    $md += "|---|---|---|---|---|"
    foreach ($r in $resultados) {
        $md += "| ``$($r.Arquivo)`` | $($r.Camada) | $($r.Defeito) | ``$($r.Asn1)`` | ``$($r.Rsa)`` |"
    }
    $md += ""
    $md += "## Como treinar"
    $md += ""
    $md += "1. Apague este gabarito, ou gere a bancada com ``-SemGabarito``."
    $md += "2. Para cada arquivo, rode primeiro o mapa de linhas (passo 1 da nota de troubleshooting)."
    $md += "3. Escreva a hipotese ANTES de rodar o OpenSSL: qual camada quebrou e qual e a linha culpada."
    $md += "4. So entao rode ``openssl asn1parse`` e compare com a sua previsao."
    $md += "5. Corrija com o script de reparo e valide com ``openssl rsa -check -noout``."
    $md += "6. Confira aqui se o defeito era o que voce apontou."
    $md += ""
    $md += "Acertar o erro do OpenSSL e facil. O exercicio e acertar **a linha culpada** antes de rodar o comando."

    $gab = Join-Path $Destino 'GABARITO.md'
    [System.IO.File]::WriteAllText($gab, ($md -join "`n") + "`n")
    Write-Host ""
    Write-Host "Gabarito: $gab" -ForegroundColor Green
}

Write-Host ""
Write-Host "Bancada pronta em $Destino" -ForegroundColor Green
