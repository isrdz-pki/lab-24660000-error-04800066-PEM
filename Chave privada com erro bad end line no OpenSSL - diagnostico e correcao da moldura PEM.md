---
title: Chave privada com erro bad end line no OpenSSL - diagnostico e correcao da moldura PEM
created: 2026-09-03
updated: 2026-09-03
area: ssl
type: troubleshooting
status: resolvido
tags: [ssl, pki, openssl, pem, chave-privada, troubleshooting, type/troubleshooting, status/resolvido, soluti]
related: ["[[SSL]]", "[[Laboratorio de PEM quebrado - bancada de treino]]", "[[6 - Obsidian-Claude-Vault/Automações/Decodificador PEM/Decodificador PEM|Decodificador PEM]]", "[[4 - PKI Engineering Lab/SSL em geral/Gerendo um SLL alpha de teste/Gerando .key + CSR|Gerando .key + CSR]]", "[[4 - PKI Engineering Lab/SSL em geral/Manual – Geração de Keystore JKS e Extração da Chave Privada/Passo a passo|Keystore JKS e extração da chave privada]]"]
source: Caso real 2026-09-03 - chave privada do certificado SSL EV mtls-auth.tokiomarine.com.br (AC SOLUTI SSL EV G4). Diagnóstico feito em sessão Claude Code.
---

# Chave privada com erro bad end line no OpenSSL - diagnóstico e correção da moldura PEM

Conexão: [[SSL]]

---

## Resumo executivo

Um arquivo `.key` recusado pelo OpenSSL com a mensagem `bad end line` **não significa,
na maioria dos casos, que a chave privada corrompeu**. Significa que o arquivo de
texto que embrulha a chave está com as linhas fora de ordem.

No caso que originou esta nota, o defeito era **uma única linha em branco no lugar
errado** — entre o `-----BEGIN RSA PRIVATE KEY-----` e o `Proc-Type: 4,ENCRYPTED`.
O material criptográfico estava 100% íntegro. A correção foi reescrever a moldura
do PEM, sem tocar em um único byte do conteúdo cifrado.

A lição que generaliza: **antes de falar em revogar e reemitir, prove em qual das
três camadas o problema está.**

| Camada quebrada | O que é | Recuperável? |
|---|---|---|
| **1. Moldura do arquivo** (linhas, marcadores, cabeçalhos) | Texto ASCII que embrulha a chave | Quase sempre sim, e sem perda |
| **2. Payload cifrado** (o base64) | O corpo da chave, cifrado | Sim, se estiver completo e a senha existir |
| **3. Material da chave** (p, q, d) | Os números que formam o par RSA | Não, se realmente perdido |

Este documento cobre o caminho completo: como distinguir as três, como corrigir a
camada 1, e onde ficam os limites reais de recuperação.

---

## Sintoma

Qualquer comando OpenSSL contra o arquivo retorna:

```text
Error reading PEM file
24660000:error:04800066:PEM routines:get_header_and_data:bad end line:../openssl-3.5.5/crypto/pem/pem_lib.c:909:
```

O nome do erro engana. Ele fala em "linha final", o que leva a pensar em arquivo
truncado ou em `-----END-----` faltando. **A origem do defeito costuma estar no
começo do arquivo, não no fim.** O erro é apenas onde o parser percebe que perdeu
o enquadramento.

---

## Fundamento: como um PEM cifrado é montado

Sem entender isso, o diagnóstico vira tentativa e erro. O formato vem do RFC 1421
(e o formato moderno de envelope, do RFC 7468).

Um PEM de chave privada **tradicional e protegida por senha** tem exatamente esta
anatomia:

```text
-----BEGIN RSA PRIVATE KEY-----      <- linha de abertura
Proc-Type: 4,ENCRYPTED               <- cabeçalho 1, COLADO na abertura
DEK-Info: AES-128-CFB,0AC3D009...    <- cabeçalho 2
                                     <- UMA linha em branco: separa cabeçalho de dados
MIIEpAIBAAKCAQEA0Xj2...              <- payload base64
...
-----END RSA PRIVATE KEY-----        <- linha de fechamento
```

As quatro regras que o parser aplica, e que a maioria das ferramentas quebra:

1. **Os cabeçalhos vêm imediatamente após o `BEGIN`.** Não pode haver linha em
   branco entre eles.
2. **A linha em branco existe uma única vez**, e o seu papel é marcar o fim do
   bloco de cabeçalhos e o início dos dados.
3. **O rótulo do `BEGIN` e do `END` têm que ser idênticos.** `BEGIN RSA PRIVATE KEY`
   fecha com `END RSA PRIVATE KEY`, nunca com `END PRIVATE KEY`.
4. **O payload é base64 puro.** Qualquer caractere fora do alfabeto base64 no meio
   dos dados invalida o bloco.
5. **Todas as linhas de dados têm exatamente 64 caracteres, menos a última.** Esta
   é a regra mais rígida e a menos conhecida das cinco. Uma única linha mais curta
   no meio do bloco já destrói o arquivo — o parser a interpreta como fim dos
   dados. Ver a seção do mecanismo mais adiante.

### O que cada cabeçalho significa

- `Proc-Type: 4,ENCRYPTED` — o `4` é a versão do PEM definida no RFC 1421; o
  `ENCRYPTED` declara que o payload está cifrado.
- `DEK-Info: <algoritmo>,<IV em hexadecimal>` — DEK é *Data Encryption Key*.
  Informa com qual algoritmo o payload foi cifrado e qual o vetor de inicialização.
  O IV **não é segredo**: ele precisa estar em claro para a decifragem funcionar.

### Detalhe de segurança que vale registrar

No PEM tradicional, a chave de criptografia é derivada da senha por
`EVP_BytesToKey` usando **MD5, salt igual aos 8 primeiros bytes do IV, e uma única
iteração**. É uma derivação fraca pelos padrões atuais.

Consequência prática: chave privada protegida por PEM tradicional resiste mal a
ataque de dicionário. Para material sensível, o correto é converter para **PKCS#8
com PBKDF2** ou empacotar em PFX moderno. Ver o passo 9.

---

## Diagnóstico passo a passo

O princípio geral: **não abra o arquivo esperando "ver" o problema.** Um PEM
quebrado parece perfeito aos olhos, porque o defeito costuma ser um caractere
invisível. Meça o arquivo em vez de olhar para ele.

---

### Passo 1 - Mapear a estrutura física do arquivo

**O que fazer:** medir tamanho, tipo de quebra de linha, presença de BOM,
caracteres estranhos e o comprimento de cada linha.

**Por que fazer:** o comprimento de cada linha é a impressão digital de um PEM.
Um arquivo válido tem um padrão rígido, e qualquer desvio aponta direto para a
linha defeituosa. Isso substitui a inspeção visual, que não enxerga linha em
branco, espaço solto nem CR sobrando.

**Como fazer** (PowerShell, sem expor o conteúdo da chave):

```powershell
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
```

**Como ler o resultado:**

| Observação | Significado | Quebra de verdade? |
|---|---|---|
| Primeiros bytes `2D 2D 2D 2D 2D` | Começa com `-----`. Envelope de texto, correto. | - |
| Primeiro byte `30` | Não é PEM, é DER binário. Usar `-inform DER`. | Sim |
| **Qualquer linha de dados diferente de 64 caracteres** | Payload reagrupado por editor, textarea ou código | **Sim, e é o defeito mais letal.** Ver a seção do mecanismo |
| Linha de dados com caractere fora do base64 | Payload adulterado | Sim - `bad base64 decode` |
| Linha em branco em posição diferente da única correta | Moldura quebrada | Sim - `bad end line` |
| Espaço ou indentação antes do `-----BEGIN-----` | Moldura quebrada | Sim - `no start line` |
| `LF sozinho` maior que zero em arquivo Windows | Quebras misturadas. Indício de arquivo montado por código. | Não, por si só |
| Primeiros bytes `EF BB BF` | BOM UTF-8 no início | **Não** no OpenSSL 3.x - testado e aceito. Era fatal no OpenSSL 1.x |
| Uma linha com 1 caractere depois do `END` | Espaço solto no fim do arquivo | **Não** - testado, o OpenSSL ignora |

As duas últimas linhas dessa tabela são armadilhas de diagnóstico: são os defeitos
mais visíveis ao abrir o arquivo, e são justamente os que **não** causam o
problema. Corrigir o BOM e ver o erro continuar custa uma rodada inteira de
investigação. Todos os "quebra de verdade" desta tabela foram medidos na bancada
descrita em [[Laboratorio de PEM quebrado - bancada de treino]].

**Padrão esperado de um PEM saudável de chave RSA 2048 cifrada:**

```text
31, 22, 54, 0, 64, 64, ... , 64, 52, 29
 |   |   |   |   \___ payload: todas de 64, exceto a última
 |   |   |   \_______ a linha em branco (posição correta)
 |   |   \___________ DEK-Info
 |   \_______________ Proc-Type
 \___________________ BEGIN RSA PRIVATE KEY
```

**O que foi encontrado no caso real:**

```text
31, 0, 22, 54, 0, 64 x24, 52, 29, 0, 1
     ^                                ^
     |                                \__ espaço solto após o END
     \___ LINHA EM BRANCO NO LUGAR ERRADO
```

Dois defeitos, sendo o primeiro o fatal.

---

### Passo 2 - Conferir os marcadores de abertura e fechamento

**O que fazer:** ler exatamente o texto das linhas que contêm `-----`.

**Por que fazer:** o `bad end line` também é disparado por rótulo divergente entre
`BEGIN` e `END`, e por espaço antes do `-----`. Descartar essa hipótese custa
segundos e evita corrigir a coisa errada.

**Como conferir pelo comprimento**, sem precisar contar caractere a caractere:

| Marcador | Comprimento exato |
|---|---|
| `-----BEGIN RSA PRIVATE KEY-----` | 31 |
| `-----END RSA PRIVATE KEY-----` | 29 |
| `-----BEGIN PRIVATE KEY-----` | 27 |
| `-----END PRIVATE KEY-----` | 25 |
| `-----BEGIN ENCRYPTED PRIVATE KEY-----` | 37 |
| `-----END ENCRYPTED PRIVATE KEY-----` | 35 |
| `-----BEGIN CERTIFICATE REQUEST-----` | 35 |

Comprimento maior que o da tabela significa espaço em branco grudado no marcador.

**No caso real:** 31 e 29, ambos perfeitos. Hipótese de rótulo divergente
descartada.

---

### Passo 3 - Identificar o tipo de chave e o algoritmo de proteção

**O que fazer:** ler as linhas de cabeçalho.

**Por que fazer:** o algoritmo determina como interpretar o tamanho do payload no
passo 4. Errar isso leva a concluir "arquivo truncado" quando o arquivo está
inteiro — foi o que quase aconteceu neste caso.

Os três formatos que você vai encontrar na prática:

| Marcador | Formato | Proteção |
|---|---|---|
| `BEGIN RSA PRIVATE KEY` sem cabeçalhos | PKCS#1 tradicional | Sem senha |
| `BEGIN RSA PRIVATE KEY` + `Proc-Type`/`DEK-Info` | PKCS#1 tradicional | Com senha, cifra legada |
| `BEGIN PRIVATE KEY` | PKCS#8 | Sem senha |
| `BEGIN ENCRYPTED PRIVATE KEY` | PKCS#8 | Com senha, PBKDF2 (moderno) |

**No caso real:**

```text
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CFB,0AC3D009BE4C10D95713BDBF3C3E3F84
```

PKCS#1 tradicional, cifrado com AES-128 em modo CFB.

---

### Passo 4 - Medir o payload e testar a integridade do bloco cifrado

**O que fazer:** juntar todas as linhas base64, decodificar e medir o resultado em
bytes.

**Por que fazer:** este é o teste que separa "moldura quebrada" de "arquivo
truncado". Se o payload decodifica limpo e o tamanho fecha, o conteúdo está
completo e o problema é só a embalagem.

```powershell
$lines = [System.IO.File]::ReadAllText($p) -split "`r?`n"
$b64 = @($lines | Where-Object { $_ -match '^[A-Za-z0-9+/]+={0,2}$' })
$all = $b64 -join ''
"Linhas base64 : $($b64.Count)"
"Chars base64  : $($all.Length)"
"Padding '='   : " + ($all.Length - $all.TrimEnd('=').Length)
$bytes = [Convert]::FromBase64String($all)
"Bytes cifrados: $($bytes.Length)"
"Multiplo de 16: $(($bytes.Length % 16) -eq 0)"
```

**Como ler o resultado — e aqui mora a armadilha:**

O teste do múltiplo de 16 **só vale para modo de bloco**. Verificar o `DEK-Info`
antes de interpretar:

| Modo | Exemplos | Alinhamento obrigatório? | Tamanho cifrado |
|---|---|---|---|
| **Bloco** | `AES-256-CBC`, `AES-128-CBC`, `DES-EDE3-CBC` | Sim, múltiplo de 16 (8 no 3DES) | Maior que o texto claro, por causa do padding |
| **Fluxo** | `AES-128-CFB`, `AES-256-CFB`, `AES-128-OFB`, `AES-128-CTR` | **Não** | Idêntico ao texto claro |

Em modo de bloco, tamanho fora do múltiplo é prova de truncamento. Em modo de
fluxo, o mesmo número é perfeitamente normal.

**Tamanhos de referência de uma chave RSA em PKCS#1 DER:**

| Tamanho da chave | DER aproximado |
|---|---|
| RSA 2048 | 1190 a 1193 bytes |
| RSA 3072 | 1770 a 1795 bytes |
| RSA 4096 | 2348 a 2375 bytes |

**No caso real:** 1588 caracteres base64, 1 de padding, resultando em **1190 bytes**.
Não é múltiplo de 16 — mas o modo é CFB, que é de fluxo, então não precisa ser. E
1190 bytes é exatamente o tamanho de uma RSA 2048 em PKCS#1. **Payload completo,
zero perda.**

---

### Passo 5 - Provar a causa raiz com teste controlado

**O que fazer:** montar três variantes do mesmo arquivo e comparar o comportamento.

**Por que fazer:** corrigir e ver funcionar prova que a correção resolve, mas não
prova qual era a causa. Reintroduzir o defeito de propósito e ver o erro voltar é
o que fecha o diagnóstico. Sem esse passo, a conclusão é palpite bem-sucedido.

| Variante | Conteúdo | Resultado esperado |
|---|---|---|
| **A** | Arquivo original | Reproduz o erro |
| **B** | Moldura corrigida | Erro muda de natureza |
| **C** | Corrigido + defeito reinserido | Erro original volta |

```powershell
& openssl asn1parse -in arquivo_original.key
& openssl asn1parse -in arquivo_corrigido.key
& openssl asn1parse -in arquivo_controle.key
```

**Resultado obtido no caso real:**

```text
A) ORIGINAL
   PEM routines:get_header_and_data:bad end line

B) CORRIGIDO
   asn1 encoding routines:ASN1_get_object:header too long

C) CORRIGIDO + linha em branco reinserida após o BEGIN
   PEM routines:get_header_and_data:bad end line
```

**Como ler:** o C reproduz o defeito sob demanda, então a causa está isolada e
provada. E o B, apesar de ser um erro, é o resultado **desejado**: significa que o
OpenSSL passou da camada PEM e só travou no ASN.1 — o que é obrigatório, porque o
conteúdo ainda está cifrado, e texto cifrado nunca é ASN.1 válido. Mudar de
`PEM routines` para `asn1 encoding routines` é a prova de que a camada de
embalagem foi resolvida.

### O mecanismo real por trás do `bad end line`

Isto foi medido, não deduzido. A regra é:

> O leitor PEM do OpenSSL trata **a primeira linha de dados com menos de 64
> caracteres como sendo a última linha do bloco**. Tudo que vier depois dela
> precisa ser o marcador `-----END-----`. Se não for, o erro é `bad end line`.

**Evidência 1 — varredura de largura.** Mesmo payload, mudando só a largura:

| Largura das linhas | Resultado |
|---|---|
| 16, 32, 40, 48, 60, 63 | `bad end line` |
| **64** | passa a camada PEM |
| 65, 72, 76, 128 | `Error reading PEM file`, sem código de erro |

**Evidência 2 — uma única linha curta.** Payload perfeito de 64 colunas com **uma**
linha partida em 60 + 4 no meio do bloco: `bad end line`. Basta uma.

**Aplicando ao caso real:** a linha em branco após o `BEGIN` fez o parser concluir
que o bloco não tinha cabeçalhos e entrar direto em modo de dados. A primeira
"linha de dados" passou a ser `Proc-Type: 4,ENCRYPTED`, com 22 caracteres — curta.
O parser a tratou como última linha do bloco, esperou o `END` em seguida,
encontrou o `DEK-Info` e falhou.

**O erro apontava a linha 31. A causa estava na linha 2. E o gatilho técnico era o
comprimento da linha 3.**

Consequência operacional: qualquer coisa que reformate quebras de linha de um
`.key` destrói o arquivo. Editor com quebra automática, campo de formulário web,
colar em chat, concatenação de string em código. Não é preciosismo de formato, é
falha dura.

---

## Correção passo a passo

### Passo 6 - Reconstruir a moldura

**O que fazer:** reescrever o arquivo com as linhas na ordem canônica, preservando
byte a byte o conteúdo base64.

**Por que fazer desta forma:** a reconstrução por filtro é imune à posição original
das linhas. Ela não "conserta" o arquivo, ela **remonta** a partir das peças
válidas. Isso resolve de uma vez linha em branco fora do lugar, espaço solto,
linha extra no fim e ordem trocada de cabeçalhos.

**Regra inegociável: nunca sobrescreva o original.** Grave em arquivo novo. Se a
reconstrução estiver errada, você ainda tem a evidência para tentar de outro jeito.

```powershell
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
```

**Por que cada filtro existe:**

| Filtro | Papel | Por que é seguro |
|---|---|---|
| `-like '-----BEGIN*'` | Captura a abertura | Só uma linha começa assim |
| `-match '^(Proc-Type\|DEK-Info):'` | Captura os cabeçalhos | Contêm `:`, nunca confundem com base64 |
| `-match '^[A-Za-z0-9+/]+={0,2}$'` | Captura só payload | Exclui marcadores (começam com `-`), cabeçalhos (têm `:` e espaço) e linhas vazias |
| `-like '-----END*'` | Captura o fechamento | Só uma linha começa assim |
| `@('')` | Reinsere a linha em branco | Na única posição correta: entre cabeçalho e dados |

O `if` que trata chave sem senha é essencial: em PEM **não cifrado**, não existe
linha em branco nenhuma. Inserir uma ali criaria exatamente o defeito que estamos
corrigindo.

---

### Passo 7 - Validar a correção

**O que fazer:** rodar o OpenSSL contra o arquivo novo.

```powershell
openssl rsa -in chave_corrigida.key -check -noout
```

**Como ler o resultado:**

| Saída | Significado | Ação |
|---|---|---|
| `RSA key ok` | Chave íntegra e consistente | Seguir para o passo 8 |
| Pede a senha (`Enter pass phrase`) | Moldura correta, chave cifrada | Digitar a senha |
| `bad decrypt` ou `unable to load key` após digitar | Senha errada, ou senha certa e material danificado | Ver passo 10 |
| `bad end line` de novo | A reconstrução não pegou algum defeito | Voltar ao passo 1 |

O `-check` faz mais do que carregar: ele valida a **consistência interna** do par
RSA, conferindo se `n = p * q`, se `d` é o inverso de `e` módulo `φ(n)` e se os
parâmetros do Teorema Chinês do Resto (`dp`, `dq`, `qInv`) batem. Uma chave que
passa no `-check` está matematicamente sã.

---

### Passo 8 - Confirmar que a chave pertence ao certificado

**O que fazer:** comparar o módulo (`n`) da chave com o módulo do certificado.

**Por que fazer:** carregar sem erro só prova que o arquivo é uma chave RSA válida.
Não prova que é **a** chave daquele certificado. Em pasta com várias emissões,
trocar arquivo é erro comum, e o sintoma só aparece quando o serviço sobe e
recusa o handshake.

O módulo é o componente público compartilhado pelos dois: está dentro da chave
privada e dentro do certificado. Se bate, é o mesmo par.

```powershell
openssl rsa  -in chave_corrigida.key -noout -modulus | openssl sha256
openssl x509 -in certificado.cer -inform DER -noout -modulus | openssl sha256
```

Para conferir também contra o CSR original:

```powershell
openssl req -in requisicao.csr -noout -modulus | openssl sha256
```

**Como ler:** os três hashes têm que ser idênticos. Qualquer divergência significa
que a chave não é daquele certificado — e nesse caso não existe correção, existe
o arquivo certo em outro lugar.

---

### Passo 9 - Empacotar e modernizar a proteção

**O que fazer:** gerar o PFX para instalação e, no mesmo movimento, sair da
criptografia legada.

**Por que fazer:** conforme registrado no fundamento, o PEM tradicional deriva a
chave com MD5 e uma iteração. Manter a chave nesse formato depois de já ter mexido
nela é desperdiçar a oportunidade de corrigir a proteção.

Converter para PKCS#8 com PBKDF2:

```powershell
openssl pkcs8 -topk8 -in chave_corrigida.key -out chave_pkcs8.key -v2 aes-256-cbc -v2prf hmacWithSHA256
```

Gerar o PFX com a cadeia completa:

```powershell
openssl pkcs12 -export -inkey chave_corrigida.key -in certificado.cer -certfile intermediaria.cer -out certificado.pfx -name "nome-amigavel"
```

Validar o PFX antes de entregar:

```powershell
openssl pkcs12 -in certificado.pfx -info -noout
```

Se o PFX for antigo e o OpenSSL 3.x recusar por algoritmo legado (RC2-40, 3DES-SHA1),
adicionar `-legacy`. Isso **não é corrupção**, é o provider legado desabilitado por
padrão no OpenSSL 3.

---

## Tabela de erros do OpenSSL e o que cada um realmente diz

### Antes da tabela: use o comando certo, ou o diagnóstico não existe

No OpenSSL 3.x, `openssl rsa` passa pelo `OSSL_STORE`/`DECODER`, que **mascara o
erro de moldura** atrás de mensagens genéricas. Medido em bancada: sete defeitos
completamente diferentes retornam a mesma mensagem.

| Defeito real | `openssl rsa` diz | `openssl asn1parse` diz |
|---|---|---|
| Linha em branco após o BEGIN | `DECODER ... unsupported` | `bad end line` |
| Rótulo final divergente | `DECODER ... unsupported` | `bad end line` |
| Espaço antes do BEGIN | `DECODER ... unsupported` | `no start line` |
| Caractere inválido no payload | `DECODER ... unsupported` | `bad base64 decode` |
| Payload truncado | `STORE ... unsupported` | (não detecta) |
| Senha errada, arquivo perfeito | `STORE ... unsupported` | (não detecta) |

**Regra: para investigar, `openssl asn1parse`. O `openssl rsa` serve para validar
depois da correção, não para diagnosticar.** Diagnosticar pelo `openssl rsa` leva
a revogar certificado que estava recuperável, ou a caçar senha de arquivo que
estava destruído.

### A tabela

Erros medidos com OpenSSL 3.5.5. A coluna do comando importa.

| Mensagem | Comando | Camada | Causa | Recuperável? |
|---|---|---|---|---|
| `get_header_and_data:bad end line` | `asn1parse` | Moldura | Linha de dados com menos de 64 caracteres em qualquer posição; linha em branco fora do lugar; rótulo divergente; `END` ausente | Sim, passo 6 |
| `Error reading PEM file` sem código | `asn1parse` | Moldura | Cabeçalhos colados no payload (sem o separador), ou linhas com mais de 64 caracteres | Sim, passo 6 |
| `get_name:no start line` | `asn1parse` | Moldura | Algo antes do `-----BEGIN-----`, ou arquivo é DER | Sim |
| `PEM_read_bio_ex:bad base64 decode` | `asn1parse` | Payload | Caractere fora do alfabeto base64 no bloco | Depende da extensão |
| `ASN1_get_object:header too long` | `asn1parse` | ASN.1 | **Não é erro nesse contexto.** Significa que o PEM foi lido e o conteúdo está cifrado. É o resultado desejado após corrigir a moldura | - |
| `ossl_cipher_generic_block_final:wrong final block length` | `rsa` | Criptografia | `DEK-Info` declara modo de bloco, mas o payload não tem tamanho alinhado. Algoritmo declarado errado | Sim, corrigindo o `DEK-Info` |
| `EVP_DecryptFinal_ex:bad decrypt` | `rsa` | Criptografia | Senha errada em modo de bloco | Sim, com a senha correta |
| `ossl_store_handle_load_result:unsupported` | `rsa` | Genérico | Ambíguo: cobre moldura quebrada, truncamento e senha errada. **Não conclua nada a partir dele** | Rodar `asn1parse` |
| `OSSL_DECODER_from_bio:unsupported` | `rsa` | Genérico | Idem acima | Rodar `asn1parse` |
| `pkcs12:mac verify error` | `pkcs12` | PFX | Senha errada ou arquivo truncado | Ver `-info` |
| `digital envelope routines::unsupported` | qualquer | Provider | Algoritmo legado desabilitado no OpenSSL 3 | Sim, usar `-legacy` |

Um ponto que a tabela não mostra e precisa ficar explícito: **truncamento é
invisível para os dois parsers**. Um arquivo com metade do payload removido produz
exatamente a mesma saída de um arquivo íntegro, porque para o parser é só um bloco
base64 válido de tamanho diferente. Truncamento só aparece **medindo** o payload,
no passo 4.

---

## Passo 10 - Os limites reais de recuperação

Depois de descartar a camada de moldura, restam os casos de dano real. Aqui está
o que ainda tem saída e o que não tem.

### A ordem dos campos dentro de uma chave RSA

Uma `RSAPrivateKey` em PKCS#1 tem os campos gravados nesta sequência fixa:

```text
version, n, e, d, p, q, dp, dq, qInv
```

Onde:

- `n` = módulo (público)
- `e` = expoente público
- `d` = expoente privado
- `p`, `q` = os dois primos
- `dp`, `dq`, `qInv` = parâmetros do Teorema Chinês do Resto, usados só para
  acelerar operações

Essa ordem é o que determina o que sobrevive a um truncamento:

| Até onde o arquivo chegou íntegro | Recuperável? | Como |
|---|---|---|
| Passou de `q` | **Sim, integralmente** | `dp`, `dq` e `qInv` são todos deriváveis de `p`, `q`, `d` e `e` |
| Passou de `d`, perdeu `p` e `q` | **Sim** | Conhecendo `n`, `e` e `d` é possível fatorar `n` em tempo polinomial probabilístico, recuperando `p` e `q` |
| Parou antes de `d` | **Não** | Sem `d` e sem os primos, só resta o material público |

Confirmar onde o corte aconteceu:

```powershell
openssl asn1parse -in chave.key
```

O `asn1parse` mostra o offset de cada campo e onde a estrutura quebra. Se o
comprimento declarado no SEQUENCE externo for maior que o arquivo, está truncado —
e o offset do último campo lido diz qual linha da tabela acima se aplica.

### Onde não existe recuperação

- **Chave gerada em token ou smartcard A3.** Gerada com `CKA_SENSITIVE=TRUE` e
  `CKA_EXTRACTABLE=FALSE` por exigência normativa. Não existe cópia, nem no token,
  nem na AC. Só revogação e reemissão.
- **Container do Windows destruído.** Se `certutil -user -key` não lista o
  container, o arquivo protegido por DPAPI não tem reconstrução parcial suportada.
- **Senha perdida.** A chave está lá, íntegra, e permanece inacessível. Não existe
  recuperação de senha de chave privada.
- **Em ICP-Brasil, a AC não guarda cópia da chave privada.** Não há serviço de
  recuperação a acionar. Perdeu, reemite.

---

## Como identificar a origem do defeito

Isso importa porque muda o encaminhamento: se o defeito nasce no processo, ele vai
voltar no próximo cliente.

### Indício 1 - O algoritmo no DEK-Info

| Valor | Origem provável |
|---|---|
| `AES-256-CBC` ou `DES-EDE3-CBC` | OpenSSL padrão (`genrsa -aes256`, `req -des3`) |
| `AES-128-CFB`, `AES-128-OFB` | Gerador Java/BouncyCastle, biblioteca de terceiro ou ferramenta web |

O OpenSSL não usa modo CFB para proteger chave privada por padrão. Encontrar CFB
significa que **o arquivo não saiu do OpenSSL**.

### Indício 2 - A posição da linha em branco

Linha em branco logo após o `BEGIN` é assinatura de PEM montado por concatenação
de string em código — alguém escreveu algo como `"-----BEGIN...-----\n\n" + headers`
— ou de conteúdo que passou por campo de formulário web e voltou reformatado.

### Conclusão no caso real

Os dois indícios apontam para a mesma coisa: **a geração da chave funcionou, e o
que falhou foi a serialização/entrega do arquivo.** O par RSA nunca esteve
corrompido.

Isso muda completamente o atendimento: não é caso de revogar nem de reemitir, é
caso de corrigir a formatação e, no médio prazo, ajustar a ferramenta que gerou o
arquivo mal formado.

---

## Prevenção

### Validação obrigatória logo após gerar ou receber

Trinta segundos que evitam descobrir o problema na hora de subir o serviço:

```powershell
openssl rsa -in chave.key -check -noout
openssl rsa -in chave.key -noout -modulus | openssl sha256
```

Guardar o hash do módulo junto do CSR. Ele identifica o par em qualquer
investigação futura e resolve sozinho a pergunta "essa chave é desse certificado?".

### Regras de manuseio

1. **Nunca transportar `.key` por campo de texto, chat ou formulário web.** Sempre
   como arquivo anexado, ou dentro de um PFX.
2. **Nunca abrir `.key` em editor que reformate.** Word, Bloco de Notas com quebra
   automática e editores online são os principais causadores.
3. **Chave privada operacional fora de pasta sincronizada em nuvem.** Sincronização
   sob demanda pode entregar arquivo não hidratado, e o sintoma imita truncamento.
4. **Backup só depois de validar.** Copiar arquivo quebrado gera dois arquivos
   quebrados com o mesmo horário — foi o que aconteceu neste caso, e o "backup" era
   inútil.
5. **Preferir PKCS#8 com PBKDF2** ao PEM tradicional, pelo motivo do fundamento.
6. **Registrar tamanho e hash do arquivo** no momento da entrega ao cliente, para
   comparar depois.

### Melhoria de processo sugerida

Incluir a validação do par (`-check` + confronto de módulo) como etapa formal do
roteiro de emissão SSL, antes da entrega ao cliente. Hoje o defeito só é descoberto
quando o cliente tenta instalar, o que transforma um problema de trinta segundos em
um chamado.

---

## Evidências do caso real

| Item | Valor |
|---|---|
| Data | 2026-09-03 |
| Certificado | `CN=mtls-auth.tokiomarine.com.br`, SSL EV ICP-Brasil |
| Titular | TOKIO MARINE SEGURADORA S.A. |
| Emissor | AC SOLUTI SSL EV G4 |
| Serial | `11DE2609024E058E48C5` |
| Validade | 02/09/2026 a 02/09/2027 |
| Arquivo | `11DE2609024E058E48C533164021000100.key` (serial + CNPJ) |
| Tamanho | 1789 bytes, 33 linhas, CRLF consistente |
| Proteção | `AES-128-CFB`, PKCS#1 tradicional |
| Payload | 1588 chars base64 → 1190 bytes cifrados |
| Defeito | Linha em branco entre `BEGIN` e `Proc-Type` (L2) e espaço solto após o `END` (L33) |
| Diagnóstico | Moldura PEM inválida; material criptográfico íntegro |
| Status | Moldura corrigida e validada. Confirmação final do par depende da senha da chave |

### Pendência

A prova definitiva de que a chave decifra corretamente exige a senha. Com ela em
mãos, executar os passos 7 e 8. Se a senha não for localizada, o encaminhamento
passa a ser reemissão — que neste caso é simples, por se tratar de emissão recente.

---

## Notas relacionadas

- [[Laboratorio de PEM quebrado - bancada de treino]] - bancada para reproduzir e treinar todos os defeitos desta nota
- [[SSL]] - conexão da área
- [[6 - Obsidian-Claude-Vault/Automações/Decodificador PEM/Decodificador PEM|Decodificador PEM]] - ferramenta própria para inspecionar CSR, certificados e chaves
- [[4 - PKI Engineering Lab/SSL em geral/Gerendo um SLL alpha de teste/Gerando .key + CSR|Gerando .key + CSR]] - geração correta pelo OpenSSL
- [[4 - PKI Engineering Lab/SSL em geral/Manual – Geração de Keystore JKS e Extração da Chave Privada/Passo a passo|Keystore JKS e extração da chave privada]] - contexto Java, onde o modo CFB costuma aparecer
