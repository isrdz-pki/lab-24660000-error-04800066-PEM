# Direto ao ponto

Sua chave `.key` não abre no OpenSSL (`bad end line`). O conteúdo dela está intacto,
só a formatação do arquivo está errada. O script abaixo reescreve a formatação.

## 1. Abra o `ReconstruirMoldura.ps1` com o bloco de notas e troque as duas primeiras linhas

```powershell
$src = 'C:\caminho\arquivo_original.key'   # sua .key com problema
$dst = 'C:\caminho\chave_corrigida.key'    # onde salvar .key corrigida
```

## 2. Rode

```powershell
powershell -ExecutionPolicy Bypass -File .\ReconstruirMoldura.ps1
```

Tem que aparecer: `gerado: C:\caminho\chave_corrigida.key`

## 3. Confira

```powershell
openssl rsa -in "C:\caminho\chave_corrigida.key" -check -noout
```

Vai pedir a senha da chave (não aparece nada na tela enquanto você digita).
Se responder **`RSA key ok`**, acabou.

---


