# Lab — Erro `04800066` / PEM


Laboratório para investigação e Troubleshooting de arquivos de chave privada em formato PEM que apresentam problemas de estrutura ou formatação.

  
O repositório reúne pequenos scripts PowerShell usados para **inspecionar a estrutura física do arquivo**, **medir e validar o payload Base64/bloco cifrado** e **reconstruir a moldura PEM** sem alterar o conteúdo criptográfico do bloco.

  
> **Objetivo:** investigar o arquivo e corrigir problemas de estrutura/formatação PEM quando aplicável.  

## Contexto

Um dos erros investigados neste laboratório é:

  
```text

error:04800066:PEM routines::bad end line

```


Esse tipo de erro está relacionado à leitura da estrutura PEM. Um arquivo PEM normalmente possui uma moldura composta por uma linha `BEGIN`, eventualmente cabeçalhos, um payload Base64 e uma linha `END`.

  
O laboratório permite separar o problema em partes:


1. verificar a estrutura física do arquivo;

2. identificar as linhas `BEGIN`/`END`;

3. analisar o conteúdo Base64;

4. medir o tamanho do payload decodificado;

5. verificar se o bloco cifrado possui tamanho compatível com blocos de 16 bytes;

6. reconstruir a moldura PEM em um novo arquivo;

7. testar o arquivo reconstruído com as ferramentas criptográficas apropriadas.

## Estrutura do repositório
```text

lab-24660000-error-04800066-PEM/

│

├── Lab-PEM-quebrado/

│   └── arquivos utilizados no laboratório

│

├── lab-pem/

│   └── arquivos utilizados para comparação/testes

│

├── MapearEstruturaArquivoKey.ps1

├── Medir-Payload-Validar-BlocoCifrado.ps1

└── ReconstruirMoldura.ps1

```


As pastas `Lab-PEM-quebrado` e `lab-pem` contêm os arquivos utilizados no experimento e comparação. Os scripts principais ficam na raiz do repositório.

---

# Ferramentas


## `MapearEstruturaArquivoKey.ps1`


Script utilizado para mapear a estrutura física de um arquivo `.key`.

O script coleta:

- tamanho do arquivo em bytes;

- atributos do arquivo;

- primeiros 8 bytes;

- últimos 8 bytes;

- quantidade de `CRLF`;

- quantidade de `LF` isolado;

- quantidade total de linhas;

- linhas que contêm marcadores PEM;

- comprimento de cada linha.

  
A finalidade é identificar diferenças entre um arquivo PEM esperado e um arquivo que apresenta comportamento anômalo.

### Configuração

Edite o caminho no início do script:

```powershell

$p = 'C:\caminho\para\arquivo.key'

```

  

Depois execute:

  

```powershell

.\MapearEstruturaArquivoKey.ps1

```

  
O script trabalha diretamente com os bytes do arquivo e também interpreta o conteúdo como ASCII para realizar a inspeção estrutural.

  

---

# `Medir-Payload-Validar-BlocoCifrado.ps1`


Script utilizado para analisar o payload Base64 presente no arquivo.
  

Ele:

1. lê o arquivo;

2. identifica as linhas que contêm somente caracteres Base64;

3. concatena essas linhas;

4. informa a quantidade de linhas Base64;

5. informa a quantidade de caracteres Base64;

6. verifica o padding `=`;

7. decodifica o Base64;

8. informa o tamanho do bloco resultante em bytes;

9. verifica se o tamanho é múltiplo de 16.

Exemplo de saída:

  

```text

Linhas base64 : ...

Chars base64 : ...

Padding '=' : ...

Bytes cifrados: ...

Multiplo de 16: True/False

```

### Confiuração


Defina o caminho do arquivo na variável utilizada pelo script:


```powershell

$p = 'C:\caminho\para\arquivo.key'

```


Execute:

  
```powershell

.\Medir-Payload-Validar-BlocoCifrado.ps1

```


O teste de múltiplo de 16 é uma verificação estrutural útil para o bloco de dados cifrados, mas **não comprova, sozinho, que a chave seja válida ou que a senha esteja correta**.

  

---

# `ReconstruirMoldura.ps1`


Script destinado à reconstrução da estrutura externa do PEM. Ele procura no arquivo original:


- linha `BEGIN`;

- cabeçalhos como `Proc-Type` e `DEK-Info`, quando existentes;

- linhas Base64;

- linha `END`.


Depois monta um novo arquivo mantendo esses componentes na ordem esperada.

### Arquivo de entrada


```powershell

$src = 'C:\caminho\arquivo_original.key'

```

### Arquivo de saída

  

```powershell

$dst = 'C:\caminho\chave_corrigida.key'

```


Execute:


```powershell

.\ReconstruirMoldura.ps1

```
  

O arquivo reconstruído é gravado separando corretamente os componentes da moldura PEM e utilizando `LF` como quebra de linha.

  

> **Atenção:** este procedimento deve ser utilizado como etapa de diagnóstico/correção estrutural. O arquivo original deve ser preservado e nunca sobrescrito.

  

---

# Fluxo de investigação


Uma sequência recomendada para o laboratório é:

```text

                    ┌─────────────────────┐

                    │ Arquivo .key original│

                    └──────────┬──────────┘

                               │

                               ▼

                 ┌─────────────────────────┐

                 │ Mapear estrutura física │

                 └────────────┬────────────┘

                              │

                              ▼

                 ┌─────────────────────────┐

                 │ Medir payload Base64    │

                 │ e bloco decodificado    │

                 └────────────┬────────────┘

                              │

                              ▼

                 ┌─────────────────────────┐

                 │ Estrutura PEM apresenta │

                 │ problema?               │

                 └────────────┬────────────┘

                              │

                    ┌─────────┴─────────┐

                    │                   │

                   SIM                 NÃO

                    │                   │

                    ▼                   ▼

          ┌──────────────────┐    Investigar outras

          │ Reconstruir      │    causas de leitura

          │ moldura PEM      │

          └────────┬─────────┘

                   │

                   ▼

          ┌──────────────────┐

          │ Testar arquivo   │

          │ reconstruído     │

          └──────────────────┘

```

  

---

  

# Execução no Windows


Abra o PowerShell na pasta do laboratório:


```powershell

cd C:\caminho\lab-24660000-error-04800066-PEM

```


Se a política de execução do PowerShell permitir a execução de scripts:


```powershell

.\MapearEstruturaArquivoKey.ps1

```


```powershell

.\Medir-Payload-Validar-BlocoCifrado.ps1

```


```powershell

.\ReconstruirMoldura.ps1

```


Caso o PowerShell bloqueie a execução dos scripts por política de execução, siga a política de segurança da máquina/ambiente antes de alterar qualquer configuração.

---

## A reconstrução não altera a criptografia
  

O `ReconstruirMoldura.ps1` trabalha sobre a representação textual do PEM:


```text

BEGIN

   │

   ├── cabeçalhos

   │

   ├── Base64

   │

   ▼

END

```


Ele não executa uma operação de descriptografia nem recriptografa a chave.

Portanto, uma reconstrução estrutural bem-sucedida não significa que a chave privada esteja matematicamente válida, que a senha seja conhecida ou que o arquivo possa ser utilizado por qualquer aplicação.

---

# Relação com o erro `04800066`

O laboratório foi organizado para investigar especificamente problemas relacionados à leitura de PEM e ao erro:


```text

04800066

PEM routines

bad end line

```

O diagnóstico deve distinguir pelo menos três possibilidades:

### 1. Problema na moldura PEM


Exemplos:

```text

-----BEGIN ...

...

-----END ...

```


com marcador incorreto, quebrado ou malformado.
  
### 2. Problema no payload
  
O conteúdo Base64 pode apresentar:

- caracteres inesperados;

- linhas inválidas;

- padding incorreto;

- tamanho incompatível após decodificação.

### 3. Problema além da estrutura PEM

Mesmo que a moldura e o Base64 estejam estruturalmente corretos, ainda pode existir outro problema no conteúdo criptográfico ou no formato esperado pela aplicação.
  
Por isso, os testes deste laboratório devem ser interpretados como **diagnóstico incremental**, e não como uma única validação definitiva.

---
