# Guia manual de PC Check — Roblox

Versão do programa descrita: B.O.P.E Scanner **0.11.0**.

Guia prático para uma sessão de PC Check por screenshare, com ou sem o B.O.P.E Scanner. Cada passo diz
**onde olhar**, **o que é normal**, **o que merece pergunta** e **o que não se pode concluir**. Tudo é
somente leitura: nada aqui pede para apagar, mover, renomear ou executar arquivos do jogador.

Convenções: `%LOCALAPPDATA%` = `C:\Users\<conta>\AppData\Local`; `%APPDATA%` =
`C:\Users\<conta>\AppData\Roaming`. "Admin" = precisa de terminal/Explorer executado como
administrador. Comandos são do PowerShell do próprio Windows (5.1 ou 7). Horários do Windows são
locais na tela e UTC nos relatórios do B.O.P.E.

---

## 1. Consentimento e preparação

1. Explique ao jogador o que será olhado (pastas do Roblox, pastas de usuário, histórico de programas
   do Windows) e o que **não** será: senhas, conversas, fotos, documentos pessoais, histórico de
   navegação, dados bancários.
2. Peça que feche janelas com dados pessoais e que **ele mesmo** controle o mouse e o teclado. Você
   pede; ele clica.
3. Combine as capturas de tela: só ele as tira (Win+Shift+S) e envia, ou você as tira do
   compartilhamento **com aviso em voz**. Registre na ata quais capturas foram feitas e por quê.
4. Anote: data, hora e fuso horário do PC (canto da barra de tarefas), versão do Windows
   (`winver`), nome da conta Windows usada.
5. Se for usar o B.O.P.E Scanner: confira o SHA-256 do executável antes, contra o valor que a sua
   comunidade publica. Ele mostra o que será lido antes de ler qualquer coisa.

## 2. Identificar o cliente Roblox em execução

Peça para abrir o Roblox e entrar em um jogo qualquer, depois o **Gerenciador de Tarefas** →
aba **Detalhes**:

- Procure `RobloxPlayerBeta.exe`. Clique com o botão direito → **Abrir local do arquivo**. O normal é
  `%LOCALAPPDATA%\Roblox\Versions\version-<hash>\` (ou, com Bloxstrap/Fishstrap,
  `%LOCALAPPDATA%\Bloxstrap\Versions\version-<hash>\` e equivalentes).
- Propriedades do arquivo → **Assinaturas Digitais**: deve listar **Roblox Corporation**, e "Esta
  assinatura digital está OK".
- Adicione a coluna **Linha de comando** só se necessário e **não peça para mostrar o conteúdo**: a
  linha de comando do Roblox pode conter um ticket de autenticação. O B.O.P.E não lê linhas de
  comando por esse motivo.
- Outros processos estranhos rodando de `Downloads`, `Área de Trabalho`, `Temp`: anote nome e
  caminho (botão direito → Abrir local).

**Não conclua:** um processo desconhecido não é um cheat por si; overlays (Discord, NVIDIA, Steam,
OBS) e utilitários de periféricos aparecem sempre.

## 3. Arquivos, pastas e ferramentas conhecidas

Peça para abrir, um por vez, no Explorer (com "Itens ocultos" e "Extensões de nomes de arquivos"
ligados em **Exibir**):

| Local | O que olhar |
|---|---|
| `%LOCALAPPDATA%` | Pastas `Roblox`, `Bloxstrap`, `Fishstrap`, `Voidstrap`, `Froststrap` e qualquer pasta com nome de executor |
| `%APPDATA%` | Pastas com nome de executor ou de ferramenta de FastFlags |
| `%LOCALAPPDATA%\Temp` | Executáveis e pastas recentes (ordene por **Data de modificação**) |
| `Downloads`, `Área de Trabalho`, `Documentos` | Executáveis, `.zip`, `.rar`, `.lua`, `.txt` com scripts |
| `C:\Program Files`, `C:\Program Files (x86)` | Programas instalados com nomes do catálogo |

**Estrutura típica de executor:** uma pasta com subpastas **`autoexec`** e **`workspace`** lado a
lado (às vezes também `scripts` e `bin`). Esse padrão é mais forte que qualquer nome.

## 4. Nomes e variantes (ferramentas de FastFlags e outras)

Na caixa de busca do Explorer, dentro de cada pasta acima, pesquise (o Windows ignora maiúsculas):

```
bloxstrap   fishstrap   voidstrap   froststrap   fflag   fastflag   flagmanager
fpsunlocker   rbxfpsunlocker   clientappsettings   executor   injector
```

Variantes de grafia: espaço, hífen e sublinhado (`blox strap`, `blox-strap`, `fflag_manager`).
Termos parciais como **strap** e **trap** só servem para chamar atenção: aparecem em `bootstrap`
(software comum), `strapi`, `trapcode` e muitos outros.

Alternativa em PowerShell (somente leitura, lista nomes):

```powershell
$termos = 'bloxstrap','fishstrap','voidstrap','fflag','fastflag','flagmanager','fpsunlocker','executor','injector'
$locais = "$env:LOCALAPPDATA","$env:APPDATA","$env:USERPROFILE\Downloads","$env:USERPROFILE\Desktop","$env:USERPROFILE\Documents","$env:TEMP"
Get-ChildItem $locais -Recurse -Depth 2 -ErrorAction SilentlyContinue |
  Where-Object { $n = $_.Name.ToLower() -replace '[\s_\-\.]',''; $termos | Where-Object { $n -like "*$_*" } } |
  Select-Object FullName, Length, CreationTime, LastWriteTime
```

**Legítimos e comuns:** Bloxstrap e seus forks (launchers de código aberto), o FPS unlocker,
Roblox Account Manager. Estar instalado **não** é cheat.

## 5. FastFlags e configurações do cliente

1. Abra `…\Versions\version-<hash>\ClientSettings\ClientAppSettings.json` da pasta do processo
   em execução (passo 2). É o arquivo que o player lê.
2. Abra também `%LOCALAPPDATA%\Bloxstrap\Modifications\ClientSettings\ClientAppSettings.json` (ou o
   equivalente do fork): é a cópia que o launcher escreve na pasta de versão ao abrir o Roblox.
3. Olhe os **nomes** das flags. Agrupe:
   - frame rate (`…TaskSchedulerTargetFps…`) e gráficos (`…Render…`, `…Shadow…`, `…Texture…`,
     `…D3D11…`, `…Vulkan…`): comuns, quase sempre benignos;
   - rede/física (`…Physics…`, `…Sender…`, `…Replicat…`, `…Packet…`, `…Bandwidth…`): **pergunte** —
     valores editados dessas flags já foram usados para dessincronizar o personagem.
4. Compare as datas (Propriedades → Modificado) com o horário em que o Roblox foi aberto e com os
   logs em `%LOCALAPPDATA%\Roblox\logs` (só datas; não é preciso abrir logs).

**Não conclua:** uma flag no arquivo pode não ter efeito (clientes recentes ignoram flags fora de
uma lista de permissões). Não existe uma "cópia oficial" do arquivo para comparar.

## 6. Assinaturas, hashes e caminhos

Para cada executável suspeito encontrado:

```powershell
Get-FileHash 'C:\caminho\arquivo.exe' -Algorithm SHA256
Get-AuthenticodeSignature 'C:\caminho\arquivo.exe' | Format-List Status, SignerCertificate
Get-Item 'C:\caminho\arquivo.exe' -Stream * | Select-Object Stream, Length   # Zone.Identifier = baixado da internet
```

Anote hash, status da assinatura e assinante. Sem assinatura **não** quer dizer malicioso: muitos
utilitários pequenos não são assinados.

## 7. Rastros históricos e arquivos ausentes

O Windows guarda referências a programas mesmo depois que o arquivo some. O que **dá para ver
manualmente**:

| Fonte | Como ver | O que diz | Limite |
|---|---|---|---|
| Prefetch (admin) | `C:\Windows\Prefetch` — arquivos `NOME.EXE-XXXXXXXX.pf` | O programa **rodou**; data de modificação ≈ última execução | Pode estar desligado; guarda ~1024 entradas |
| Lixeira | Abrir a Lixeira, coluna **Local original** e **Data de exclusão** | O que foi excluído e de onde | Esvaziar remove |
| Recentes | `Win+R` → `shell:recent` | Atalhos para arquivos abertos | Lista aparada pelo Windows |
| Atalhos | Área de Trabalho, `shell:start menu`, `shell:programs` — Propriedades → **Destino** | Para onde o atalho aponta e se ainda existe | Atalho pode ser antigo |
| Programas instalados | Configurações → Aplicativos | Instalações (nome, data) | Desinstalar remove |
| Eventos de limpeza (admin) | Visualizador de Eventos → Logs do Windows → Segurança, evento **1102**; Sistema, evento **104** | Um log foi apagado | Não diz o que havia nele |

Fontes que **só ferramentas leem bem** (o B.O.P.E lê): BAM/DAM, UserAssist (ROT13), ShimCache,
MuiCache, FeatureUsage, Amcache e SRUM (de uma shadow copy existente), USN Change Journal (nomes do
catálogo), Master File Table, ShellBags e OpenSavePidlMRU, assinaturas WMI permanentes, Program
Compatibility Assistant. Veja a seção 7A.

Quando uma fonte aponta para um caminho e nada existe lá hoje, registre: **fonte**, **caminho**,
**horário**, "**não está no caminho hoje**". Isso **não** prova exclusão: pode ter sido movido,
renomeado ou estar em um pendrive. Exclusão só aparece como tal na Lixeira, no USN Journal e num
registro da MFT marcado como fora de uso.

ShimCache e Amcache são **inventário**: mostram que o Windows viu o arquivo, **não** que ele rodou.

## 7A. Fontes adicionadas na versão 0.10.0

Todas são **somente leitura**. Nenhuma cria shadow copy, nenhuma executa nada, nenhuma altera
Registro, MFT, journal ou WMI. Quando uma fonte não pode ser lida, o relatório mostra **NÃO
VERIFICADO** com o motivo (`not_admin`, `source_absent`, `access_denied`, `read_failed`,
`budget_spent`, `not_consented`), nunca "nada encontrado".

### SRUM (uso de recursos por programa)

- **Onde:** `C:\Windows\System32\sru\SRUDB.dat` (banco ESE). O Windows mantém o arquivo aberto; o
  B.O.P.E tenta o arquivo uma vez e depois lê a **shadow copy mais nova que já existe** (admin).
  Manualmente não há visualizador no Windows; ferramentas forenses de terceiros leem o mesmo banco.
- **Demonstra:** que um programa com determinado caminho teve **tempo de CPU** registrado numa hora
  (`used_cpu`), e totais de bytes de rede. CPU registrada conta como execução na correlação.
- **Não demonstra:** quando o programa começou (os horários são **horas** em que o SRUM gravou),
  nem o que ele fez. A última hora antes da shadow copy pode faltar (logs de transação não aplicados).
- **Falsos positivos:** programa legítimo com o mesmo nome; arquivo renomeado. Sem shadow copy, o
  SRUM aparece como não verificado.

### MFT e USN Journal (metadados NTFS)

- **Onde:** a `$MFT` do volume do Windows, lida em modo bruto por `\\.\C:` (admin, **verificação
  avançada**). O USN Journal continua sendo lido na verificação padrão.
- **Demonstra:** nomes do catálogo em registros da MFT, com caminho reconstruído pelas pastas-pai,
  horários `$STANDARD_INFORMATION` e `$FILE_NAME`, e se o registro está **em uso** ou **liberado**
  (entrada excluída). `si_created_before_fn` indica que o horário que programas podem alterar é
  anterior ao que só o NTFS grava.
- **Não demonstra:** conteúdo do arquivo (nunca é lido nem recuperado), quem apagou, nem execução. Um
  registro liberado pode ser reutilizado a qualquer momento. Caminho com `?` = pasta-pai já
  reutilizada.
- **Falsos positivos:** download apagado sem abrir; antivírus que removeu algo; arquivos copiados ou
  extraídos com horários originais (explicam `si_created_before_fn`).
- **Correlação:** um registro **em uso** é o mesmo arquivo que a listagem de pastas vê — conta como
  uma família só. Registro liberado + USN + Lixeira podem ser o mesmo evento de exclusão.

### ShellBags e OpenSavePidlMRU

- **Onde:** `HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU`,
  `HKCU\Software\Microsoft\Windows\Shell\BagMRU` e
  `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU` (verificação
  avançada). Só caminhos com nome do catálogo ou que citam o Roblox são mantidos.
- **Demonstra:** que o Explorer **abriu a pasta** (ShellBags) ou que uma caixa Abrir/Salvar **escolheu
  o arquivo** (OpenSave), inclusive em pastas que não existem mais, em outra unidade (`drive`,
  `system_drive: false`) ou em rede.
- **Não demonstra:** execução. Os horários mostrados são os da própria pasta quando o item foi criado
  (precisão de 2 s), não o momento em que foi aberta.
- **Falsos positivos:** pasta comum com nome igual (ex.: "Wave"); olhar dentro de um arquivo
  compactado ou de uma pasta compartilhada; anexar um arquivo num navegador.

### Assinaturas WMI permanentes

- **Onde:** `ROOT\subscription` e `ROOT\default`, pela interface de consulta documentada do WMI.
  Manualmente (PowerShell como admin):
  `Get-CimInstance -Namespace root\subscription -ClassName __EventFilter`, `__EventConsumer` e
  `__FilterToConsumerBinding`.
- **Demonstra:** filtros, consumidores e vínculos; o programa que um consumidor inicia (com SHA-256 e
  assinatura quando o arquivo existe); para scripts, só tamanho, SHA-256 e nomes de arquivos citados.
- **Não demonstra:** que a assinatura disparou, nem o que o programa faz. O texto de scripts e os
  argumentos nunca são guardados.
- **Normal:** `SCM Event Log Filter/Consumer` (vem com o Windows, marcado `known_default`). Software
  de fabricantes (Dell, HP, Lenovo) e agentes de gerenciamento também usam WMI.

### Arquivos .rar e .7z

- **Demonstra:** os **nomes internos** de arquivos `.rar` (RAR 4 e 5) e `.7z` em Downloads, Área de
  Trabalho, Temp e locais do catálogo, com o caminho interno e se há estrutura `autoexec` +
  `workspace`. **Nada é extraído nem executado**; o cabeçalho 7z comprimido é o único dado
  descomprimido, com limite de 16 MiB.
- **Não demonstra:** o conteúdo. Arquivo com **cabeçalhos criptografados** aparece como tal, sem
  nomes. Nomes podem ser enganosos.

### Exportação PDF

O relatório pode ser salvo em PDF além de HTML, TXT e JSON. O PDF traz versão, data/hora UTC,
cobertura, ferramentas Roblox, fontes lidas e não lidas, evidências e estados, linha do tempo,
limitações e falsos positivos, e o **SHA-256 do JSON equivalente**. Publique o SHA-256 do próprio PDF
ao lado dele. Caracteres fora do Windows-1252 (tailandês) saem como `?`: para esses idiomas use HTML.

### Validação em Windows 10/11

O procedimento e o checklist estão em [validacao-windows.md](validacao-windows.md). Até ele ser
executado num Windows real, trate SRUM, MFT, WMI e a interface gráfica da 0.10.0 como **não validados
em hardware real** (validados só com dados sintéticos).

## 7B. Novo na versão 0.11.0

Tudo continua **somente leitura**: nada é escrito no Roblox, nenhuma flag é alterada, nenhum arquivo
suspeito é executado e nenhuma proteção do Windows é desativada. A página **Forense do Roblox** reúne:

- **Referência de FastFlags** (Roblox-FFlag-Tracker, `PCDesktopClient.json`): estado, revisão, data,
  número de entradas, versão do cliente citada no commit, última tentativa. Use **Atualizar agora** antes
  da verificação (é a única requisição de rede do programa; a verificação em si nunca acessa a rede). Sem
  referência, as comparações aparecem como "sem referência" — nunca como "igual".
- **Modo de monitoramento**: ligue antes de pedir ao jogador para entrar num jogo e deixe rodar alguns
  minutos; cada mudança aparece com o horário das amostras de cada lado. "Valor de flag restaurado" é uma
  flag que mudou e voltou ao valor anterior **entre amostras**; uma mudança feita e desfeita entre duas
  amostras não é vista. A sessão entra no próximo relatório.
- **Player do Roblox**: identidade (nome, pasta Versions, assinatura da Roblox Corporation), e — quando o
  anticheat permite leitura, o que é raro — código × arquivo, hooks com destino, memória executável sem
  módulo, strings categorizadas e valores de flags em memória. "Acesso recusado" é o anticheat funcionando,
  não um fato sobre o jogador.
- **Valores anteriores**: outras cópias das configurações com outro valor e as datas dos arquivos, e
  valores em dumps de falha do Roblox com a hora do dump.
- **Inventário de arquivos** (verificação avançada): todas as unidades acessíveis, com as classes de
  integridade das DLLs e executáveis (cada uma com motivos e limitações). Se o resumo disser que a
  varredura **parou antes de terminar**, a ausência de um arquivo na lista não significa nada.

Leia uma divergência de FastFlag junto da **correspondência de versão**: só "exata" torna a comparação
mais que indicativa, e mesmo assim a referência é o que o canal ao vivo entrega, não o que o cliente usou.

## 8. Correlação com a linha do tempo

Monte uma linha do tempo simples (horário, fonte, o que mostra). Exemplo de leitura correta:

1. 19:58 — USN: `Fluxus.exe` criado.
2. 20:01 — Amcache: entrada para `downloads\fluxus\fluxus.exe` (inventário).
3. 20:02 — UserAssist: `Downloads\Fluxus\Fluxus.exe` iniciado pelo Explorer (execução).
4. 20:10 — `ClientAppSettings.json` modificado com flag de física.
5. 22:40 — USN: `Fluxus.exe` excluído; Lixeira guarda `FluxusBootstrapper.exe`.

Escreva só os passos que os dados sustentam. Proximidade de horários **não** prova causa. Duas
interpretações do mesmo registro (ex.: dois coletores lendo a mesma pasta) contam como **uma** fonte.

## 9. Processos e módulos

Com o Roblox aberto, o Process Explorer (Sysinternals) ou o Gerenciador de Tarefas mostram processos;
os **módulos** carregados no `RobloxPlayerBeta.exe` normalmente não podem ser listados porque o
anticheat (Hyperion) bloqueia o acesso — isso é **normal** e não é suspeito. Se a lista abrir e
houver DLL vinda de `Downloads`, `Temp` ou da pasta de um executor, isso é forte e deve ser
fotografado (pelo jogador).

Um programa rodando ao mesmo tempo que o Roblox **não** é interação com o Roblox. Interação é um
módulo dentro do processo do Roblox, ou um rastro que mostre escrita/injeção.

## 10. Evidência direta, indício e hipótese

| Tipo | Exemplos |
|---|---|
| **Evidência direta** | Pasta com `autoexec`+`workspace` e scripts com `getgenv`, `hookfunction`, `loadstring(game:HttpGet(…))`; DLL de pasta de executor carregada no Roblox |
| **Indício forte** | Execução registrada (Prefetch/BAM/UserAssist) de executável com nome de executor + Amcache/atalho/USN do mesmo arquivo |
| **Indício** | Nome de executor em uma fonte só; arquivo excluído com nome de executor; flags de rede/física |
| **Hipótese** | Nome parcial (`strap`, `trap`), nome comum (`Wave`, `Delta`, `Solara`, `Synapse`), log limpo, Prefetch vazio |

## 11. Falsos positivos legítimos (exemplos)

- **Razer Synapse** (software de periféricos) × "Synapse X".
- Editores de áudio "Wave", apps "Delta", jogos/temas "Solara", "Celery" (biblioteca Python).
- `bootstrap.css`, `bootstrapper.exe` de instaladores comuns.
- Bloxstrap/Fishstrap com flags de gráficos e FPS.
- Ferramentas de desenvolvimento do Roblox Studio com pastas de scripts.
- Prefetch desligado por guias de "otimização"; logs limpos por programas de limpeza.
- Cheat Engine usado em jogos single-player.

## 12. Checklist de conclusão

- [ ] Consentimento registrado; capturas feitas pelo jogador ou com aviso.
- [ ] Cliente Roblox identificado e assinatura conferida.
- [ ] Pastas do passo 3 vistas; busca do passo 4 feita.
- [ ] FastFlags do arquivo **em uso** e do launcher conferidos.
- [ ] Hash e assinatura de cada executável suspeito anotados.
- [ ] Rastros históricos e arquivos ausentes anotados com fonte e horário.
- [ ] Linha do tempo montada só com fatos.
- [ ] Inspeção visual do guia de screenshare (2º PC, placas, cabos).
- [ ] Conclusão escrita como uma das: *sem evidências suspeitas nas fontes examinadas*,
      *inconclusivo*, *requer revisão manual*, *múltiplos indicadores corroborados*,
      *evidência de alta confiança* — nunca "limpo" ou "culpado".
- [ ] Relatório (e hashes) guardado; cópia oferecida ao jogador.

## 13. Limitações

- **Manual:** depende do que o jogador mostra e de o operador conhecer os artefatos; lento; não lê
  BAM, UserAssist, ShimCache, Amcache, SRUM, MFT, ShellBags nem USN sem ferramentas.
- **Automatizado (B.O.P.E):** só vê o que está neste Windows; não vê outro PC, DMA que imita hardware
  comum, macros na memória do mouse, firmware comprometido, Windows reinstalado. Fontes sem
  permissão aparecem como **não verificadas**, nunca como "nada encontrado". O catálogo de nomes é
  um ponto de partida: um cheat renomeado só aparece por estrutura, scripts, módulos ou correlação.
- **Ambos:** um nome não é uma identidade; horário próximo não é causa; ausência de rastro não prova
  inocência, e limpeza de rastros não prova trapaça.
