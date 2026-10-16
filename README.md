# B.O.P.E Scanner

**Verificação offline de PC para screenshares de Roblox (e FiveM).** Lê os rastros que o Windows guarda
sobre programas, arquivos, dispositivos e configurações, correlaciona fontes independentes, explica cada
achado com as explicações legítimas que também o produzem e mostra tudo na tela enquanto o jogador
compartilha. **Nunca diz que um PC está limpo** — e nunca declara culpa sozinho.

**Versão atual: 0.11.0** — baseada no [aeterna-rongroi](https://github.com/aeterna/aeterna-rongroi) 0.9.0
(GPL-3.0-or-later). Esta é uma **versão modificada**: toda build mostra `UNOFFICIAL BUILD` em relação ao
aeterna-rongroi, como a seção 7(c) do [NOTICE](NOTICE) exige. Confira o arquivo baixado pelo SHA-256 que
sua comunidade publica (`bope-scanner-0.11.0-windows-x64.exe`, `bope-scanner-cli-0.11.0-windows-x64.exe`).

## Por que esta base

Auditei os três candidatos lendo o código real, não só os README ([auditoria completa](docs/bope/auditoria.md)):

| Repositório | Linguagem / licença | O que o código realmente tem | Decisão |
|---|---|---|---|
| Screenshare Tool | C/C++, MIT | Nenhuma linha específica de Roblox (só o README cita Roblox); usa hooks globais `WH_KEYBOARD_LL`/`WH_MOUSE_LL` (proibidos pela especificação); depende de um scanner de memória externo que não está no repositório; último commit em jan/2024; sem testes | Não usado |
| DexCheck | PowerShell, MIT | 40 sondas bem testadas para CoD/Warzone, estados OK/INFO/WARN/FLAG/NA | Referência para os estados e o veredito conservador |
| **Aeterna Rongroi** | **Rust + Tauri, GPL-3.0** | Arquitetura coletor → regras → relatório → visão, 955 testes, regras YAML com fixtures, consentimento e modo SS, offline por construção | **Base escolhida** |

## O que foi construído sobre a base

- **20 coletores novos**, todos somente leitura e testados com hosts sintéticos: UserAssist (ROT13 +
  contadores), MuiCache, AppCompatCache/ShimCache (decodificador Win8/10/11), FeatureUsage, listas do
  Explorer (RunMRU, TypedPaths, RecentDocs, LastVisitedPidlMRU), desvios de execução (IFEO Debugger,
  SilentProcessExit, AppInit_DLLs, AppCertDlls, Winlogon), instalação do Roblox (assinatura do player,
  DLLs com nome de DLL do sistema ao lado dele, ClientAppSettings, logs, bootstrappers), **player do
  Roblox em execução** (módulos fora do Windows, memória executável privada/mapeada por tipo, programas
  rodando de pastas do usuário, processo pai), **pegada de executor** (estrutura `autoexec`+`workspace`),
  **scripts Lua com APIs exclusivas de executor** (getgenv, hookfunction, `loadstring(game:HttpGet(...))`…
  sem guardar o texto), arquivos baixados com **Mark of the Web**, USB/HID com **placas Arduino/RP2040
  atuando como teclado** e o `setupapi.dev.log`, extensões de navegador e suas permissões, programas
  instalados por categoria (Cheat Engine, macros, VPN, limpadores…), adaptadores VPN/TAP e proxies,
  identidade de firmware e indícios de máquina virtual.
- **72 regras novas** (143 no total), cada uma com nível (`info`/`warn`/`flag`), explicações legítimas,
  profundidade da fonte, fixtures positivas e negativas e um host de referência de um PC comum de
  jogador de Roblox em que todas ficam quietas.
- **Camada de avaliação separada das evidências**: OK / INFO / WARN / FLAG / NÃO VERIFICADO por
  categoria e uma conclusão geral que conta **fontes independentes** (duas regras sobre a mesma fonte
  contam uma vez) e lista proximidade temporal entre fontes — sem nunca declarar "limpo".
- **Interface nova em português**: tela inicial com o que será examinado, direitos,
  padrão/avançada e consentimento **antes** de ler qualquer coisa; progresso real com cancelamento;
  painel de categorias, pesquisa, filtros e ordenação; relatório salvo em **HTML, JSON, TXT e PDF com
  SHA-256** na pasta escolhida.
- **CLI em português** (`--lang pt-br` é o padrão) com a mesma avaliação e `--export-dir`.
- **Detecção específica de Roblox (ADRs 0118–0123):** catálogo de ferramentas (Bloxstrap e forks,
  FFlagManager e variantes, FPS unlocker, executores, injetores; `strap`/`trap` só como parcial fraco),
  busca desses nomes em arquivos, pastas, `.zip` e na Lixeira; atalhos `.lnk` com verificação do
  destino; **Amcache** lido de shadow copies já existentes; nomes do catálogo no **USN Journal**;
  módulo de **FastFlags** (arquivo em uso × cópia do launcher, flags de rede/física); e a correlação
  **`roblox_trace`**, que cruza todas as fontes e dá a cada ferramenta um status INFO / SUSPEITO /
  DETECTADO / CORROBORADO com as famílias de fontes independentes, dizendo também quais fontes não
  puderam ser lidas.
- **Novo na 0.10.0 (ADRs 0124–0129):** **SRUM** (uso de CPU e rede por programa, lido de shadow copy
  existente com um leitor ESE próprio e limitado), **Master File Table** (metadados de registros em uso
  e liberados com nomes do catálogo, leitura bruta somente leitura, verificação avançada),
  **ShellBags e OpenSavePidlMRU** (verificação avançada), **assinaturas WMI permanentes**, nomes
  dentro de **`.rar` e `.7z`** (só o índice, com limites contra decompression bomb), exportação
  **PDF** nativa e as descrições das 71 regras herdadas em português. 152 regras no total. Validação em
  Windows real ainda pendente: [docs/bope/validacao-windows.md](docs/bope/validacao-windows.md).
- **Novo na 0.11.0 (ADRs 0133–0138):**
  - **Inventário de arquivos de todas as unidades** (verificação avançada): percorre as unidades fixas e
    removíveis acessíveis sem seguir junções/links, com orçamento, cancelamento e progresso real;
    conta arquivos listados, pastas inacessíveis, links ignorados, imagens avaliadas / só contadas / não
    avaliadas, e nunca apresenta uma varredura parcial como completa.
  - **Verificação de DLLs e executáveis** em oito classes (referência verificada, assinatura válida,
    desconhecido, suspeito, integridade comprometida, malicioso com evidência corroborada, não
    verificado, inconclusivo), cada uma com motivos e limitações: SHA-256, Authenticode com data da
    assinatura, **catálogo do Windows**, cabeçalhos PE, arquitetura, seções e permissões, importações e
    exportações, TLS callbacks, recurso de versão, checksum, overlay. Nenhum arquivo é executado.
  - **Módulos e memória de processos** e **análise do player do Roblox**: identidade além do nome
    (caminho, assinatura, signatário), código em memória × arquivo (realocado como o loader faz, tabelas
    preenchidas pelo loader ignoradas), **hooks inline** com destino e dono do destino, imagens mapeadas à
    mão, mapeamentos que o loader não lista, **strings categorizadas** (ASCII, UTF-8, UTF-16LE) e
    identificadores de FastFlags de rede/física sem offsets fixos. Só leitura: nada é escrito no Roblox.
  - **Referência de FastFlags** do [Roblox-FFlag-Tracker](https://github.com/MaximumADHD/Roblox-FFlag-Tracker)
    (`PCDesktopClient.json`): sincronização condicional com validação, substituição atômica, cópia
    offline e atualização manual; comparação de valores observados (arquivos, memória, dumps de falha)
    com revisão e correspondência de versão do cliente.
  - **Valores anteriores**: cópias das configurações com valores diferentes e as datas dos arquivos,
    dumps de falha do Roblox, e o **modo de monitoramento** explícito e visível (detecta flag alterada e
    depois restaurada entre amostras).
  - **Modo SS removido** por completo (interface, rotas, estados, opções da CLI e filtros).
- Guia manual: [docs/bope/guia-pc-check-roblox.md](docs/bope/guia-pc-check-roblox.md).

## Capacidades e limites

Leia [docs/bope/capacidades.md](docs/bope/capacidades.md): para cada área da especificação, o que é
**detectado**, o que é só **investigável** e o que **não pode ser verificado** por software dentro do
Windows (outro PC, DMA que imita hardware comum, firmware comprometido, Windows reinstalado, macros
guardadas na memória do mouse…). Para essas, o [guia de PC check](docs/bope/guia-pc-check-roblox.md) traz
uma checklist de inspeção manual.

## Privacidade

- O código do programa **não envia nada** sobre o PC, a verificação ou você. A única requisição de rede
  é baixar o arquivo público de referência de FastFlags do GitHub — pelo botão "Atualizar agora", pelo
  comando `fflags sync` ou pela verificação automática que pode ser desligada na página do Roblox
  (ADR 0136). Uma verificação nunca acessa a rede.
- **Somente leitura**: nenhum arquivo, chave, serviço, driver ou configuração examinado é alterado.
- Nunca lê senhas, cookies, tokens, mensagens, conteúdo de documentos ou dados de pagamento; de linhas
  de comando guarda só o programa, nunca argumentos; de scripts guarda só quais funções aparecem.
- Fontes mais pessoais (extensões, arquivos do usuário, MRUs, ShellBags, Master File Table, comandos do
  PowerShell) só na
  **verificação avançada**, escolhida antes de começar.
- Da memória do Roblox só guarda strings de categorias fixas (nunca chat ou texto qualquer).
- O modo de monitoramento só roda enquanto você o deixa ligado, mostra cada mudança e não persiste
  nada além do relatório (ou do arquivo que você indicar na CLI).

Detalhes: [PRIVACY.md](PRIVACY.md).

## Compilar

Requisitos: Windows 10/11 x64, Rust 1.98 (`rust-toolchain.toml`), Node 22 + pnpm, WebView2.

A 0.11.0 ainda não tem binários publicados: o código foi verificado por compilação cruzada para
`x86_64-pc-windows-msvc` e por testes com hosts sintéticos, não em um Windows real
([docs/bope/validacao-windows.md](docs/bope/validacao-windows.md)). Os binários da 0.10.0 eram compilados em
Linux com MinGW-w64 (alvo `x86_64-pc-windows-gnu`; o `WebView2Loader.dll` precisa ficar ao lado do
`bope-scanner.exe`). Para compilar no Windows (alvo MSVC, recomendado):

```bat
pnpm -C apps/desktop install --frozen-lockfile
pnpm -C apps/desktop tauri build --no-bundle -- --locked   :: GUI: target\release\bope-scanner.exe
cargo build --release --locked -p bope-cli                 :: CLI: target\release\bope-scanner-cli.exe
```

Compilar para Windows a partir do Linux (como foi feito para a entrega; MinGW-w64 e o código-fonte da
biblioteca padrão do Rust instalados):

```bash
pnpm -C apps/desktop build
RUSTC_BOOTSTRAP=1 CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc \
  cargo build --release -Z build-std=std,panic_unwind --target x86_64-pc-windows-gnu \
  -p bope-cli -p bope-desktop --features tauri/custom-protocol
```

Uso da CLI:

```bat
bope-scanner-cli scan --mode ss --elevate --export-dir "%USERPROFILE%\Documents\B.O.P.E Scanner"
bope-scanner-cli scan --full --lang en --json > relatorio.json
```

Verificações do projeto (rodam em Linux e Windows):

```bash
cargo test                         # 1 081 testes Rust (sem o crate do desktop)
cargo clippy --all-targets -- -D warnings
cargo xtask check-rules            # regras, fixtures e traduções
cargo xtask check-baseline         # todas as regras quietas nos PCs de referência
cargo xtask check-locales && cargo xtask check-unicode && cargo xtask check-versions
pnpm -C apps/desktop typecheck && pnpm -C apps/desktop lint && pnpm -C apps/desktop test
```

## Licença e créditos

GPL-3.0-or-later, com os termos adicionais da seção 7 do [NOTICE](NOTICE), que este projeto preserva.
Regras e fixtures em `rules/` estão sob CC-BY-SA-4.0. Copyright do código original: aeterna-rongroi
contributors; as modificações: B.O.P.E Scanner contributors. O nome "rongroi" não é usado para
identificar esta versão modificada.

O README original do aeterna-rongroi está em [docs/upstream/](docs/upstream/README.aeterna-rongroi.md).
