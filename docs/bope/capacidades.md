# Capacidades e limites

Para cada área pedida na especificação: o que o B.O.P.E Scanner **detecta** (há regra que gera
WARN/FLAG), o que **investiga** (mostra como contexto/INFO para a pessoa avaliar) e o que **não pode
verificar**. "Avançada" = só na verificação avançada, escolhida antes de começar.

## Execução de programas

| Fonte | Estado | Observações |
|---|---|---|
| Prefetch | Detecta | Admin. Desligado em alguns SSDs/edições; vazio é sinal de limpeza, não de cheat. |
| BAM/DAM | Detecta (por nome via linha do tempo) | Só ~1 semana; zera ao desligar o serviço. |
| UserAssist | Detecta (por nome) | Por conta; desligável em Configurações. |
| MuiCache | Investiga | Sem data. |
| FeatureUsage | Investiga | Contadores, sem data por programa. |
| ShimCache | Detecta (por nome) | No Windows 10+ presença ≠ execução; gravado no desligamento. |
| PCA (Program Compatibility Assistant) | Detecta (por nome) | Windows 11 22H2+. |
| PowerShell (histórico PSReadLine, eventos 4103/4104) | Detecta palavras, nunca guarda comandos | Avançada para o histórico. |
| Processos em execução e processo pai | Detecta | |
| RunMRU, TypedPaths, RecentDocs, LastVisitedPidlMRU | Investiga | Avançada. Só programas/extensões selecionadas. |
| Amcache.hve | Detecta (nomes do catálogo, pastas do usuário) | Admin. Lido de uma **shadow copy já existente** (nenhuma é criada); sem shadow copy fica NÃO VERIFICADO. Inventário ≠ execução. Logs de transação não aplicados. |
| SRUM | Detecta (uso de CPU de programas com nome do catálogo) | Admin. Lido de uma **shadow copy já existente** com leitor ESE próprio; logs de transação não aplicados; horários por hora. CPU registrada conta como execução na correlação. |
| USN Journal | Detecta nomes do catálogo (criação, exclusão, renomeação) e contagens por pasta | Admin. Só a unidade do sistema; o journal cita o nome, não a pasta. |
| $MFT (metadados, inclusive registros liberados) | Detecta (Avançada) | Admin, leitura bruta somente leitura de `\\.\C:`. Nomes do catálogo, caminho, horários SI/FN, em uso ou liberado. **Conteúdo nunca é recuperado.** Só a unidade do sistema. |
| Atalhos (.lnk) | Detecta (destino com nome do catálogo; destino ausente hoje) | Área de Trabalho, Menu Iniciar, barra de tarefas, Recentes. |
| Lixeira (`$I`) | Detecta (nomes do catálogo, local original, data de exclusão) | Só a conta que roda a verificação; esvaziar remove. |
| ShellBags, OpenSavePidlMRU | Investiga (Avançada) | Só caminhos com nome do catálogo ou do Roblox; abrir pasta ≠ execução; horários do item, não da abertura. |
| **Histórico de downloads do navegador** | **Não lido** (privacidade) | Substituído pelo Mark of the Web dos arquivos baixados (verificação avançada). |
| **Criação de shadow copy / VSS ativo** | **Não implementado, por decisão** | Criar snapshot altera o sistema; só snapshots existentes são lidos. |
| **Linhas de comando completas** | **Não coletado** (por privacidade) | Só o programa. |

## Roblox

| Área | Estado |
|---|---|
| Instalação, assinatura do player, DLLs com nome de DLL do sistema ao lado (proxy DLL) | Detecta |
| ClientAppSettings (FFlags) — só nomes e contagem | Investiga (bootstrappers legítimos editam) |
| Bootstrappers de terceiros | Investiga (INFO) |
| Player em execução: módulos fora do Windows/Roblox, memória executável privada/mapeada, pai | Detecta, se o Hyperion permitir abrir o processo |
| Estrutura de executor (`autoexec` + `workspace`), também dentro de `.zip`, `.rar` e `.7z` (só o índice) | Detecta (FLAG / WARN) |
| Catálogo de ferramentas (Bloxstrap, forks, FFlagManager e variantes, FPS unlocker, executores, injetores) em arquivos, pastas, .zip/.rar/.7z, Lixeira, atalhos, Amcache, SRUM, MFT, ShellBags, WMI, USN, Prefetch, BAM, UserAssist, ShimCache, MuiCache, FeatureUsage, PCA, programas instalados e processos | Correlaciona (`roblox_trace`): INFO / SUSPEITO / DETECTADO / CORROBORADO por ferramenta, com famílias de fontes independentes |
| FastFlags (`ClientAppSettings.json` em uso, cópias de launchers, backups de ferramentas) | Detecta flags de rede/física no arquivo em uso (WARN); conta o resto (INFO) |
| Scripts com APIs exclusivas de executor | Detecta (FLAG), sem guardar o texto |
| Conteúdo da memória do Roblox, hooks internos, scripts injetados | **Não verifica** — ler memória do jogo conflitaria com o Hyperion e com o modo somente leitura |
| Executores 100% em memória que não deixam pasta | **Não verifica** além de módulos/memória executável |

## Persistência e integridade

| Área | Estado |
|---|---|
| Run/RunOnce, Startup, tarefas agendadas, serviços | Detecta |
| IFEO, SilentProcessExit, AppInit/AppCert DLLs, Winlogon | Detecta |
| Drivers carregados, assinaturas, Code Integrity, lista de drivers vulneráveis | Detecta |
| Modo de teste, HVCI, Secure Boot, TPM, tipo de firmware | Detecta/Investiga |
| Assinaturas WMI permanentes | Detecta (consumidores de linha de comando/script; nomes do catálogo) — via `ExecQuery`, somente leitura; nunca guarda texto de scripts (ADR 0127) |
| **Extensões de shell** | Parcial (via autostart/serviços) |

## Dispositivos

| Área | Estado |
|---|---|
| USB/HID atuais e passados, USBSTOR, setupapi.dev.log | Detecta |
| Placas Arduino/Teensy/RP2040 agindo como teclado/mouse | Detecta (WARN) |
| Placas PCI e dispositivos que saíram antes da verificação | Investiga |
| **DMA (FPGA que imita placa comum), KMBox, fusers** | **Não verifica** — inspeção visual |
| **Macros na memória do mouse/teclado** | **Não verifica** — abrir o software da marca |
| **Estatísticas de entrada / captura de teclas** | **Não implementado, por decisão** — seria um keylogger |

## Navegador, rede, ambiente

| Área | Estado |
|---|---|
| Extensões (permissões, acesso ao Roblox, userscripts) | Detecta (Avançada) |
| Arquivos baixados com Mark of the Web | Detecta (Avançada); host de download só com opção marcada |
| Hosts file, DNS, proxy, adaptadores VPN/TAP | Detecta/Investiga |
| Máquina virtual | Investiga (INFO) |
| Logs de eventos apagados (1102, 104), mudança de horário (4616), serviço instalado (7045), Defender desligado, Code Integrity, script blocks do PowerShell (4104) | Detecta |
| Criação de processos (4688) | **Não usado** — desligado por padrão no Windows e traz linhas de comando |
| **Tráfego de rede** | **Não verifica** (programa sem código de rede) |

## Limites gerais

- **Outro PC** rodando o cheat, captura de vídeo + IA, e qualquer hardware que imite um periférico comum
  são invisíveis para software no PC verificado.
- **Windows reinstalado** ou disco trocado apaga quase todas as fontes; o programa mostra a data de
  instalação para que isso seja perguntado.
- **Firmware/UEFI comprometido** ou rootkit em kernel pode mentir para qualquer API.
- Ferramentas de limpeza removem rastros; o programa mostra sinais de limpeza, não o que foi apagado.
- Toda conclusão vale **só para as fontes examinadas**. "Sem evidências suspeitas" não é "limpo".
- Nenhum nome de cheat, hash ou data foi inventado: regras usam estrutura, comportamento e fontes
  reais; nomes públicos só rotulam algo que já correspondeu por estrutura.

## Exportação e validação (0.10.0)

| Área | Estado |
|---|---|
| Relatórios HTML, TXT, JSON | Implementado, cada um com SHA-256 |
| Relatório PDF | Implementado sem dependências (PDF 1.4, fontes padrão, WinAnsi); inclui o SHA-256 do JSON equivalente. Caracteres fora do Windows-1252 saem como `?` |
| Testes em Windows 10/11 real | **Não executados nesta entrega** — procedimento e script em [validacao-windows.md](validacao-windows.md) |
| Fontes novas (SRUM, MFT, WMI, ShellBags) | Testadas com dados sintéticos; **validação em hardware real pendente** |
