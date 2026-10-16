// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

//! Texto da CLI em português do Brasil. Uma chave ausente aqui cai para o inglês.

/// O texto de `key`, quando traduzido.
pub(crate) fn text(key: &str) -> Option<&'static str> {
    Some(match key {
        "unofficial" => {
            "não foi gerado pelo fluxo de release oficial do aeterna-rongroi (esta é a versão modificada B.O.P.E Scanner). Confira o hash da sua cópia."
        }
        "official" => "build oficial",
        "found" => "ENCONTRADO",
        "not_found" => "NÃO ENCONTRADO",
        "hidden" => "Oculto no modo SS",
        "unmeasured_expected" => "NÃO VERIFICADO (esperado aqui)",
        "unmeasured_unexpected" => "NÃO VERIFICADO (não esperado)",
        "description" => "Sobre esta verificação",
        "falsepositives" => "Coisas comuns que também produzem isto",
        "scope_not_admin" => {
            "Escopo: {n} verificação(ões) não puderam ser respondidas porque esta execução não tem direitos de administrador. Execute de novo como administrador para respondê-las."
        }
        "scope_not_attempted" => {
            "Escopo: {n} verificação(ões) não puderam ser respondidas porque o programa parou de ler antes de chegar ao que elas perguntam. É um limite deste programa, não um achado sobre o PC."
        }
        "scope_not_consented" => {
            "Escopo: {n} verificação(ões) não foram respondidas porque só a verificação avançada as lê, e a verificação padrão foi escolhida."
        }
        "boot_time" => {
            "Início do Windows: {at}, {since} antes desta verificação. Não é zerado por \"Desligar\" com Inicialização Rápida (padrão do Windows), suspensão ou hibernação; é zerado por reinício."
        }
        "boot_time_unmeasured" => "Início do Windows: não verificado — {reason}",
        "own_traces" => "rastros do próprio programa (separados)",
        "own_traces_note" => {
            "o que este programa deixou no que foi lido; não é evidência sobre este PC"
        }
        "unmatched" => "observações sem regra",
        "unmatched_note" => {
            "o que os coletores viram e nenhuma regra marcou; são coisas vistas, não achados"
        }
        "footer" => {
            "Somente evidências. Este relatório não prova que um PC está limpo nem que alguém trapaceou."
        }
        "listed" => {
            "Listado: {found} encontrado(s) · {not_found} não encontrado(s) · {unmeasured} não verificado(s)"
        }
        "code" => "Código: {url}",
        "code_unknown" => "Código: {url} (o código exato desta build não é conhecido)",
        "elevated_yes" => "administrador",
        "elevated_no" => "usuário comum",
        "declined" => "Verificação cancelada. Nada foi lido.",
        "elevate_started" => {
            "Reiniciando com direitos de administrador. A nova janela fará a verificação."
        }
        "elevate_declined" => "O pedido de administrador foi recusado. Nada foi verificado.",
        "elevate_failed" => "não foi possível reiniciar com direitos de administrador",
        "elevate_not_windows" => {
            "Direitos de administrador são do Windows; --elevate não faz nada neste sistema."
        }
        "pause_at_exit" => "Pressione Enter para fechar esta janela.",
        "timeline" => "linha do tempo",
        "timeline_note" => {
            "os horários deste relatório, do mais antigo ao mais novo. Ordem de horários registrados não é ordem de eventos, e um registro ausente não foi necessariamente apagado. Um horário de listagem de pasta é o que o sistema de arquivos diz, e quem escreveu o arquivo pode alterá-lo."
        }
        "coverage" => "cobre",
        "coverage_note" => "fora do intervalo que uma fonte cobre, ela não diz nada",
        "not_measured" => "não verificado",
        "scan_time" => "esta verificação rodou",
        "boot_anchor" => "Windows iniciou",
        "selectors" => "O que os horários selecionados significam",
        "selector_causes" => "Coisas comuns por trás destes horários",
        "row_band_found" => {
            "A fonte só tinha de {from} a {to} quando foi lida; o que foi contado aqui é desse intervalo."
        }
        "row_band_not_found" => {
            "Nada neste intervalo: {from} a {to}, o que a fonte tinha quando foi lida. Nada antes disso foi visto."
        }
        "row_band_none" => {
            "A fonte não tinha nenhum registro quando foi lida, então não há intervalo em que algo pudesse ser visto."
        }
        "tier_standard" => "verificação padrão",
        "tier_full" => "verificação avançada",
        "full_declined" => {
            "Verificação padrão: as fontes que só a verificação avançada lê não serão lidas."
        }
        "server_identity_question" => {
            "Mostrar a quem está assistindo quais servidores são estes (nomes das pastas de cache de servidor do FiveM)? Se não, cada nome aparece como %SERVER_IDENTITY%. [s/N] "
        }
        "account_identifier_question" => {
            "Mostrar a quem está assistindo os identificadores de conta lidos? Se não, cada um aparece como %ACCOUNT_IDENTIFIER%. [s/N] "
        }
        "download_host_question" => {
            "Mostrar a quem está assistindo o nome de cada site de onde um arquivo ou comando baixou algo? Só o nome do site é lido, nunca o resto do endereço. Se não, cada nome aparece como %DOWNLOAD_HOST%. [s/N] "
        }
        "check" => "verificação",
        _ => return None,
    })
}

/// A duração em dias, horas e minutos.
pub(crate) fn elapsed(days: u64, hours: u64, minutes: u64) -> String {
    if days == 0 {
        format!("{hours} h {minutes} min")
    } else {
        format!("{days} d {hours} h {minutes} min")
    }
}

/// A pergunta de consentimento do modo SS.
pub(crate) const CONSENT: &str = "Modo SS — verificação durante compartilhamento de tela (B.O.P.E Scanner)\n\
Este programa vai ler, neste PC (somente leitura):\n\
\x20 - configurações de segurança como Secure Boot (como o Windows e o firmware informam), memory integrity e as políticas de log do PowerShell deste PC e da conta do Windows que executa a verificação, se as mitigações de execução especulativa, o SEHOP e a proteção de namespace de objetos do kernel estão desligados, e se o firmware descreve uma IOMMU\n\
\x20 - os programas rodando agora e quando cada um começou, e os arquivos nas pastas de plugin do FiveM para GTA V Legacy e Enhanced e o próprio FiveM.exe, com suas assinaturas (Authenticode)\n\
\x20 - das pastas de log, crash e cache do FiveM: quantos arquivos e subpastas, o tamanho total e os horários mais antigo e mais novo, nunca um nome de arquivo\n\
\x20 - o que o Windows registrou sobre programas executados (Prefetch, BAM, Program Compatibility Assistant) e se o Prefetch está ligado\n\
\x20 - quantos eventos de cada tipo os logs de eventos do Windows (event log) guardam, não o que os eventos dizem, e o arquivo e tamanho que o Windows define para cada log\n\
\x20 - se um arquivo de Prefetch ou de log de eventos está marcado como somente leitura\n\
\x20 - quantos registros o change journal da unidade do Windows guarda e para certas pastas quantos criaram, apagaram, renomearam ou alteraram arquivos, nunca um nome de arquivo\n\
\x20 - os drivers registrados no Windows: nome e tipo de início de cada serviço de driver (driver), onde está o arquivo e o SHA-256\n\
\x20 - os dispositivos PCI que o Windows lembra, presentes ou não, com fabricante, dispositivo, classe e datas, nunca número de série\n\
\x20 - como o Windows iniciou cada vez que o log System lembra: inicialização completa ou Fast Startup\n\
\x20 - o que o Windows inicia sozinho: serviços, valores Run e RunOnce e cada tarefa agendada (scheduled task), com o arquivo que iniciam — onde está e, fora da pasta do Windows, SHA-256 e assinatura; nunca os argumentos\n\
\x20 - as exclusões (exclusion) do Microsoft Defender: pastas, programas e tipos de arquivo, e quantos endereços de rede, nunca os endereços\n\
\x20 - as configurações que decidem para onde vai o tráfego de rede: as linhas do arquivo hosts que dão um endereço a um nome sob roblox.com, rbxcdn.com, robloxlabs.com, cfx.re, fivem.net ou rockstargames.com, se há proxy ligado, e as regras do Windows Firewall para programas nas pastas do FiveM\n\
\x20 - o que o Windows diz que esta instalação é (edição, build, fabricante e modelo) e como os serviços do Windows (Defender, Windows Update, Error Reporting, Event Log, SysMain, Search) estão configurados para iniciar\n\
\x20 - se seis locais conhecidos existem: cinco instalados pelas modificações de Windows Atlas e ReviOS, e a pasta do mecanismo do Defender\n\
\x20 - as pastas do próprio Roblox: o player RobloxPlayerBeta.exe e cada programa ou DLL ao lado dele com SHA-256 e assinatura (Authenticode), quantas configurações o ClientAppSettings.json define (nunca os valores), quantos logs do Roblox existem e seus horários mais antigo e mais novo (nenhum log é aberto), e se Bloxstrap, Fishstrap ou Voidstrap está instalado\n\
\x20 - o player do Roblox em execução por dentro, quando o anticheat do Roblox (Hyperion) permite: os módulos que o RobloxPlayerBeta.exe carregou fora da pasta do Windows, com SHA-256 e assinatura, e quanta memória executável ele tem por tipo, nunca o conteúdo; e programas rodando de Temp, Downloads, Área de Trabalho, Documentos, AppData ou Lixeira, com SHA-256 e assinatura\n\
\x20 - pastas organizadas como executor de scripts do Roblox (pastas autoexec e workspace lado a lado) em Área de Trabalho, Downloads, Documentos, AppData e Temp, até dois níveis: a pasta, seus programas com SHA-256 e assinatura, e quais funções exclusivas de executor cada script do autoexec chama, nunca o script; e pastas com nome exato de executor conhecido publicamente\n\
\x20 - nomes que correspondem a um catálogo de ferramentas do Roblox (Bloxstrap, FFlagManager, FPS unlockers, executores, injetores e variações de grafia), e só esses nomes: arquivos e pastas em AppData, Temp, ProgramData, Program Files, Downloads, Área de Trabalho e Documentos, os nomes dentro de arquivos .zip ali (nada é extraído) e itens da $Recycle.Bin desta conta, com onde estavam e quando foram excluídos; programas que correspondem recebem SHA-256 e assinatura\n\
\x20 - atalhos (.lnk) na Área de Trabalho, no menu Iniciar, na barra de tarefas e em Recentes que apontam para uma ferramenta do Roblox ou para um programa nas suas pastas: o caminho de destino, se ele ainda existe e os horários do destino gravados no atalho, nunca os argumentos\n\
\x20 - o Amcache.hve, inventário de programas do Windows, lido de uma shadow copy que já existe (nenhuma é criada): entradas de ferramentas do Roblox e de programas nas suas pastas\n\
\x20 - o banco do SRUM (SRUDB.dat), lido do mesmo tipo de shadow copy existente: para programas com nome de ferramenta do Roblox ou nas suas pastas, quanto tempo de CPU e tráfego de rede o Windows registrou por hora, nunca nomes de usuário ou de rede\n\
\x20 - assinaturas de eventos WMI permanentes (filtros, consumidores e vínculos): nomes, consultas, o programa que um consumidor inicia com SHA-256 e assinatura, nunca o texto de um script ou os argumentos de um comando\n\
\x20 - o estado de cinco serviços do Windows (PcaSvc, DiagTrack, DPS, SysMain, EventLog) como o Service Control Manager informa agora, só com direito de consulta, e os eventos de estado, tipo de inicialização e instalação (7034, 7036, 7040, 7045) no log System; nenhum serviço é iniciado, parado ou alterado\n\
\x20 - a $Recycle.Bin desta conta na unidade do sistema: de cada item, o arquivo $I (onde estava, tamanho, quando foi excluído) e os horários das entradas $I e $R; os arquivos excluídos nunca são abertos, nada é restaurado nem removido, e o modo SS mostra só um resumo sem nomes e os itens que batem com o catálogo de ferramentas do Roblox\n\
\x20 - arquivos de FastFlag do Roblox (ClientAppSettings.json nas pastas do Roblox e dos bootstrappers, e arquivos de configuração de ferramentas de FastFlag): tamanho, horários, SHA-256, quantas flags de cada tipo e os nomes das flags de rede/física, nunca os valores\n\
\x20 - no change journal, os nomes de arquivos que correspondem ao catálogo de ferramentas do Roblox, com quantas vezes foram criados, excluídos ou renomeados\n\
\x20 - o que o Explorer registra sobre programas que esta conta iniciou: UserAssist (quantas vezes e quando por último), MuiCache (nome do produto e empresa do próprio programa), FeatureUsage (contadores da barra de tarefas) e o AppCompatCache, com o caminho de cada programa\n\
\x20 - configurações do registro que iniciam ou carregam algo dentro de, ou no lugar de, outro programa: debuggers em Image File Execution Options, monitores SilentProcessExit, AppInit_DLLs, AppCertDlls e Shell e Userinit do Winlogon — só o programa indicado, nunca os argumentos\n\
\x20 - os programas da lista de instalados do Windows (nome, editor, versão, data e pasta), agrupados como ferramentas de macro, Cheat Engine e outras ferramentas de memória, softwares de periféricos, limpadores, VPN e máquinas virtuais\n\
\x20 - dispositivos USB e HID que o Windows lembra, presentes ou não: números de fabricante e produto (nunca número de série), se o fabricante faz placas tipo Arduino, quando cada um foi instalado, conectado por último e removido; os modelos de armazenamento USB lembrados; e as instalações que o setupapi.dev.log registra com o horário local\n\
\x20 - os adaptadores de rede com driver (descrição, componente e fornecedor, se é adaptador de software ou TAP/túnel), se há proxy WinHTTP e quais variáveis de ambiente de proxy existem, nunca um endereço\n\
\x20 - o que o firmware diz que este PC é (SMBIOS: fabricante, modelo, placa-mãe, BIOS, versão e data), se o Windows iniciou por UEFI e se há drivers de convidado de máquina virtual\n\
\x20 - quando partes deste PC foram configuradas, como datas: instalação do Windows, criação do change journal, da raiz da unidade e da $Recycle.Bin, e das pastas do FiveM\n\
\x20 - quando o Windows iniciou pela última vez, mostrado uma vez no topo do relatório\n\
Mostra o que corresponde a uma regra e uma linha do tempo (timeline) com: os horários que o Windows registrou (Prefetch, BAM, Program Compatibility Assistant) para programas chamados FiveM.exe, GTA5.exe, GTA5_Enhanced.exe, PlayGTAV.exe ou FiveM_b<número>_GTAProcess.exe; os horários que UserAssist, AppCompatCache e FeatureUsage guardam para programas cujo nome começa com Solara, Xeno, Celery, Fluxus, KRNL, JJSploit, Synapse, Seliware, Nihon ou Script-Ware — um nome não mostra qual programa era; o registro mais antigo e mais novo de cada log; quando o Code Integrity recusou um arquivo e o Defender detectou algo, nunca qual; e quanto tempo cada fonte alcança no passado. O próprio código deste programa não envia nada a lugar nenhum. Seu nome de usuário fica oculto nos caminhos. O endereço de uma linha do hosts aparece só como seu tipo (loopback, unspecified, private ou public). O nome de um valor Run ou tarefa agendada não é mostrado.\n\
Uma avaliação separada classifica cada categoria como OK, INFO, WARN, FLAG ou NÃO VERIFICADO; ela nunca declara o PC limpo nem culpado.\n\
Você pode recusar.\n\
Continuar? [s/N] ";

/// O que a verificação avançada lê além da padrão.
pub(crate) const FULL_READS: [&str; 7] = [
    "o nome de cada pasta de cache de servidor que o FiveM for GTA V Enhanced guarda — uma por servidor em que este PC entrou — com quando foi criada e alterada",
    "as palavras dos comandos do PowerShell, guardadas só como tipos — se um comando baixou algo e executou, mandou o Microsoft Defender ignorar algo, limpou um log ou histórico — do histórico do PowerShell e dos scripts que ele marcou como suspeitos. Nenhum comando é guardado ou mostrado; só o nome do site de onde um comando baixou algo, que o modo SS mostra apenas se você concordar separadamente",
    "as extensões de cada perfil do Chrome, Edge, Brave, Opera, Vivaldi e Firefox: id, nome, versão e se podem acessar roblox.com ou todos os sites, rodar scripts do usuário ou controlar o DevTools — nunca histórico, cookies, senhas ou conteúdo de páginas",
    "em Downloads, Área de Trabalho e Documentos, até um nível abaixo: programas, arquivos compactados e scripts pelo nome e horário, com SHA-256, assinatura e a Marca da Web (Mark of the Web) que o Windows anexou no download — o nome do site só aparece no modo SS se você concordar —, quais funções exclusivas de executor cada script .lua chama, nunca o texto, e os nomes de arquivos de macro do AutoHotkey, AutoIt e similares",
    "as listas do Explorer: programas iniciados pela caixa Executar (RunMRU, nunca os argumentos), pastas digitadas na barra de endereço (TypedPaths), programas, scripts e arquivos compactados abertos recentemente (RecentDocs, só esses tipos) e os programas que usaram por último uma janela Abrir ou Salvar",
    "a Master File Table do NTFS da unidade do Windows, lida em modo bruto e somente leitura: o nome de cada registro passa pela memória uma vez e só ficam os nomes do catálogo de ferramentas do Roblox, com a pasta, os horários do NTFS e se o registro ainda está em uso ou foi liberado por uma exclusão — nunca o conteúdo de um arquivo",
    "as pastas que o Explorer lembra (ShellBags) e os arquivos que a caixa Abrir/Salvar lembra (OpenSavePidlMRU): só caminhos com um nome do catálogo de ferramentas do Roblox ou que citam o Roblox",
];

/// A pergunta da verificação avançada.
pub(crate) fn full_question(items: &str) -> String {
    format!(
        "Verificação avançada — lê mais do que a padrão:\n  - {items}\nNada é enviado a lugar nenhum. No modo SS, nomes de servidores e de sites só aparecem se você concordar separadamente.\nDigite sim para a verificação avançada; qualquer outra coisa inicia a padrão: "
    )
}
