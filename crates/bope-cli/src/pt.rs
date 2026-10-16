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

/// O que a verificação avançada lê além da padrão.
pub(crate) const FULL_READS: [&str; 7] = [
    "o nome de cada pasta de cache de servidor que o FiveM for GTA V Enhanced guarda — uma por servidor em que este PC entrou — com quando foi criada e alterada",
    "as palavras dos comandos do PowerShell, guardadas só como tipos — se um comando baixou algo e executou, mandou o Microsoft Defender ignorar algo, limpou um log ou histórico — do histórico do PowerShell e dos scripts que ele marcou como suspeitos. Nenhum comando é guardado ou mostrado; só o nome do site de onde um comando baixou algo",
    "as extensões de cada perfil do Chrome, Edge, Brave, Opera, Vivaldi e Firefox: id, nome, versão e se podem acessar roblox.com ou todos os sites, rodar scripts do usuário ou controlar o DevTools — nunca histórico, cookies, senhas ou conteúdo de páginas",
    "em Downloads, Área de Trabalho e Documentos, até um nível abaixo: programas, arquivos compactados e scripts pelo nome e horário, com SHA-256, assinatura e a Marca da Web (Mark of the Web) que o Windows anexou no download, com o nome do site, quais funções exclusivas de executor cada script .lua chama, nunca o texto, e os nomes de arquivos de macro do AutoHotkey, AutoIt e similares",
    "as listas do Explorer: programas iniciados pela caixa Executar (RunMRU, nunca os argumentos), pastas digitadas na barra de endereço (TypedPaths), programas, scripts e arquivos compactados abertos recentemente (RecentDocs, só esses tipos) e os programas que usaram por último uma janela Abrir ou Salvar",
    "a Master File Table do NTFS da unidade do Windows, lida em modo bruto e somente leitura: o nome de cada registro passa pela memória uma vez e só ficam os nomes do catálogo de ferramentas do Roblox, com a pasta, os horários do NTFS e se o registro ainda está em uso ou foi liberado por uma exclusão — nunca o conteúdo de um arquivo",
    "as pastas que o Explorer lembra (ShellBags) e os arquivos que a caixa Abrir/Salvar lembra (OpenSavePidlMRU): só caminhos com um nome do catálogo de ferramentas do Roblox ou que citam o Roblox",
];

/// A pergunta da verificação avançada.
pub(crate) fn full_question(items: &str) -> String {
    format!(
        "Verificação avançada — lê mais do que a padrão:\n  - {items}\nNada é enviado a lugar nenhum.\nDigite sim para a verificação avançada; qualquer outra coisa inicia a padrão: "
    )
}
