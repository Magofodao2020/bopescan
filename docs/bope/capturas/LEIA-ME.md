<!--
SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
SPDX-License-Identifier: GPL-3.0-or-later
-->

# Capturas da interface (dados sintéticos)

Feitas em Linux, no Chromium, com a interface compilada (`pnpm build`) e o IPC do Tauri respondido na
própria página. Os relatórios vêm do pipeline real (`cargo run -p bope-collectors --example view_json`)
sobre uma cópia do host de fixture `roblox-tool-history` acrescida de serviços e itens de Lixeira
**inventados**; o histórico de serviços (eventos 7036/7040) foi acrescentado à mão, porque não existe
`System.evtx` sintético com eventos do Service Control Manager. Nenhum dado vem de um PC real. Fuso:
America/Sao_Paulo. Não são capturas do aplicativo rodando no Windows/WebView2.

| Arquivo | Tela |
|---|---|
| `01-scanner-consentimento.png` | Scanner: escolha, profundidade e consentimento |
| `02-scanner-progresso.png` | Progresso real: módulo atual, contagens, tempo decorrido |
| `03-visao-geral.png` | Visão geral: avaliação, categorias, contagens |
| `04-evidencias-detalhe.png` | Evidências com o painel lateral de detalhes |
| `05-servicos.png` | Serviços do Windows: estado atual e histórico |
| `06-lixeira.png` | Lixeira: última modificação observada e itens |
| `07-linha-do-tempo.png` | Linha do tempo com tipo e confiabilidade de cada horário |
| `08-relatorios.png` | Relatórios (exportação) |
| `09-configuracoes-sobre.png` | Configurações e sobre (UNOFFICIAL BUILD, créditos, licenças) |
| `10-visao-geral-janela-estreita.png` | Janela estreita (820 px) |
