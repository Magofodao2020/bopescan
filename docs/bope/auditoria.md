# Auditoria das bases candidatas

Feita em 2026-10-15 lendo o código-fonte, a licença, os testes e o histórico de cada repositório — não
apenas o README. Nada foi executado nos PCs de ninguém.

## tempusernamedduck/screenshare-tool

- **Licença:** MIT. **Linguagem:** C/C++ (Win32).
- **Roblox:** citado só no README; nenhuma verificação específica do Roblox no código.
- **Problemas:** instala hooks globais `WH_KEYBOARD_LL` e `WH_MOUSE_LL` — captura de teclado/mouse do
  sistema todo, proibida pela especificação (keylogger). O "scanner de memória" depende de um binário
  externo que não está no repositório, então não é auditável. Sem testes. Último commit em jan/2024.
- **Decisão:** não usado; nenhum código copiado.

## ablanchard-dev/dexcheck

- **Licença:** MIT. **Linguagem:** um script PowerShell.
- **Foco:** Call of Duty/Warzone (~40 sondas). Estados OK/INFO/WARN/FLAG/NA e veredito conservador bem
  pensados; sem testes automatizados; difícil de modularizar e de testar com fixtures.
- **Decisão:** usado como **referência de ideias** (estados por módulo, linguagem que não acusa). Nenhum
  código copiado, portanto nenhuma obrigação de atribuição além desta menção.

## aeterna/aeterna-rongroi 0.9.0

- **Licença:** GPL-3.0-or-later + termos adicionais (NOTICE §7); regras CC-BY-SA-4.0.
- **Linguagem:** Rust (workspace) + Tauri 2 / React / TypeScript.
- **Qualidade:** separação coletor → regras → relatório → visão; trait `Host` com `FixtureHost` YAML
  (todo coletor testável em Linux); 955 testes, snapshots, gates de regras, baseline, locales, unicode e
  versões; ADRs para cada decisão; offline imposto por `cargo deny` e ESLint; somente leitura imposto por
  `clippy.toml`.
- **Lacunas para Roblox:** focado em FiveM; sem UserAssist/ShimCache/MuiCache, sem processo do Roblox,
  sem USB/HID, sem extensões, sem avaliação por categoria, UI sem consentimento antes da leitura,
  sem exportação.
- **Decisão:** **base escolhida.** Obrigações cumpridas: NOTICE e cabeçalhos SPDX mantidos; arquivos
  modificados com o aviso "modified version"; nomes "aeterna-rongroi"/"rongroi" não identificam a
  versão modificada (crates, binários, janela e releases renomeados); `UNOFFICIAL BUILD` em toda build;
  o marcador de build oficial do upstream nunca é definido; README original preservado em
  [docs/upstream/](../upstream/README.aeterna-rongroi.md).
