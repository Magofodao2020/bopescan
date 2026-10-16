<!--
SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
SPDX-License-Identifier: GPL-3.0-or-later
-->

# Validação em Windows 10/11 — B.O.P.E Scanner 0.10.0

**Estado:** a 0.10.0 foi compilada para Windows (`x86_64-pc-windows-gnu`, a partir de Linux) e testada
com testes automatizados e artefatos **sintéticos**. **Nenhum teste foi executado num Windows real**
durante o desenvolvimento desta versão: não havia uma máquina Windows disponível. Este documento é o
procedimento para fazer essa validação. Até ele ser executado e o resultado registrado no fim desta
página, trate a interface gráfica e os coletores SRUM, MFT, WMI e ShellBags como **não validados em
hardware real**.

## Ambientes

Execute em pelo menos dois ambientes, de preferência máquinas de teste ou VMs sem dados pessoais:

| Ambiente | Mínimo |
|---|---|
| Windows 10 22H2 (build 19045) x64 | conta local, com e sem administrador |
| Windows 11 23H2/24H2 x64 | conta local, com e sem administrador |

Para SRUM e Amcache aparecerem como lidos, a máquina precisa ter **pelo menos uma shadow copy já
existente** (Proteção do Sistema / ponto de restauração criado pelo próprio usuário **antes** do
teste). O scanner nunca cria uma.

## Parte automatizada

1. Extraia `bope-scanner-0.10.0-windows-x64.zip` numa pasta.
2. Copie `scripts/validate-windows.ps1` (do código-fonte) para a mesma pasta.
3. Abra o PowerShell **como administrador** nessa pasta e rode:

   ```powershell
   powershell -ExecutionPolicy Bypass -File .\validate-windows.ps1 -Dir .
   ```

4. O script grava `validacao-<data>\resultado.md` e `resultado.json`, além dos relatórios exportados
   (padrão e avançada, em JSON/HTML/TXT/PDF) e dos logs da CLI. O código de saída é o número de falhas.

O script verifica: versão do Windows e se é admin; runtime do WebView2; presença dos arquivos e
SHA-256 contra `SHA256SUMS.txt`; verificação padrão e avançada pela CLI; que a opção `--mode ss` não
existe mais; `fflags status` (sem rede); cada exportação contra o seu `.sha256`; cabeçalho do PDF; estado
das fontes `srum`, `mft`, `shellbags`, `wmi_subscription`, `amcache`, `usn` e `roblox_files`; o resumo de
`file_inventory`, `process_modules`, `roblox_memory` e `roblox_flags`; versão `0.11.0` no relatório;
**que nenhuma shadow copy e nenhuma assinatura WMI foram criadas**; e se a interface inicia e carrega o
WebView2.

Repita uma vez **sem administrador** (`-SkipGui` opcional): as fontes que exigem admin (SRUM, MFT,
Amcache, Prefetch) devem aparecer como `not_measured (not_admin)`, nunca como `measured` vazio nem como
`error`.

## Parte manual (interface)

- [ ] A janela abre com o título do B.O.P.E Scanner e mostra **UNOFFICIAL BUILD**.
- [ ] A tela de consentimento lista SRUM, assinaturas WMI e `.rar`/`.7z`; a opção avançada lista
      "Master File Table" e "ShellBags".
- [ ] Botão de elevação: o Windows pede confirmação (UAC); recusar mantém o programa sem admin.
- [ ] Verificação padrão: a barra de progresso avança, o botão **Cancelar** interrompe e o programa
      continua respondendo.
- [ ] Verificação avançada: o diálogo do Windows pede confirmação antes de ler; "Não" volta para a
      padrão.
- [ ] Painel "Ferramentas Roblox": a lista de fontes mostra SRUM, Master File Table, ShellBags e WMI
      com estado lida / não verificada / fora desta verificação.
- [ ] Exportar: marcar HTML, JSON, TXT e **PDF**, escolher uma pasta, salvar; cada arquivo tem um
      `.sha256` ao lado; o PDF abre no Edge e mostra versão, UTC, fontes, evidências e o SHA-256 do JSON.
- [ ] Modo SS: o nome de usuário não aparece nos caminhos (tela, HTML e PDF).
- [ ] Fechar a janela durante a verificação encerra o programa sem travar.

## Casos de teste com artefatos de teste (opcional, máquina descartável)

Só numa VM de teste, nunca no PC de um jogador:

1. Crie `C:\Users\<conta>\Downloads\Teste\Solara.exe` (cópia renomeada de `notepad.exe`), execute-o
   uma vez, feche, apague o arquivo e esvazie a Lixeira; espere a hora virar (SRUM grava por hora) e
   crie um ponto de restauração. Esperado: `mft` mostra o registro liberado de `Solara.exe`; `srum`
   (da shadow copy nova) mostra uso de CPU; `usn` mostra criação e exclusão; a correlação junta tudo
   como **Solara** (nome ambíguo: precisa de contexto Roblox para passar de INFO).
2. Abra a pasta `Downloads\Teste\Fluxus` no Explorer e escolha um arquivo nela com Arquivo → Abrir no
   Bloco de Notas. Esperado na verificação avançada: `shellbags` com `list: shellbag` e
   `list: open_save`.
3. Compacte uma pasta com `Fluxus.exe` em `.7z` e `.rar` (e outro `.rar` com "criptografar nomes").
   Esperado: `roblox_files` com `archive_entry` (`archive_format` 7z/rar5) e uma linha
   `encrypted_headers: true`.
4. Crie uma assinatura WMI de teste (somente na VM) e remova-a depois:
   ```powershell
   $f = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{Name='BopeTest'; EventNamespace='root\cimv2'; QueryLanguage='WQL'; Query="SELECT * FROM __InstanceModificationEvent WITHIN 3600 WHERE TargetInstance ISA 'Win32_LocalTime'"}
   $c = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{Name='BopeTest'; CommandLineTemplate='C:\Windows\System32\notepad.exe'}
   Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{Filter=$f; Consumer=$c}
   ```
   Esperado: regra "Uma assinatura WMI permanente executa uma linha de comando ou um script" com
   `program` notepad.exe, SHA-256 e assinatura Microsoft. Remova depois com `Remove-WmiObject`.

## Interface reformulada, serviços e Lixeira (ADR 0130–0132)

1. **Navegação**: antes de verificar, só Scanner e Configurações estão habilitados; depois, todas as
   páginas abrem e mostram o mesmo relatório. Nenhum banner "UNOFFICIAL BUILD" no topo; a indicação
   aparece em Configurações e sobre, nos fatos da Visão geral e nos relatórios exportados.
2. **Progresso**: durante a verificação, o módulo "em execução" muda a cada coleta; Lidos + Não verificados
   + Só na avançada + Pendentes = total; o tempo decorrido sobe. Cancelar para depois do módulo atual e não
   gera relatório.
3. **Horários**: em Configurações, compare a hora local mostrada com o relógio do Windows (mesmo fuso e
   deslocamento) e com "UTC primeiro". Um horário de evento no relatório HTML deve bater com o da tela.
   Teste também com o Windows num fuso com horário de verão (por exemplo Europe/Lisbon).
4. **Serviços**: compare a tabela "Estado atual" com
   ```powershell
   Get-Service PcaSvc, DiagTrack, DPS, SysMain, EventLog | Format-Table Name, Status, StartType
   Get-CimInstance Win32_Service -Filter "Name='SysMain'" | Select ProcessId, StartName, PathName
   ```
   Na VM, pare e desative o SysMain (`Stop-Service SysMain; Set-Service SysMain -StartupType Disabled`),
   verifique de novo e confira: estado Parado, inicialização Desativada, nenhuma cor de alerta, e no
   histórico eventos 7036 e 7040 com os mesmos horários que o Visualizador de Eventos mostra
   (`Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Service Control Manager'; Id=7036,7040} -MaxEvents 20`).
   Restaure depois. Sem administrador, o resultado deve continuar legível (consulta só de estado).
5. **Lixeira**: exclua dois arquivos de teste para a Lixeira, esvazie parte dela pelo Explorer e verifique.
   Confira a "Última modificação observada no artefato" contra
   `Get-ChildItem -Force C:\$Recycle.Bin\<seu SID> | Select Name, CreationTime, LastWriteTime` e a data de
   exclusão de cada item contra a coluna "Data de exclusão" do Explorer. Nada deve ter sido restaurado.

## Registro dos resultados

| Data | Windows (build) | Admin | Script (falhas) | Interface | Observações | Quem testou |
|---|---|---|---|---|---|---|
| — | — | — | — | — | ainda não executado | — |

## O que a 0.11.0 ainda precisa de um Windows real para confirmar

Nada disto foi executado num Windows durante o desenvolvimento; tudo foi verificado por compilação cruzada
(`x86_64-pc-windows-msvc`) e por hosts sintéticos:

- `ReadProcessMemory`/`VirtualQueryEx` no player do Roblox: espera-se `access: refused` na maioria dos PCs
  (o anticheat Hyperion recusa); anote o que aparece com e sem administrador.
- A comparação de código × arquivo e a detecção de hooks em um processo comum (por exemplo o Bloco de
  Notas com e sem um overlay) — quantos bytes diferem num processo sem nada injetado.
- A verificação por **catálogo** do Windows em DLLs do sistema (`in_catalog`) e o tempo do inventário de
  arquivos numa unidade cheia (orçamento de 25 minutos).
- `fflags sync` atrás de um proxy corporativo (WinHTTP usa o proxy automático do Windows) e a resposta
  do GitHub quando o limite da API é atingido (deve cair para o arquivo do `main`).
- O modo de monitoramento por alguns minutos com o Roblox aberto, e a CPU que ele usa a cada amostra.
