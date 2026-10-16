# Guia de screenshare — B.O.P.E Scanner **0.10.0**

Para quem conduz a verificação (staff) e para quem é verificado (jogador). O programa lê rastros; quem
decide é uma pessoa que entende o que eles significam. Leia também [capacidades.md](capacidades.md).

## 1. Antes da chamada

1. Publique no seu servidor/Discord o **SHA-256** do arquivo oficial da sua comunidade
   (`bope-scanner-0.10.0-windows-x64.exe` ou `bope-scanner-cli-0.10.0-windows-x64.exe`). O release traz
   `SHA256SUMS.txt`.
2. Peça ao jogador que baixe o arquivo **durante** a chamada e confira o hash compartilhando a tela:

   ```powershell
   Get-FileHash .\bope-scanner-0.10.0-windows-x64.exe -Algorithm SHA256
   ```

   Hash diferente: pare. Não use cópias enviadas por terceiros.
3. O jogador deve fechar programas com dados pessoais na tela. O programa não lê conversas, senhas,
   cookies nem pagamentos — mas a tela compartilhada mostra o que estiver aberto.

## 2. Durante a verificação

1. Abra o programa. A tela inicial mostra **o que será examinado**, o que nunca é lido, e pede para
   escolher:
   - **Modo screenshare** (padrão): oculta o nome de usuário e lista só o que corresponde a uma regra.
   - **Verificação padrão** ou **avançada** (inclui extensões de navegador, arquivos baixados, listas
     recentes do Explorer e comandos do PowerShell — sem conteúdo). A avançada é mais completa e mais
     pessoal: o jogador decide.
2. O jogador marca o consentimento e clica em **Iniciar verificação**. Para examinar logs de segurança,
   o Prefetch e outros processos, o programa pede **elevação (UAC)** e diz por quê. Recusar não impede a
   verificação: o que não puder ser lido aparece como **NÃO VERIFICADO**, nunca como "nada encontrado".
3. Acompanhe o progresso módulo a módulo. **Cancelar** é sempre possível; um relatório cancelado não é
   usado para conclusão.
4. Deixe o Roblox **aberto** se quiser examinar o processo do player (módulos carregados e memória
   executável). O Hyperion pode negar a leitura — isso é registrado como lacuna, não como achado.

## 3. Lendo o resultado

| Estado | Significado |
|---|---|
| **OK** | A categoria foi examinada e nenhuma regra correspondeu. Não prova ausência. |
| **INFO** | Contexto (ex.: VPN instalada, PC em máquina virtual). Não pesa contra ninguém. |
| **WARN** | Algo que merece uma pergunta (ex.: placa Arduino agindo como teclado, extensão com acesso ao Roblox). |
| **FLAG** | Rastro forte (ex.: pasta com estrutura de executor, script com APIs exclusivas de executor). |
| **NÃO VERIFICADO** | Não foi possível ler (sem admin, fonte ausente, acesso negado). Pergunte por quê. |

A **conclusão geral** é uma destas — nenhuma diz "inocente" ou "culpado":

- *Sem evidências suspeitas nas fontes examinadas* — só fala das fontes listadas.
- *Inconclusivo* — fontes importantes não puderam ser lidas.
- *Requer revisão manual* — há WARN/FLAG de uma fonte só.
- *Múltiplos indicadores corroborados* — fontes **independentes** concordam.
- *Evidência de alta confiança* — várias fontes independentes com FLAG, perto no tempo.

Cada achado traz a **fonte**, a **data** (quando a fonte guarda uma), hash/assinatura quando há
arquivo, **explicações legítimas** e as **limitações** da fonte. Leia as explicações em voz alta antes
de perguntar — um macro de mouse da marca, um VPN de trabalho ou um Arduino de faculdade são comuns.

Sinais de **limpeza** (log de eventos apagado, Prefetch vazio, histórico desligado) são registrados
como tal. Limpar não é trapacear; é motivo para perguntar e para dar mais peso à inspeção visual.

## 4. Inspeção visual — o que software nenhum dentro do Windows enxerga

Peça ao jogador que mostre com a câmera do celular ou descreva:

- [ ] **Outro computador** ligado na mesa ou no mesmo cabo de rede (cheats DMA rodam em um 2º PC).
- [ ] **Placas PCIe** desconhecidas (DMA/FPGA, ex.: placa com porta USB-C ou Thunderbolt no slot
      M.2/PCIe) — peça uma foto do gabinete aberto se a comunidade exigir.
- [ ] Cabos USB saindo do PC para **outro dispositivo** que não é periférico (fusers, KMBox, placas
      Arduino/Teensy/RP2040 escondidas).
- [ ] **Capturadora/HDMI splitter** entre o PC e o monitor (fusers de vídeo).
- [ ] Mouse/teclado com software de macro: abra o programa da marca e mostre as macros salvas **na
      memória do dispositivo**.
- [ ] Monitor secundário, celular ou tablet mostrando algo durante o jogo.

Peça também, se a comunidade usar: **Gerenciador de Tarefas** (aba Detalhes), `msinfo32` (Secure Boot,
Virtualização) e o **Painel do Roblox** (`Configurações → Sobre`) com a versão em uso.

## 5. Depois

1. Salve o relatório (**HTML + JSON + TXT**) na pasta escolhida. Cada arquivo tem um `.sha256` ao lado
   e o relatório inclui as versões do programa e das regras.
2. Guarde o relatório só pelo tempo que sua comunidade precisa. Ele é **dado pessoal**; no modo SS o
   nome de usuário já sai oculto.
3. Decida com base no **conjunto**: relatório + inspeção visual + conversa. Um achado isolado com
   explicação legítima plausível não é prova.
4. Se o jogador contestar, ele pode rodar a mesma versão no modo próprio e ver exatamente o que foi lido.

## 6. O que o jogador pode exigir

- Ver a tela de consentimento **antes** de qualquer leitura e recusar a verificação avançada.
- Saber por que o programa pede administrador.
- Receber uma cópia do relatório que foi salvo sobre ele.
- O programa **não instala nada**, não deixa serviço nem driver, não desliga o antivírus e não envia
  dados. Ao fechar, apaga a própria pasta temporária do WebView.
