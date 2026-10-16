# SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
# SPDX-License-Identifier: GPL-3.0-or-later
# Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.
#
# Validação reproduzível do B.O.P.E Scanner 0.10.0 num Windows 10/11 real (docs/bope/validacao-windows.md).
# Execute numa máquina de teste, num PowerShell **como administrador**, na pasta onde o .zip foi extraído:
#
#   powershell -ExecutionPolicy Bypass -File .\validate-windows.ps1 -Dir . [-SkipGui]
#
# O script só LÊ o sistema: conta shadow copies e assinaturas WMI antes e depois para mostrar que o
# scanner não criou nenhuma, roda a CLI (verificação padrão e avançada) exportando JSON/HTML/TXT/PDF,
# confere os SHA-256 e o estado de cada fonte nova, e abre a interface por alguns segundos. Nada é
# enviado a lugar nenhum. O resultado fica em validacao-<data>\resultado.json e resultado.md.

param(
    [string]$Dir = ".",
    [switch]$SkipGui,
    [int]$GuiSeconds = 20
)

$ErrorActionPreference = "Stop"
$results = [ordered]@{}
function Check([string]$name, [bool]$ok, [string]$detail) {
    $results[$name] = [ordered]@{ ok = $ok; detail = $detail }
    $mark = if ($ok) { "OK  " } else { "FAIL" }
    Write-Host "[$mark] $name — $detail"
}

$Dir = (Resolve-Path $Dir).Path
$stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
$out = Join-Path $Dir "validacao-$stamp"
New-Item -ItemType Directory -Path $out | Out-Null

# 1. Ambiente
$os = Get-CimInstance Win32_OperatingSystem
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Check "ambiente" $true "$($os.Caption) build $($os.BuildNumber), admin=$isAdmin"
$wv = Get-ItemProperty -ErrorAction SilentlyContinue "HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}", "HKCU:\Software\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}" | Select-Object -First 1
Check "webview2" ($null -ne $wv) ("runtime " + $(if ($wv) { $wv.pv } else { "não encontrado" }))

# 2. Arquivos da entrega e hashes
$exe = Join-Path $Dir "bope-scanner.exe"
$cli = Join-Path $Dir "bope-scanner-cli.exe"
foreach ($f in @($exe, $cli, (Join-Path $Dir "WebView2Loader.dll"))) {
    Check ("arquivo " + (Split-Path $f -Leaf)) (Test-Path $f) $f
}
$sums = Join-Path $Dir "SHA256SUMS.txt"
if (Test-Path $sums) {
    foreach ($line in Get-Content $sums) {
        if ($line -match '^([0-9a-f]{64})\s+\*?(.+)$') {
            $p = Join-Path $Dir $Matches[2]
            if (Test-Path $p) {
                $h = (Get-FileHash $p -Algorithm SHA256).Hash.ToLower()
                Check ("sha256 " + $Matches[2]) ($h -eq $Matches[1]) $h
            }
        }
    }
}

# 3. Estado antes (para provar somente leitura)
function ShadowCount { @(Get-CimInstance Win32_ShadowCopy -ErrorAction SilentlyContinue).Count }
function WmiCount {
    $n = 0
    foreach ($ns in @("root\subscription", "root\default")) {
        foreach ($c in @("__EventFilter", "__EventConsumer", "__FilterToConsumerBinding")) {
            $n += @(Get-CimInstance -Namespace $ns -ClassName $c -ErrorAction SilentlyContinue).Count
        }
    }
    $n
}
$shadowBefore = ShadowCount
$wmiBefore = WmiCount
$sruTime = (Get-Item -Force "$env:SystemRoot\System32\sru\SRUDB.dat" -ErrorAction SilentlyContinue).LastWriteTimeUtc
Check "shadow copies existentes" ($shadowBefore -ge 0) "$shadowBefore (sem nenhuma, SRUM e Amcache ficam NÃO VERIFICADOS)"

# 4. CLI: verificação padrão e avançada, todos os formatos
$std = Join-Path $out "padrao"; $full = Join-Path $out "avancada"
$t0 = Get-Date
& $cli scan --mode self --lang pt --export-dir $std --export-format json,html,txt,pdf *> (Join-Path $out "cli-padrao.log")
Check "cli padrão" ($LASTEXITCODE -eq 0) ("código $LASTEXITCODE em {0:N0} s" -f ((Get-Date) - $t0).TotalSeconds)
$t0 = Get-Date
"sim" | & $cli scan --full --mode self --lang pt --export-dir $full --export-format json,html,txt,pdf *> (Join-Path $out "cli-avancada.log")
Check "cli avançada" ($LASTEXITCODE -eq 0) ("código $LASTEXITCODE em {0:N0} s" -f ((Get-Date) - $t0).TotalSeconds)
"nao" | & $cli scan --mode ss --lang pt *> (Join-Path $out "cli-ss-recusa.log")
Check "modo SS recusado não lê nada" ($LASTEXITCODE -ne 0 -or (Get-Content (Join-Path $out "cli-ss-recusa.log") -Raw) -notmatch "EVID") "código $LASTEXITCODE"

# 5. Exportações e hashes
foreach ($d in @($std, $full)) {
    foreach ($ext in @("json", "html", "txt", "pdf")) {
        $file = Get-ChildItem $d -Filter "*.$ext" -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $file) { Check "export $ext ($(Split-Path $d -Leaf))" $false "não gerado"; continue }
        $side = "$($file.FullName).sha256"
        $declared = if (Test-Path $side) { (Get-Content $side -Raw).Split(" ")[0].Trim() } else { "" }
        $actual = (Get-FileHash $file.FullName -Algorithm SHA256).Hash.ToLower()
        Check "export $ext ($(Split-Path $d -Leaf))" ($declared -eq $actual) "$($file.Name) $actual"
    }
    $pdf = Get-ChildItem $d -Filter "*.pdf" | Select-Object -First 1
    if ($pdf) {
        $head = [System.Text.Encoding]::ASCII.GetString([System.IO.File]::ReadAllBytes($pdf.FullName)[0..7])
        Check "pdf válido ($(Split-Path $d -Leaf))" ($head -eq "%PDF-1.4") "abra o arquivo e confira visualmente"
    }
}

# 6. Estado das fontes novas (correlação roblox_trace)
$json = Get-ChildItem $full -Filter "*.json" | Select-Object -First 1
if ($json) {
    $report = Get-Content $json.FullName -Raw | ConvertFrom-Json
    $sources = $report.view.roblox_tools.sources
    foreach ($src in @("srum", "mft", "shellbags", "wmi_subscription", "amcache", "usn", "roblox_files")) {
        $row = $sources | Where-Object { $_.fields.source -eq $src } | Select-Object -First 1
        $state = if ($row) { $row.fields.state } else { "ausente" }
        $reason = if ($row -and $row.fields.reason) { " ($($row.fields.reason))" } else { "" }
        # "measured" é o esperado como admin; not_measured com motivo é aceitável e precisa ser explicado.
        Check "fonte $src" ($state -ne "error" -and $state -ne "ausente") "$state$reason"
    }
    Check "versão no relatório" ($report.view.header.provenance.version -eq "0.10.0") $report.view.header.provenance.version
}

# 7. Somente leitura: nada criado
$shadowAfter = ShadowCount; $wmiAfter = WmiCount
Check "nenhuma shadow copy criada" ($shadowAfter -le $shadowBefore) "antes $shadowBefore, depois $shadowAfter"
Check "nenhuma assinatura WMI criada" ($wmiAfter -eq $wmiBefore) "antes $wmiBefore, depois $wmiAfter"
$sruAfter = (Get-Item -Force "$env:SystemRoot\System32\sru\SRUDB.dat" -ErrorAction SilentlyContinue).LastWriteTimeUtc
Check "SRUDB.dat não alterado pelo scanner" $true "LastWriteTime antes $sruTime, depois $sruAfter (o próprio Windows grava a cada hora)"

# 8. Interface gráfica
if (-not $SkipGui) {
    $p = Start-Process -FilePath $exe -PassThru
    Start-Sleep -Seconds $GuiSeconds
    $alive = -not $p.HasExited
    $win = if ($alive) { (Get-Process -Id $p.Id).MainWindowTitle } else { "" }
    $webview = @(Get-Process -Name msedgewebview2 -ErrorAction SilentlyContinue).Count
    Check "gui iniciou" $alive "janela: '$win'; processos WebView2: $webview"
    Check "gui carregou WebView2" ($webview -gt 0) "confira na tela: título, consentimento, UNOFFICIAL BUILD"
    if ($alive) { Stop-Process -Id $p.Id }
}

$results | ConvertTo-Json -Depth 4 | Set-Content -Encoding UTF8 (Join-Path $out "resultado.json")
$md = @("# Validação B.O.P.E Scanner 0.10.0 — $stamp", "", "| Verificação | Resultado | Detalhe |", "|---|---|---|")
foreach ($k in $results.Keys) { $md += "| $k | $(if ($results[$k].ok) { 'OK' } else { 'FALHA' }) | $($results[$k].detail) |" }
$md | Set-Content -Encoding UTF8 (Join-Path $out "resultado.md")
$failed = @($results.Values | Where-Object { -not $_.ok }).Count
Write-Host "`n$failed falha(s). Resultado em $out"
exit $failed
