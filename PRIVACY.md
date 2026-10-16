# Privacy

> **B.O.P.E Scanner** (modified version of aeterna-rongroi). The section "B.O.P.E Scanner additions" just
> below lists what this version reads beyond the original; everything after it is the original text and
> still applies, except where B.O.P.E 0.11 changed it (one view, no screenshare mode; one network request
> for a public reference file). Resumo em português: o programa não envia dados sobre o PC, a verificação
> ou você; a única requisição de rede baixa o arquivo público de referência de FastFlags do GitHub quando
> você pede ou quando a verificação automática (que pode ser desligada) está ligada. Não altera nada, não
> lê senhas, cookies, tokens, mensagens, conteúdo de documentos nem dados de pagamento, e só lê as
> fontes mais pessoais na verificação avançada escolhida antes de começar.

## B.O.P.E Scanner additions

Standard scan:
- **UserAssist, MuiCache, FeatureUsage** (this account): program paths/names, run and focus counts, last
  run time. **ShimCache**: program paths and file times. **Installed programs**: name, publisher,
  version, install date and folder.
- **Execution hijack settings** (IFEO, SilentProcessExit, AppInit/AppCert DLLs, Winlogon): the configured
  program paths.
- **The Roblox installation**: version folders, the player's hash and signature, file names beside it,
  the *names* of flags in `ClientAppSettings.json` (never values), log folder counts/sizes/times (never
  log text), bootstrapper presence.
- **The running Roblox player**, when it is open: its parent process, the paths of loaded modules that are
  not Windows' or Roblox's, and *counts* of executable memory regions by type (`roblox_process`). The
  memory analysis added in 0.11 is described below; the process is never changed.
- **Programs running from Downloads, Desktop or Temp**: their paths, hashes and signatures.
- **Executor folders**: the folder layout, file names, and for scripts in them the *names of
  executor-only functions* they mention and counts. **Script text is never stored or shown.**
- **USB devices**: vendor/product ids, device class, interface kinds, first/last times Windows stores,
  and install section headers from `setupapi.dev.log`. Never serial numbers.
- **Network adapters and proxies**: adapter descriptions and kinds (VPN/TAP), whether a WinHTTP or
  environment proxy is set and its host. No traffic.
- **Firmware identity**: BIOS vendor/product/version and VM hints. Never serial numbers or UUIDs.

- **Roblox tool names on disk** (ADR 0118): in AppData, Temp, ProgramData, Program Files, Downloads,
  Desktop and Documents, only the names that match the Roblox tool catalog, with size, times, and for
  programs SHA-256 and signature; the names inside `.zip`, `.rar` and `.7z` archives there, read from
  their headers only (nothing extracted; ADR 0128); and items
  in this account's Recycle Bin whose original name matches, with original path and deletion time.
  Names that do not match are compared and dropped.
- **Shortcuts** (ADR 0119): `.lnk` files on the Desktop, Start menu, taskbar and Recent that point at a
  Roblox tool, or (outside Recent) at a program in your own folders: target path, whether it exists
  today, target times saved in the shortcut. Arguments are never read out.
- **Amcache** (ADR 0120), from an existing shadow copy only (none is created): inventory rows for Roblox
  tools, Roblox paths and programs in your own folders (path, SHA-1, publisher, version, time written).
  Other programs are counted, not listed.
- **SRUM** (ADR 0124), from an existing shadow copy only (none is created): for programs matching the
  Roblox tool catalog, naming Roblox or in your own folders, their path, the CPU time and network byte
  totals Windows recorded per hour, and the first and last hour. User SIDs, network interfaces and
  network profile names are never read.
- **Permanent WMI event subscriptions** (ADR 0127): names and queries of event filters, consumer
  classes and names, the program a consumer starts (never its arguments) with SHA-256 and signature, a
  script consumer's engine and script file, and for an inline script only its length, SHA-256 and the
  program/script file names it mentions — never the script's text.
- **Windows services** (ADR 0130): for PcaSvc, DiagTrack, DPS, SysMain and EventLog, what the Service
  Control Manager reports now (state, process id, start type, account, program path), asked with query
  rights only, and their state, start-type and install events (7034, 7036, 7040, 7045) in the System log,
  read as a file. No service is started, stopped or changed.
- **Recycle Bin times** (ADR 0131): for this account's Recycle Bin on the system drive, each `$I` file
  (original path, size, deletion time) and the times of the `$I` and `$R` entries; the deleted files are
  never opened and nothing is restored or removed.
- **Change journal names** (ADR 0121): names of files matching the Roblox tool catalog, with counts of
  creations, deletions and renames and first/last times. Every other name is dropped after comparison.
- **FastFlag files** (ADR 0122): size, times, SHA-256, counts of flags by kind and the names of
  network/physics flags (`fastflags`). Since 0.11 `roblox_flags` also reads the **values** the
  player's and bootstrappers' settings files set, to compare them with the reference (below).
- **Correlation** (ADR 0123) reads nothing new: it combines the rows above and says which sources
  could be read.

Advanced scan only (chosen on the start screen before anything is read):
- **Browser extensions**: id, name, version, permissions and site matches. Never cookies, history,
  saved passwords, storage or extension data.
- **Files in Downloads, Desktop, Documents** (one level + one subfolder level): names, sizes, times of
  programs, archives and scripts; hash and signature of programs; Mark-of-the-Web zone. The download
  host only if the person ticks that option; full download URLs never.
- **Explorer recent lists**: RunMRU program names (no arguments), typed folder paths, recent documents
  of a fixed set of extensions, last-visited program names.
- **Master File Table** (ADR 0125): the system volume is read raw and read-only; every file record's
  name passes through memory once and only names matching the Roblox tool catalog are kept, with folder
  path, NTFS times, size and whether the record is in use or freed. No file content is read.
- **ShellBags and OpenSavePidlMRU** (ADR 0126): folder and dialog paths Explorer remembers, kept only
  when a segment matches the Roblox tool catalog or names Roblox; every other path is dropped after
  comparison.

Saved reports may be HTML, TXT, JSON or PDF (ADR 0129); the PDF carries the SHA-256 of the JSON export
of the same view.

Saved reports go only to the folder the person picks. Nothing is uploaded.

### Added in B.O.P.E 0.11 (ADR 0133–0138)

Standard scan:
- **Modules and executable memory of running processes** (`process_modules`, ADR 0134): the path,
  hash, signature, catalog state and PE structure of loaded DLLs that are not routine signed Windows
  modules, which processes loaded them, and the address, size and protection of private executable
  memory and of image mappings the loader does not list. Opened with query and read rights only.
- **The Roblox player's memory** (`roblox_memory`, ADR 0134), when Windows and Roblox's anti-cheat allow
  it (usually they do not; the report then says "refused"): its identity checks; code of its modules
  compared with their files (only counts and address ranges of differing bytes are kept); jumps written
  at exported functions and where they go; executable memory no module accounts for; and **strings of
  fixed categories only** — executor function names, injection API names, FastFlag names and JSON
  assignments, module paths, URLs, script loaders — at most 40 per category, with address and encoding.
  **Chat, page text and any uncategorised text are never kept.** Nothing is written to the process.
- **FastFlag values** (`roblox_flags`, ADR 0135–0136): the values set in the player's and bootstrappers'
  settings files, other copies of them (backups, older version folders) with their file times, and the
  FastFlag assignments in Roblox crash dumps (`%LOCALAPPDATA%\CrashDumps`, `Roblox\logs`) with the dump's
  time. Nothing else of a dump is kept.

Full scan:
- **File inventory of every accessible drive** (`file_inventory`, ADR 0133): every folder is listed and
  every DLL, executable and driver is counted; the hash, signature, catalog state and PE structure of
  those that are not routine are reported with their path and times. Files are read, never run.

Only when the person starts it:
- **Monitoring mode** (`roblox_monitor`, ADR 0137): samples of the Roblox player's modules, executable
  memory and FastFlag values, and the settings files' hashes and values, at the interval chosen, while the
  window (or console) that started it stays open. Kept in memory for the next report, or written only to
  the file named on the command line.

**The one network request** (ADR 0136): the FastFlag reference file
`MaximumADHD/Roblox-FFlag-Tracker/PCDesktopClient.json` is downloaded from `api.github.com` /
`raw.githubusercontent.com` when you press "Atualizar agora", run `fflags sync`, or — unless you turn it off
on the Roblox page — at most every six hours when the window opens. The request carries the file's address,
a fixed program name and version, and a tag GitHub gave for the copy you already have. Nothing from the
scan, your PC or you is sent; GitHub sees your IP address as with any download. A scan never makes a
request; it uses the copy on disk (`%LOCALAPPDATA%\BOPE Scanner\fflag-reference`) or says there is none.

**The screenshare mode is removed** (ADR 0138). There is one view of the report, described under
[What is shown](#what-is-shown).


## What the tool reads

Only local artifacts needed by its collectors, for example machine security settings (Secure Boot),
FiveM's plugin folders (for GTA V Legacy and Enhanced) and the signatures of the files in them, FiveM's own program file (`FiveM.exe`) and its signature, counts, sizes and times of FiveM's log, crash and cache folders and of Legacy's resource cache index, the list of running processes with when each started, the drivers
registered with Windows and a SHA-256 of each driver's file, the PCI devices Windows remembers, what the Program Compatibility Assistant, Windows
Prefetch and the Background Activity Moderator recorded about programs that ran, and what the Windows
event logs hold, counts of the Windows drive's change journal records, for the drive as a whole and
for each folder those collectors read and for the folder PowerShell keeps its command history in, with no
file name, and the settings that decide where network
traffic goes: the hosts file, whether a proxy is set, and the Windows Firewall rules for FiveM, and what
Windows says this installation is, with how the services Windows ships with are set to start,
whether six named places are on this PC, and what Windows is set to start by itself — services, `Run`
and `RunOnce` values and scheduled tasks — with the file each one starts, what Microsoft Defender is
told not to scan, and when parts of this PC were set up, as dates (see [below](#how-far-back-the-traces-reach)).
Each collector is listed with what it reads in [docs/architecture.md](docs/architecture.md).

Of each file in FiveM's plugin folders it reads its location, a SHA-256 of its contents, and what Windows
says about the digital signature embedded in it: whether it is valid and, when it is, the name on the
signing certificate and a hash of that certificate. **Checking a signature does not use the internet** —
the check is told to use only what Windows already holds, and the Windows CI job proves it on every
change (ADR 0035). The name on a certificate is usually a company's; some developers sign in their own
name, and that name is then what the report shows.

It reads the same four things of `FiveM.exe` in the program folder of each FiveM edition, so that the
report can say whether FiveM's own program carries the signature FiveM was measured with (ADR 0036). To
find that one file it lists the names in the program folder; **no other file there is reported**, and
nothing is read from inside it but what the hash and the signature check consume. Since ADR 0061 it also reads
when that program folder, and Legacy's `FiveM.app` folder, were created — each folder's own time, to the
second, as the log and cache folders' times are — and `FiveM.exe`'s row carries them.

Of FiveM's **log, crash and cache folders** in both editions it reads only what listing each folder
gives: how many files and subfolders it holds, the files' total size, the earliest and latest creation and
last-write times among them, and the folder's own times (ADR 0053). Of each folder FiveM for GTA V Enhanced
keeps per server, it reads when it was created and last changed and how many entries it holds. **It reads
no file name and no folder name there**, and opens no file: a log's or a crash dump's name can carry a date,
and a server folder's name identifies the server. The times are what Windows recorded, which programs set as
they copy and extract files; they are specific enough to match two reports of the same PC (ADR 0050).
Of each of FiveM for GTA V Legacy's resource caches it also reads its **index**, the `db` folder inside it:
the folder's own creation and last-write times, how many files it holds, and the latest creation and
last-write time among them — no file name (ADR 0062). These times are on the
[timeline](#the-timeline) (ADR 0051).

**Since ADR 0036 rules read these files.** Each file in a plugin folder, and `FiveM.exe` when its
signature is not the expected one, matches a rule and is shown with its path, its hash, its signature and
the signer's name.

Of a running process it reads the name of the program and, when Windows will say, where that program
is on disk and when that process started (ADR 0062). When that place is below one of FiveM's two program
folders it also records which one — one word, `legacy` or `enhanced` — and nothing more of the path. The
start time is read only for the session statement [below](#how-far-back-the-traces-reach) and is never on
the timeline. It does not read what a program is doing, what is in its memory, or what you typed into it.

Of a driver registered with Windows it reads the name of its driver service, when Windows is set to start
it, where its file is, and a SHA-256 of that file. The list names some of your hardware and software — a
graphics card vendor, a VPN, a virtualisation product — because their drivers are registered. It does not
read which drivers are loaded or what they do.

Of the **PCI devices Windows remembers** — the cards, controllers and bridges on the board, present now or
set up earlier and gone — it reads, through Windows' device list (ADR 0069, ADR 0070): the maker, device and
subsystem numbers and the class Windows records (`PCI\VEN_…&DEV_…&SUBSYS_…&REV_…`), the driver bound to each,
its problem code when it is present, whether it is present, and three times Windows stores beside it — when
Windows first set it up, the last start of Windows at which it was present, and when Windows recorded it
removed. It never reads a serial number, a device's position on the board, a name you gave a device, or any
USB device, phone, camera or drive. The list names some of your hardware, as the driver list does. The first-
set-up times of a PC's devices are close to unique to one Windows installation, so **two reports of the same
PC can be matched through them**, as file times can (ADR 0050); this tool sends nothing, but whoever receives
two of your reports can make that match. Beside the device rows it reads how Windows
started each time its System log remembers, one number per start (see the event logs below), because a
device taken out before a full shutdown has no removal time and one taken out during a Fast Startup
shutdown has one.

Of **what Windows starts by itself** it reads three places (ADR 0060):

- **Services** that are programs rather than drivers: each one's name, how it is set to start, whether it
  starts on a trigger, and the file it runs — its `ServiceDll` when it has one.
- **`Run` and `RunOnce`** under the machine's key, the machine's 32-bit key and your Windows account's
  key: each value's name, and the file its command line starts. Other accounts' keys are not read.
- **Scheduled tasks**, from the task files Windows keeps in `%SystemRoot%\System32\Tasks`: each task's
  name and folder, whether it is on, which kinds of trigger start it (at start-up, at sign-in, on a
  schedule, on an event), and the file each of its programs is. Windows lets only administrators read
  these files, so a scan without administrator rights says it could not.

**It never reads the arguments a program is given** — not even whether there were any: a command line is
read only to find where the program's file ends, because arguments are where a token, a password or an
address is passed to a program. (The one place this program reads any command, PowerShell's, is a full
scan's, and it keeps only what kinds of words it held — [below](#a-full-scan-reads-more-and-only-if-you-agree-before-it-starts).) Of a task it also never reads who made it, its description, its working
folder or the account it runs as into the report; the account is compared with the one running this
scan, only to know whose folders a `%LOCALAPPDATA%`-style path means. Of each file **outside the Windows
folder** it reads a SHA-256 and what Windows says about its embedded signature, as for FiveM's files;
files inside the Windows folder are reported by their path alone. The list names software you
installed — launchers, chat apps, peripheral and RGB utilities — because they set themselves to start.

The name of a `Run` value and of a scheduled task is shown as Windows holds it: a task's name can carry
your account's security identifier, and a `Run` value's name is whatever the program chose.

Of **Microsoft Defender's exclusions** — the folders, programs and file types Defender is told not to
scan — it reads each one as Defender holds it, whether Defender's own settings or a policy set it, and,
for a folder or a program, whether it covers one of FiveM's folders (ADR 0060). Of the network addresses
Defender is told to skip it reads **only how many there are, never an address**, which can name your or
your employer's network. Windows lets only administrators read the exclusions, so a scan without
administrator rights says it could not.

Of the **network settings** it reads three things, and never a record of where traffic went: not which
sites or servers you connected to, not the DNS cache, not the connections open now, not the firewall log,
and nothing captured off the network (ADR 0054).

- **The hosts file.** It counts the lines in effect. Of a line that gives a name under `cfx.re`,
  `fivem.net` or `rockstargames.com` an address, it reads that name, the address and the line's number.
  **Every other line is counted and never reported**: they are your own choices about the rest of the
  internet.
- **The proxy.** Whether your Windows account has a proxy switched on, and whether a proxy server or a
  setup script is set. **Never the address of either**, which can name your employer's or your own
  server, and never the list of your VPN and dial-up connections Windows keeps beside it.
- **The Windows Firewall rules.** How many rules there are, and of each rule for a program in a FiveM
  folder, whether it allows or blocks, whether it is on, its direction, protocol and network profiles, and
  the program's path. **Never a rule's name or description**, which anyone who made the rule could write
  anything in. Rules for other programs are only counted.

No rule reads the proxy or the firewall rules; they are listed among what no rule matched.

Of **what Windows says this installation is** it reads the edition and build values `winver` shows, the
registered organisation, and the manufacturer, model and support link Settings shows — the last three are
where two published Windows-modification playbooks write their own name (ADR 0056). **It does not read
`RegisteredOwner`**, the name of the person who set the PC up. It also reads, for each of eight services
Windows ships with — Defender, Windows Update, Error Reporting, Event Log, SysMain, Diagnostic Policy,
Search and telemetry — whether its key is there and how it is set to start. No other service is read, and
no service is started, stopped or changed.

Of the **six named places** it reads one thing each: whether the place is there. Five are what the Atlas
and ReviOS Windows modifications install — folders and a registry key of theirs — and the sixth is
Microsoft's own, the folder Windows keeps Defender's engine in, read for its absence (ADR 0057).
**What is inside a folder is never listed, reported or hashed**, and no value is read from the registry
key. Nothing is opened for writing.

Of a Prefetch file it reads the program's name, how many times Windows recorded it running and when it
last ran. **A Prefetch file also lists every file that program loaded — normally hundreds of paths,
some of them inside your own folders — and the disks it touched, including a serial number that
identifies your PC. None of that is reported, in either mode.** Replacing your user name inside those
paths would not help: the list itself is a description of what is on your PC, and this check has no use
for it. The report says so, rather than leaving you to notice it is missing. The program's own entry in
that list is read for one word only: when it is below one of FiveM's two program folders, which one —
`legacy` or `enhanced` — and the entry itself is not reported (ADR 0062).

Of Windows' Background Activity Moderator it reads which programs ran and when. That record is kept
**per user account**, and the account is named by a SID — an identifier of the account *and* of the
Windows installation it belongs to. **No part of that SID is reported**, hashed or otherwise: the report
says how many accounts had records and nothing else about them. The path of a program is reported as BAM
wrote it, with `path_form` saying whether it starts with a drive letter, names a device, or neither
(B.O.P.E 0.11). When
the path is below one of FiveM's two program folders, the record also carries which one — `legacy` or
`enhanced` — whether the path is shown or withheld (ADR 0062).
Of the Windows event logs it reads **how many events of each kind each log holds** — the channel, who
wrote them, the event number, the severity and the first and last time one was written — and, of each log
itself, how far back it still reaches: the time and the record number of the oldest and the newest event
that survives in it, and how large the file was. For the folder as a whole it counts how many of the logs
it read hold no events at all and how many different channels have anything in them. None of that names a
person, and none of it is a conclusion: a log that reaches back only a few days is the ordinary result of
Windows overwriting the oldest events when the log fills, of a channel that was switched on recently, or of
a Windows upgrade, and a PC with almost every log empty is what a "PC optimiser" script leaves behind — the
report says which of these it cannot tell apart. **What each event says is not read into the report at
all**: an event's own text is where user names, PC names, addresses, account identifiers and full command
lines live, and none of it survives the step that reads the file. **One number is the exception** (ADR 0071):
of the event Windows writes to its System log each time it starts, the tool reads `BootType`, which says
whether that start followed a full shutdown or a Fast Startup one, and the time of the event. Nothing else of
that event is read, and nothing of any other event.
A log the tool could not read — because Windows refused it, because it is larger than the tool will open,
or because the tool's own time limit ran out — is **named in the report as one it could not read**, rather
than passed over in silence. A log the tool never opened at all, because that time limit was already gone
when its turn came, is named as one it did not look at — which is a different thing and is said in
different words.

Of the change journal it reads, for the Windows drive only, how many records the journal holds, when the
oldest and newest were written, whether older records have been trimmed from it, and the journal's maximum
size; and for each of the Prefetch, event log and Program Compatibility Assistant folders, FiveM's two
plugin folders and the folder PowerShell keeps its command history in (ADR 0063), how many records name that folder, how many of those created, deleted, renamed or changed
a file, and when the oldest and newest of that folder's records were written. **It reads no file name**: the journal names every file
changed on the drive, and the program's parser skips the name without keeping it. It reports no journal
identifier and no file number, because each would identify your PC across two reports.

**Four rules read the deletions and renames of FiveM's two plugin folders** (ADR 0047, amendment of
2026-09-30). When one matches, the report shows that folder's counts and the time of its first and last
record, beside the span the journal held — still no file name, because none was read. The journal does not
say which program deleted or renamed a file, and the row says so. **Two rules read the deletions and renames of PowerShell's command history folder** (ADR 0063), in the
same way: counts and times, never the file's name and **never anything the file holds** — this program does
not open it. It is the one folder the journal is counted for that no other part of this program reads.
PowerShell adds each command typed into its window to that file, so the times of the folder's changes, on
the timeline, show when someone typed into a PowerShell window within the journal's span, never what. The
counts of the Prefetch, event log and
Program Compatibility Assistant folders are read by no rule. A FiveM folder on another drive is not
counted at all: the report says it is on another drive, and no other drive's journal is read.

Of the machine's security settings it also reads two more (ADR 0038). One is what the PC's **firmware**
itself says about Secure Boot, beside what Windows says — one on/off value, nothing that names a person.
Windows only lets a program read a firmware value with a special permission that administrators hold, so
the tool switches that permission on inside its own process for that one read and switches it back; it
changes nothing on the PC and writes nothing to the firmware. Without administrator rights the tool does
not get the permission and says the check could not be answered. The other is whether a Windows
**policy** turns PowerShell's script logging on or off, or whether no such policy was set: the setting
only, never what any script contained. It is read for Windows PowerShell and for PowerShell 7, both for
the whole PC and for the **Windows account the tool is running as** — the per-user half of the same
policy, from that account's own part of the registry. That is your account unless the tool was restarted
with someone else's administrator password, in which case it is theirs. Whether PowerShell 7 is installed
is not read.

It also reads the **names** of the ACPI tables the PC's firmware gives Windows, to see whether one that
describes an IOMMU is among them (ADR 0038, amendment of 2026-10-15). Only whether such a table is there is
kept, and nothing is read from inside any table.

It also reads one Windows setting about itself: whether Windows is writing a record when a program is
launched (`EnablePrefetcher`). That is a machine setting and names no person. It is read so that "there
is no record of this program" can be told apart from "Windows is not keeping such records on this PC",
which are not the same statement about you. The value, and whether the Prefetch folder is there at all,
are shown as they were read; nothing is concluded from them.

Of each Prefetch file and each event log file it reads **one attribute: whether the file is marked
read-only**. Not when the file was made or changed, not who owns it, not its other attributes. Of each
event log whose events all belong to one channel, it asks Windows' Event Log service which file that
channel is written to and how large the service lets it grow. That is how this PC is set up, not
anything a log says, and asking changes nothing: the question is read-only. None of these names a
person, and none is a conclusion — a file can be read-only because it was restored from a backup, and a
log can be in a file Windows no longer writes because it was archived or exported.

It also reads **when Windows last started counting** — one number Windows keeps about the machine, the
time since it started — and puts it at the top of the report as a time, so that the times
on other rows can be read against it. It names no person and says nothing about who used the PC. It is
not a conclusion and not "when you turned your PC on": a "Shut down" with Fast Startup, which is how
Windows ships, and sleep and hibernation do not start the count again, so on an ordinary PC it is often
days old. It does say roughly when the PC was last restarted, which is a small fact about your day, and
two reports taken before the next restart show the same time (ADR 0039).

It also reads **when parts of this PC were set up**, and keeps each as a **date, never a time**
(ADR 0061): when this Windows installation was installed or last upgraded to a new feature version
(`InstallDate`); the earliest installation date Windows Setup kept from before its upgrades, and how many
it kept — **never the names of those records**, which carry dates to the second; the date the Windows
drive's change journal identifier gives when it is read as a time — **never the identifier itself**, which
names one journal on one PC, and only with administrator rights; when the Windows drive's root folder and
its `$Recycle.Bin` were created; and when FiveM's program folders (and Legacy's `FiveM.app`) were created on
your account. A date is what these are compared in; a time to the second would be the same in every report
of this PC. The dates still say something about this PC — when it was set up, when FiveM was installed —
and two reports of it show the same ones. The folders' times are read without listing the folder above
them, so no other account's folder name is read. Nothing here is a conclusion: each is shown with what
ordinarily resets it, and they disagreed by years on the one PC measured.

### A full scan reads more, and only if you agree before it starts

There are two scans (ADR 0052). Everything above is the **standard scan**, which every run makes. A
**full scan** also reads the sources below, and only when you agree to it **before the scan starts**, in
the program that will read them: the command-line version asks when you run `scan --full` and starts the
full scan only if you type `yes`; the desktop app's "Full scan" button starts the program again, and a
Windows dialog lists what a full scan reads before anything is read. Anything but yes is the standard
scan. No flag, shortcut or script answers for you, and a standard scan never touches these sources at
all — the report says, once, how many checks only a full scan answers.

What a full scan reads today:

- **The name of each server cache folder FiveM for GTA V Enhanced keeps**, one per server the game
  joined, with when each was created and last changed (ADR 0055). What the name is made from is not
  known. It stays the same for that server on this PC, so it can match two reports of this PC; whether
  another PC gets the same name is not known. Nothing inside those folders is read.
- **Which kinds of words your PowerShell commands held** (ADR 0064): the history of commands typed into a
  PowerShell window on the account running the scan, the scripts PowerShell itself flagged as suspicious in
  its log, and the command lines Windows PowerShell was started with, as its own log keeps them. **This is
  the one place this program reads what you typed.** Each command is read only to sort its words into a
  fixed list — downloads from the internet, runs text as a command, an encoded command, a bypassed
  execution policy, a hidden window, calls into Windows itself, a change to Microsoft Defender, a cleared
  log or history, a FiveM or GTA V process name — and then dropped. The report keeps which kinds, how many,
  how many commands ago (the history has no times) or when (the logs do), and **no text of any command**,
  with one exception: when a command downloads something, the name of the website, never the rest of the
  address. A website that is an address is kept as its kind only — loopback, private, public or
  unspecified. PowerShell itself leaves out of its history every line holding the words password, token,
  key or secret. Whether that history is the one of the account signed in at the keyboard is said as `same`
  or `other`, by comparing two account IDs that are never put in the report.

A full scan reads more, not differently: nothing here changes what the standard scan reads, and no scan
reads a browser's history, a messenger's storage, or anything that holds a password or a token.

### When the tool says it could not answer

Every check that could not be answered says **why**, in one sentence, in your language. Several of the
reasons are the ordinary state of an ordinary PC and none of them is a finding about you:

- *"this version of Windows does not keep this record"* — the record arrived in a later Windows than
  this one.
- *"the place this is kept is there and holds nothing"* — Windows keeps such records here and there are
  none right now. Windows itself deletes some of them on a schedule, and emptying others is a common
  "speed up my PC" tip.
- *"the Windows service that writes this record is switched off"* — a setting on this PC, so nothing was
  ever written to be missing.
- *"part of this was read and part of it was not"* and *"this program stopped reading before it
  finished"* — limits of this program, not of your PC, and the report says so rather than reporting
  "nothing found".

"Not measured" means the check did not get an answer. It is not a finding.

The tool does **not** take screenshots, read browser history, access files unrelated to its collectors,
or allow remote access.

## What leaves the machine

- **B.O.P.E Scanner's own code sends nothing about you, your PC or the scan.** Its one network request
  downloads the public FastFlag reference file from GitHub, as described above (ADR 0136); it lives in one
  function, and CI rejects any other network dependency or API.
- **The GUI uses Microsoft WebView2**, a Windows component. Microsoft documents that WebView2 collects
  some required diagnostic data regardless of settings and follows the Windows *Diagnostic data* setting
  for optional data; crash reports may be sent to Microsoft. aeterna-rongroi turns off SmartScreen inside
  its WebView and keeps the WebView profile in a temporary folder that is deleted on exit — or, if the
  program was stopped before it could delete it, at its next start — but it cannot switch off Windows' own
  diagnostics.
- **The CLI version does not use WebView2.** Use it if you want no WebView component involved.

## What is shown

There is one view of the report (ADR 0138): everything the scan read is shown to the person who ran it —
the evidence, what the collectors saw that no rule matched, paths as Windows wrote them, the timeline and
how far back each source reaches. Whoever you show the window or a saved report to sees the same. If a
report will be seen by someone else, read it first.

### The timeline

The view shows the times the report holds in one list, oldest first, with the span each Windows log and
the change journal could see, and the sources whose times could not be read (ADR 0051). The list never
calls anything a gap or a cleaning: an order of recorded times is not an order of events. When each running
process started is read only to place FiveM's folders beside its session (ADR 0062) and is never on the
list.

### How far back the traces reach

The view puts **how far back each source reaches** beside **when parts of this PC were set up** (ADR 0061):
for each event log, Prefetch, the Background Activity Moderator, the Program Compatibility Assistant, the
change journal and FiveM's folders, how many entries it holds and the oldest time still in it, with what
that source ordinarily keeps. A source the scan could not read is shown as **not known**, never as empty.
The FiveM statements of ADR 0061 and ADR 0062 are not evidence and not findings; they are always shown with
the ordinary things that produce the same result.

### aeterna-rongroi's own traces

The program is running while it scans, so it is in the list of running programs it reads. The report keeps
what it saw of **itself** in a separate "own traces" section instead of deleting it: it is not evidence about
your PC, and hiding it would tell you less about what the tool did, not more.

### What a collector saw that no rule matched

Some collectors read things no rule asks about — the programs you are running, drivers, PCI devices, what
Windows recorded about programs that ran, FiveM folders, change-journal counts. They are listed under
"unmatched observations", so that you can read what the tool saw and judge it yourself.

## What is stored

Nothing unless you ask. The window saves a report only when you press save, in the folder you choose, as
HTML, TXT, JSON or PDF with a `.sha256` file beside each (ADR 0116, ADR 0129). The CLI writes files only with
`--export-dir`, or when you redirect its output. The monitoring mode keeps its session in memory (desktop)
or in the file you name (`monitor --out`). The FastFlag reference copy and its update record are kept in
`%LOCALAPPDATA%\BOPE Scanner\fflag-reference`; delete the folder to remove them. If you send a report to a
server's staff, that server becomes responsible for how it keeps it. A report file is not signed: anyone who
holds it can change it, and the `.sha256` beside it only shows whether it changed since it was written by
someone who kept the hash elsewhere (ADR 0040).
