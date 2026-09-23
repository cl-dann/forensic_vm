#Requires -Version 5.1
<#
.SYNOPSIS
    forensic_vm.ps1: build AND verify a DFIR analysis workstation on Windows.

.DESCRIPTION
    PowerShell port of forensic_vm.py. One catalog drives both the installer
    and the checker, so they can never drift apart.

      build    fetch ~40 tools via GitHub releases, winget, direct URL and pip
      verify   locate each tool, run the console ones, check their rule sets

    Works on Windows PowerShell 5.1 and PowerShell 7.x. PowerShell 7.4+ is
    recommended: .tar.gz archives are then extracted natively, on 5.1 the
    script falls back to the tar.exe shipped with Windows.

    QUICK START on a clean VM
      1. Save this file, open an ELEVATED PowerShell (winget machine installs need admin).
         Run it as a file; pasting it into the console breaks the parameters.
      2. Unblock-File .\forensic_vm.ps1
         (or run with: powershell -ExecutionPolicy Bypass -File .\forensic_vm.ps1 ...)
      3. Strongly recommended, avoids the GitHub rate limit:
             $env:GITHUB_TOKEN = "ghp_yourtokenhere"
         Create one at github.com/settings/tokens: classic, NO scopes ticked.
      4. .\forensic_vm.ps1 -List
      5. .\forensic_vm.ps1 -All -Yes -Dest C:\tools
      6. .\forensic_vm.ps1 -Verify -Dest C:\tools
      7. .\forensic_vm.ps1 -Manual
      8. C:\tools\add_to_path.ps1            (session PATH)
         C:\tools\add_to_path.ps1 -Persist   (also User PATH)

    PYTHON BLOCKED BY POLICY (winget 0x8A15010F)
    Add -PortablePython to fall back to the official python.org NuGet package,
    extracted to <Dest>\python without an installer. Only do this if you are
    allowed to: the policy was put there by your organization.

    SAFETY
    -Verify only executes tools on an explicit console allowlist, each with a
    timeout and with stdin closed. GUI applications and installers are located
    but never launched. Prompts are skipped when -Yes is set or stdin is
    redirected. Nothing blocks indefinitely.

.EXAMPLE
    .\forensic_vm.ps1 hayabusa chainsaw -Yes -Dest C:\tools
.EXAMPLE
    .\forensic_vm.ps1 -Category evtx -List
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0, ValueFromRemainingArguments = $true)]
    [string[]]$Tools,
    [string]$Dest = "$env:SystemDrive\tools",
    [switch]$All,
    [string]$Category,
    [switch]$List,
    [switch]$Yes,
    [switch]$Manual,
    [switch]$Verify,
    [int]$Timeout = 15,
    [switch]$SkipWinget,
    [switch]$PortablePython,
    [string]$Token
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'   # Invoke-WebRequest is 10x slower with the progress bar on 5.1
try {
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch { }

# ================================================================ THE CATALOG
#
# kind     : github | winget | direct | pip
# category : base triage evtx memory static dynamic browser network
#            office utility linux
# group    : win (analysis VM, default) | lin (copy onto the Linux exam target)
#
# prefer / avoid : steer automatic asset selection (github only)
# verify         : how to check the install
#     @{ exe = <wildcard>; arg = @(<args>) }   console tool, executed
#     @{ exe = <wildcard>; gui = $true }       located only, never launched
#     @{ data = '<description>' }              no executable expected
# needs          : names that must exist below the tool folder (rules, maps)

$CATALOG = [ordered]@{

    # ------------------------------------------------------------------ base
    'python' = @{ kind = 'winget'; id = 'Python.Python.3.12'; category = 'base'
        note = 'Interpreter for volatility, oletools and the other pip tools.'
        verify = @{ data = 'installed system-wide' } }
    '7zip' = @{ kind = 'winget'; id = '7zip.7zip'; category = 'base'
        note = 'Archive handling. Also used by this script for .7z assets.'
        verify = @{ data = 'installed system-wide' } }
    'dotnet9' = @{ kind = 'winget'; id = 'Microsoft.DotNet.Runtime.9'; category = 'base'
        note = '.NET 9 runtime, required by the EZ Tools net9 builds.'
        verify = @{ data = 'installed system-wide' } }
    'notepadpp' = @{ kind = 'winget'; id = 'Notepad++.Notepad++'; category = 'base'
        note = 'Text and log viewing.'
        verify = @{ data = 'installed system-wide' } }
    'git' = @{ kind = 'winget'; id = 'Git.Git'; category = 'base'
        note = 'Rule updates, tool repos.'
        verify = @{ data = 'installed system-wide' } }
    'vscode' = @{ kind = 'winget'; id = 'Microsoft.VisualStudioCode'; category = 'base'
        note = 'Large file viewing, CSV and JSON inspection.'
        verify = @{ data = 'installed system-wide' } }
    'sysinternals' = @{ kind = 'direct'; category = 'base'
        url = 'https://download.sysinternals.com/files/SysinternalsSuite.zip'
        note = 'Autoruns, Procmon, Procexp, Strings, Sigcheck. Official zip, not winget: the suite is updated in place, so the winget manifest hash can lag behind.'
        verify = @{ exe = 'procexp64.exe'; gui = $true } }
    'powershell7' = @{ kind = 'winget'; id = 'Microsoft.PowerShell'; category = 'base'
        note = 'Better console than Windows PowerShell 5.1.'
        verify = @{ data = 'installed system-wide' } }
    'jdk' = @{ kind = 'winget'; id = 'EclipseAdoptium.Temurin.21.JDK'; category = 'base'
        note = 'Ghidra needs a JDK. CHECK the Ghidra release notes for the required version, it changes between releases.'
        verify = @{ data = 'installed system-wide' } }
    'putty' = @{ kind = 'winget'; id = 'PuTTY.PuTTY'; category = 'base'
        note = 'SSH to the Linux target. Includes plink and pscp.'
        verify = @{ data = 'installed system-wide' } }
    'winscp' = @{ kind = 'winget'; id = 'WinSCP.WinSCP'; category = 'base'
        note = 'Pull files off the Linux target over SCP or SFTP.'
        verify = @{ data = 'installed system-wide' } }

    # ---------------------------------------------------------------- triage
    'velociraptor' = @{ kind = 'github'; repo = 'Velocidex/velociraptor'; category = 'triage'
        prefer = @('windows', 'amd64'); avoid = @('linux', 'darwin', 'msi', 'arm', 'collector')
        note = 'Single-exe triage and collection, Windows and Linux.'
        verify = @{ exe = 'velociraptor*.exe'; arg = @('version') } }
    'autopsy' = @{ kind = 'github'; repo = 'sleuthkit/autopsy'; category = 'triage'
        prefer = @('64bit', 'zip'); avoid = @('src', 'doc')
        note = 'GUI disk analysis. Large download.'
        verify = @{ exe = 'autopsy64.exe'; gui = $true } }
    'eztools' = @{ kind = 'direct'; category = 'triage'
        url = 'https://download.ericzimmermanstools.com/Get-ZimmermanTools.zip'
        post = 'Run next (needs internet and the .NET 9 runtime): powershell -ExecutionPolicy Bypass -File "{DIR}\Get-ZimmermanTools.ps1" -Dest "{DIR}" -NetVersion 9 ; then --sync EvtxECmd, RECmd and SQLECmd.'
        note = 'Eric Zimmerman parsers, core Windows artifact toolkit.'
        verify = @{ exe = 'EvtxECmd.exe'; arg = @() }
        needs = @('Maps') }

    # ------------------------------------------------------------------ evtx
    'hayabusa' = @{ kind = 'github'; repo = 'Yamato-Security/hayabusa'; category = 'evtx'
        prefer = @('win', 'x64'); avoid = @('live-response', 'mac', 'lin', 'all-platforms')
        note = 'EVTX timeline and detection. Full build, not live-response.'
        verify = @{ exe = 'hayabusa*.exe'; arg = @('-h') }
        needs = @('rules') }
    'chainsaw' = @{ kind = 'github'; repo = 'WithSecureOpenSource/chainsaw'; category = 'evtx'
        prefer = @('all_platforms', 'rules'); avoid = @('examples', 'darwin', 'aarch64')
        note = 'Sigma hunting over EVTX. Must be the +rules asset.'
        verify = @{ exe = 'chainsaw*windows*.exe'; arg = @('--version') }
        needs = @('sigma', 'mappings') }
    'zircolite' = @{ kind = 'github'; repo = 'wagga40/Zircolite'; category = 'evtx'
        prefer = @('windows', 'x64'); avoid = @('linux', 'darwin', 'macos', 'arm64')
        note = 'Sigma against EVTX via SQLite.'
        verify = @{ exe = 'zircolite*.exe'; arg = @('--version') }
        needs = @('rules') }
    'evtx_dump' = @{ kind = 'github'; repo = 'omerbenamram/evtx'; category = 'evtx'
        prefer = @('.exe', 'windows', 'msvc'); avoid = @('linux', 'darwin')
        note = 'Raw EVTX to XML or JSON when parsers choke.'
        verify = @{ exe = 'evtx_dump*.exe'; arg = @('--version') } }
    'sigma' = @{ kind = 'github'; repo = 'SigmaHQ/sigma'; category = 'evtx'
        prefer = @('all_rules', 'core'); avoid = @()
        note = 'Sigma rule packs.'
        verify = @{ data = 'YAML rule pack, no executable' } }

    # ---------------------------------------------------------------- memory
    'volatility' = @{ kind = 'github'; repo = 'volatilityfoundation/volatility3'; category = 'memory'
        prefer = @('win', 'zip'); avoid = @('linux', 'macos')
        note = 'Memory analysis.'
        verify = @{ exe = 'vol.exe'; arg = @('--help') } }
    'winpmem' = @{ kind = 'github'; repo = 'Velocidex/WinPmem'; category = 'memory'
        prefer = @('mini_x64', 'x64'); avoid = @('x86')
        note = 'Memory acquisition. CONSOLE tool, run it from a prompt. Loads a kernel driver when given an output path, so verify only locates it.'
        verify = @{ exe = 'winpmem*.exe'; gui = $true } }

    # -------------------------------------------------------- malware static
    'capa' = @{ kind = 'github'; repo = 'mandiant/capa'; category = 'static'
        prefer = @('windows'); avoid = @('linux', 'macos', 'rules')
        note = 'Binary capabilities mapped to ATT&CK.'
        verify = @{ exe = 'capa.exe'; arg = @('--version') } }
    'floss' = @{ kind = 'github'; repo = 'mandiant/flare-floss'; category = 'static'
        prefer = @('windows'); avoid = @('linux', 'macos')
        note = 'Deobfuscated strings.'
        verify = @{ exe = 'floss.exe'; arg = @('--version') } }
    'die' = @{ kind = 'github'; repo = 'horsicq/DIE-engine'; category = 'static'
        prefer = @('win64', 'portable'); avoid = @('lin', 'mac', 'arm', 'win32', 'winxp', 'ubuntu', 'sourcecode')
        note = 'Packer and compiler identification.'
        verify = @{ exe = 'diec.exe'; arg = @('--version') } }
    'pebear' = @{ kind = 'github'; repo = 'hasherezade/pe-bear'; category = 'static'
        prefer = @('qt6', 'x64', 'win'); avoid = @('win32', 'x86_win', 'linux', 'macos', 'appimage')
        note = 'PE structure viewer.'
        verify = @{ exe = 'PE-bear.exe'; gui = $true } }
    'ghidra' = @{ kind = 'github'; repo = 'NationalSecurityAgency/ghidra'; category = 'static'
        prefer = @('PUBLIC', 'zip'); avoid = @('src')
        note = 'Disassembler and decompiler. Needs a matching JDK.'
        verify = @{ exe = 'ghidraRun.bat'; gui = $true } }
    'hxd' = @{ kind = 'direct'; category = 'static'
        url = 'https://mh-nexus.de/downloads/HxDSetup.zip'
        note = 'Hex editor. Downloads an INSTALLER, run it once by hand.'
        verify = @{ exe = 'HxD*.exe'; gui = $true } }

    # ------------------------------------------------------- malware dynamic
    'x64dbg' = @{ kind = 'github'; repo = 'x64dbg/x64dbg'; category = 'dynamic'
        prefer = @('snapshot'); avoid = @('symbols', 'pluginsdk')
        note = 'User-mode debugger.'
        verify = @{ exe = 'x64dbg.exe'; gui = $true } }
    'dnspy' = @{ kind = 'github'; repo = 'dnSpyEx/dnSpy'; category = 'dynamic'
        prefer = @('win64'); avoid = @('win32', 'arm')
        note = '.NET decompiler and debugger.'
        verify = @{ exe = 'dnSpy.exe'; gui = $true } }
    'systeminformer' = @{ kind = 'github'; repo = 'winsiderss/systeminformer'; category = 'dynamic'
        prefer = @('bin'); avoid = @('src', 'setup')
        note = 'Live process inspection (Process Hacker successor).'
        verify = @{ exe = 'SystemInformer.exe'; gui = $true } }

    # --------------------------------------------------------------- browser
    'hindsight' = @{ kind = 'github'; repo = 'RyanDFIR/hindsight'; category = 'browser'
        prefer = @('exe', 'win'); avoid = @('linux', 'mac', 'gui')
        note = 'Chrome and Edge artifact parsing (CLI build).'
        verify = @{ exe = 'hindsight*.exe'; arg = @('--version') } }
    'sqlitebrowser' = @{ kind = 'winget'; id = 'DBBrowserForSQLite.DBBrowserForSQLite'; category = 'browser'
        note = 'Chrome and Firefox SQLite artifacts.'
        verify = @{ data = 'installed system-wide' } }
    'browsinghistoryview' = @{ kind = 'direct'; category = 'browser'
        url = 'https://www.nirsoft.net/utils/browsinghistoryview.zip'
        note = 'Multi-browser history. NirSoft may block scripted downloads, fetch by hand if it fails.'
        verify = @{ exe = 'BrowsingHistoryView.exe'; gui = $true } }
    'esedatabaseview' = @{ kind = 'direct'; category = 'browser'
        url = 'https://www.nirsoft.net/utils/esedatabaseview.zip'
        note = 'Edge WebCacheV01.dat is an ESE database.'
        verify = @{ exe = 'ESEDatabaseView.exe'; gui = $true } }

    # --------------------------------------------------------------- network
    'wireshark' = @{ kind = 'winget'; id = 'WiresharkFoundation.Wireshark'; category = 'network'
        note = 'PCAP analysis. Includes tshark for CLI work.'
        verify = @{ data = 'installed system-wide' } }

    # ---------------------------------------------------------------- office
    'oletools' = @{ kind = 'pip'; id = 'oletools'; category = 'office'
        note = 'olevba, oleid, rtfobj: macro and OLE analysis.'
        verify = @{ data = 'python package' } }
    'msoffcrypto' = @{ kind = 'pip'; id = 'msoffcrypto-tool'; category = 'office'
        note = 'Encrypted Office documents.'
        verify = @{ data = 'python package' } }
    'pdfminer' = @{ kind = 'pip'; id = 'pdfminer.six'; category = 'office'
        note = 'PDF text extraction.'
        verify = @{ data = 'python package' } }

    # --------------------------------------------------------------- utility
    'ripgrep' = @{ kind = 'github'; repo = 'BurntSushi/ripgrep'; category = 'utility'
        prefer = @('x86_64', 'windows', 'msvc'); avoid = @('linux', 'darwin', 'gnu')
        note = 'Fast recursive search.'
        verify = @{ exe = 'rg.exe'; arg = @('--version') } }
    'jq' = @{ kind = 'github'; repo = 'jqlang/jq'; category = 'utility'
        prefer = @('windows', 'amd64'); avoid = @('linux', 'macos', 'osx')
        note = 'JSON slicing.'
        verify = @{ exe = 'jq*.exe'; arg = @('--version') } }
    'cyberchef' = @{ kind = 'github'; repo = 'gchq/CyberChef'; category = 'utility'
        prefer = @('zip'); avoid = @()
        note = 'Offline encoding and decoding.'
        verify = @{ data = 'open CyberChef*.html in a browser' } }

    # --------------------------------------- copy onto the LINUX exam target
    'uac' = @{ kind = 'github'; repo = 'tclahr/uac'; category = 'linux'; group = 'lin'
        prefer = @('tar.gz'); avoid = @()
        note = 'Unix-like Artifact Collector, the KAPE of Linux.'
        verify = @{ data = 'shell script, runs on the LINUX target' } }
    'linpeas' = @{ kind = 'github'; repo = 'peass-ng/PEASS-ng'; category = 'linux'; group = 'lin'
        prefer = @('linpeas.sh'); avoid = @('winPEAS', 'fat', 'linpeas_')
        note = 'Linux enumeration for the privesc modules.'
        verify = @{ data = 'shell script, runs on the LINUX target' } }
}

# ========================================================== NOT AUTOMATABLE

$MANUAL_ITEMS = @(
    @('Arsenal Image Mounter', 'arsenalrecon.com/downloads', 'The GitHub repo publishes no releases; the free edition is downloaded from the vendor site.'),
    @('KAPE', 'kroll.com/kape', 'Free but requires email registration and a licence click-through.'),
    @('FTK Imager', 'exterro.com', 'Registration wall. Useful as a second mounting path.'),
    @('PEstudio', 'winitor.com', 'No stable URL; version-specific download page.'),
    @('RegRipper', 'github.com/keydet89/RegRipper3.0', 'Source only, needs a Perl runtime. No release binaries.'),
    @('YARA (Windows)', 'github.com/VirusTotal/yara', 'Releases are source tarballs only. Build it, or use a third-party build.'),
    @('ExifTool', 'exiftool.org', 'Windows package is a versioned zip with no stable latest URL.'),
    @('Didier Stevens tools', 'blog.didierstevens.com', 'pdf-parser, oledump, zipdump: individual scripts, no releases.'),
    @('Thor Lite / Loki', 'nextron-systems.com', 'Registration required for Thor Lite. Loki is pip or source.'),
    @('NetworkMiner', 'netresec.com', 'Registration wall on the free edition.'),
    @('REMnux / SIFT', 'remnux.org / sans.org', 'Full VM appliances, not packages.')
)

$UA = 'forensic-vm-builder'
$ARCHIVES = @('.zip', '.tar.gz', '.tgz', '.7z')
$JUNK = @('darwin', 'apple', 'aarch64', 'arm64', 'armv7', '.deb', '.rpm',
          '.sha256', '.asc', '.sig', 'sha256sums', 'checksums')

# winget: "already there" results (winget-cli doc/.../returnCodes.md)
#   0x8A15002B UPDATE_NOT_APPLICABLE, 0x8A150061 PACKAGE_ALREADY_INSTALLED,
#   0x8A15010D INSTALL_ALREADY_INSTALLED
$WINGET_PRESENT = @('0x8A15002B', '0x8A150061', '0x8A15010D')
$WINGET_NOT_FOUND = '0x8A150014'   # NO_APPLICATIONS_FOUND
$WINGET_POLICY = '0x8A15010F'      # INSTALL_BLOCKED_BY_POLICY
$WINGET_CERT_PIN = '0x8A15005E'    # PINNED_CERTIFICATE_MISMATCH (msstore source behind SSL inspection)
# every catalog id lives in the community "winget" source; pinning the source
# keeps winget away from msstore, whose certificate pinning breaks behind
# TLS inspection proxies
$WINGET_SOURCE = @('--source', 'winget')

$script:RateLimitReset = 0
$script:RateLimited = $false
$script:PythonExe = $null

# ================================================================== helpers

function Write-Log {
    param([string]$Msg = '', [int]$Indent = 0)
    Write-Host ((' ' * $Indent) + $Msg)
}

function Get-Hex([int]$Code) { '0x{0:X8}' -f $Code }

function Test-NonEmpty([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return $false }
    return (@(Get-ChildItem -LiteralPath $Path -Force | Select-Object -First 1).Count -gt 0)
}

function Test-CanPrompt {
    try { return ((-not [Console]::IsInputRedirected) -and [Environment]::UserInteractive) }
    catch { return $false }
}

function Get-FirstLine([string]$Text) {
    if (-not $Text) { return '' }
    $l = $Text -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Select-Object -First 1
    if (-not $l) { return '' }
    if ($l.Length -gt 60) { $l = $l.Substring(0, 60) }
    return $l
}

function Join-ProcArgs([string[]]$ArgList) {
    if (-not $ArgList) { return '' }
    $out = foreach ($a in $ArgList) {
        if ($a -eq '') { '""' }
        elseif ($a -match '[\s"]') { '"' + (($a -replace '(\\*)"', '$1$1\"') -replace '(\\+)$', '$1$1') + '"' }
        else { $a }
    }
    return ($out -join ' ')
}

# Run a process with captured output, closed stdin and a hard timeout.
function Invoke-Proc {
    param([string]$File, [string[]]$ArgList = @(), [int]$TimeoutSec = 60)
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $File
    $psi.Arguments = Join-ProcArgs $ArgList
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.RedirectStandardInput = $true
    $psi.CreateNoWindow = $true
    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $psi
    try { [void]$p.Start() }
    catch { return [pscustomobject]@{ Status = 'FAIL'; Code = $null; Output = $_.Exception.Message } }
    try { $p.StandardInput.Close() } catch { }
    $o = $p.StandardOutput.ReadToEndAsync()
    $e = $p.StandardError.ReadToEndAsync()
    if (-not $p.WaitForExit($TimeoutSec * 1000)) {
        try { $p.Kill($true) } catch { try { $p.Kill() } catch { } }
        return [pscustomobject]@{ Status = 'TIMEOUT'; Code = $null; Output = "killed after ${TimeoutSec}s" }
    }
    $p.WaitForExit()
    return [pscustomobject]@{ Status = 'DONE'; Code = $p.ExitCode; Output = ($o.Result + "`n" + $e.Result) }
}

# Run a process with its output visible in the console (winget, pip).
function Invoke-Visible([string]$Exe, [string[]]$ArgList) {
    $p = Start-Process -FilePath $Exe -ArgumentList (Join-ProcArgs $ArgList) -NoNewWindow -PassThru
    $null = $p.Handle          # without this, ExitCode can come back empty on 5.1
    $p.WaitForExit()
    return $p.ExitCode
}

function Update-SessionPath {
    $m = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $u = [Environment]::GetEnvironmentVariable('Path', 'User')
    $env:Path = (@($m, $u) | Where-Object { $_ }) -join ';'
}

function Get-WingetExe {
    $c = Get-Command winget -ErrorAction SilentlyContinue
    if ($c) { return $c.Path }
    return $null
}

function Find-7Zip {
    $c = Get-Command 7z -ErrorAction SilentlyContinue
    if ($c) { return $c.Path }
    foreach ($p in @("$env:ProgramFiles\7-Zip\7z.exe", "${env:ProgramFiles(x86)}\7-Zip\7z.exe")) {
        if ($p -and (Test-Path -LiteralPath $p)) { return $p }
    }
    return $null
}

# A real interpreter, not the Microsoft Store alias stub in WindowsApps.
function Get-PythonExe {
    if ($script:PythonExe) { return $script:PythonExe }
    $portable = Get-PortablePythonExe
    if (Test-Path -LiteralPath $portable) { $script:PythonExe = $portable; return $portable }
    $cands = New-Object System.Collections.ArrayList
    $py = Get-Command py -ErrorAction SilentlyContinue
    if ($py) { [void]$cands.Add([pscustomobject]@{ Exe = $py.Path; Pre = @('-3') }) }
    foreach ($c in @(Get-Command python -All -ErrorAction SilentlyContinue)) {
        if ($c.Path -and $c.Path -notlike '*\WindowsApps\*') {
            [void]$cands.Add([pscustomobject]@{ Exe = $c.Path; Pre = @() })
        }
    }
    foreach ($c in $cands) {
        $r = Invoke-Proc $c.Exe (@($c.Pre) + @('-c', 'import sys; print(sys.executable)')) 30
        if ($r.Status -eq 'DONE' -and $r.Code -eq 0) {
            $exe = Get-FirstLine $r.Output
            if ($exe -and (Test-Path -LiteralPath $exe)) { $script:PythonExe = $exe; return $exe }
        }
    }
    return $null
}

# Header lookup that works for 5.1 (WebHeaderCollection, Dictionary) and 7.x (HttpHeaders).
function Get-Hdr($Headers, [string]$Name) {
    if ($null -eq $Headers) { return $null }
    if ($Headers -is [System.Net.WebHeaderCollection]) { return $Headers[$Name] }
    if ($Headers.PSObject.Methods['TryGetValues']) {
        $vals = $null
        if ($Headers.TryGetValues($Name, [ref]$vals)) { return [string](@($vals)[0]) }
        return $null
    }
    foreach ($k in $Headers.Keys) {
        if ($k -ieq $Name) { return [string](@($Headers[$k])[0]) }
    }
    return $null
}

# ============================================================== GitHub API

function Invoke-GitHubApi([string]$Url, [string]$CacheDir) {
    New-Item -ItemType Directory -Force -Path $CacheDir | Out-Null
    $leaf = ($Url -replace '^https://api\.github\.com/repos/', '') -replace '[/?&=]', '_'
    $key = Join-Path $CacheDir ($leaf + '.json')
    if (Test-Path -LiteralPath $key) {
        $age = ((Get-Date) - (Get-Item -LiteralPath $key).LastWriteTime).TotalHours
        if ($age -lt 24) {
            Write-Log ('(cached, {0:N1}h old)' -f $age) 8
            return (Get-Content -LiteralPath $key -Raw | ConvertFrom-Json)
        }
    }

    # after a rate limit only the cache is used, no further network calls
    if ($script:RateLimited) { throw 'RATELIMIT' }

    $headers = @{ 'Accept' = 'application/vnd.github+json' }
    if ($env:GITHUB_TOKEN) { $headers['Authorization'] = "Bearer $($env:GITHUB_TOKEN)" }
    try {
        $r = Invoke-WebRequest -Uri $Url -Headers $headers -UserAgent $UA -UseBasicParsing -TimeoutSec 30
    }
    catch {
        $resp = $null
        if ($_.Exception.PSObject.Properties['Response']) { $resp = $_.Exception.Response }
        if ($null -eq $resp) { throw }
        $code = [int]$resp.StatusCode
        $remaining = Get-Hdr $resp.Headers 'x-ratelimit-remaining'
        if ($code -eq 429 -or ($code -eq 403 -and $remaining -eq '0')) {
            $reset = Get-Hdr $resp.Headers 'x-ratelimit-reset'
            if ($reset) { $script:RateLimitReset = [long]$reset } else { $script:RateLimitReset = 0 }
            $script:RateLimited = $true
            throw 'RATELIMIT'
        }
        if ($code -eq 404) { throw 'NOTFOUND' }
        throw "GitHub API HTTP $code"
    }
    $left = Get-Hdr $r.Headers 'x-ratelimit-remaining'
    if ($left -and [int]$left -lt 10) { Write-Log "[!] only $left API calls left this hour" 8 }
    Set-Content -LiteralPath $key -Value $r.Content -Encoding UTF8
    return ($r.Content | ConvertFrom-Json)
}

function Get-Release($Spec, [string]$CacheDir) {
    $base = "https://api.github.com/repos/$($Spec.repo)/releases"
    try { return (Invoke-GitHubApi "$base/latest" $CacheDir) }
    catch {
        if ($_.Exception.Message -ne 'NOTFOUND') { throw }
    }
    Write-Log 'no "latest" release, checking the release list' 8
    $releases = @()
    try { $releases = @(Invoke-GitHubApi "$base`?per_page=10" $CacheDir | ForEach-Object { $_ }) }
    catch {
        if ($_.Exception.Message -eq 'NOTFOUND') { throw 'repo not found on GitHub' }
        throw
    }
    $rel = $releases | Where-Object { -not $_.draft } | Select-Object -First 1
    if (-not $rel) { throw 'repo has no releases on GitHub, download it by hand' }
    if ($rel.prerelease) { Write-Log "[!] only a PRE-RELEASE is available: $($rel.tag_name)" 8 }
    return $rel
}

function Get-Score([string]$Name, $Prefer, $Avoid) {
    $n = $Name.ToLower()
    $s = 0
    $i = 0
    foreach ($kw in @($Prefer)) {
        if ($kw -and $n.Contains($kw.ToLower())) { $s += 10 - $i }
        $i++
    }
    foreach ($kw in @($Avoid)) {
        if ($kw -and $n.Contains($kw.ToLower())) { $s -= 25 }
    }
    foreach ($b in $JUNK) { if ($n.Contains($b)) { $s -= 30 } }
    foreach ($ext in ($ARCHIVES + @('.exe', '.sh'))) {
        if ($n.EndsWith($ext)) { $s += 2; break }
    }
    return $s
}

function Get-RankedAssets($Assets, $Spec) {
    $i = 0
    $rows = foreach ($a in @($Assets)) {
        [pscustomobject]@{ Asset = $a; Score = (Get-Score $a.name $Spec.prefer $Spec.avoid); Idx = $i }
        $i++
    }
    return @($rows | Sort-Object -Property @{ Expression = 'Score'; Descending = $true },
                                          @{ Expression = 'Idx'; Descending = $false })
}

# Never blocks. Falls back to the best guess whenever it cannot ask.
function Select-Asset($Assets, $Spec, [bool]$AssumeYes) {
    $ranked = @(Get-RankedAssets $Assets $Spec)
    if ($ranked.Count -eq 0) { return $null }
    $best = $ranked[0]
    $runner = -99
    if ($ranked.Count -gt 1) { $runner = $ranked[1].Score }
    $ties = @($ranked | Where-Object { $_.Score -eq $best.Score })

    if ($AssumeYes -or -not (Test-CanPrompt)) {
        if ($best.Score -le 0) { Write-Log "[!] no confident match; best guess: $($best.Asset.name)" 8 }
        if ($ties.Count -gt 1) {
            Write-Log ("[!] tie at score {0}: {1}; taking {2}" -f $best.Score,
                (($ties | ForEach-Object { $_.Asset.name }) -join ', '), $best.Asset.name) 8
        }
        return $best.Asset
    }
    if ($best.Score -gt 0 -and ($best.Score - $runner) -ge 5) { return $best.Asset }

    Write-Log 'ambiguous, choose:' 8
    $n = [Math]::Min(10, $ranked.Count)
    for ($k = 0; $k -lt $n; $k++) {
        $mark = ' '
        if ($k -eq 0) { $mark = '*' }
        Write-Log ("{0}{1}: {2} ({3} KB)" -f $mark, $k, $ranked[$k].Asset.name, [int]($ranked[$k].Asset.size / 1KB)) 10
    }
    $raw = (Read-Host '        number (Enter = starred, s = skip)').Trim().ToLower()
    if ($raw -eq 's') { return $null }
    $idx = 0
    if ([int]::TryParse($raw, [ref]$idx) -and $idx -ge 0 -and $idx -lt $ranked.Count) { return $ranked[$idx].Asset }
    return $best.Asset
}

# ======================================================= download / extract

function Save-Url([string]$Url, [string]$Target) {
    $part = "$Target.part"
    $sw = [Diagnostics.Stopwatch]::StartNew()
    try {
        Invoke-WebRequest -Uri $Url -OutFile $part -UserAgent $UA -UseBasicParsing
    }
    catch {
        Remove-Item -LiteralPath $part -Force -ErrorAction SilentlyContinue
        throw
    }
    Move-Item -LiteralPath $part -Destination $Target -Force
    try { Unblock-File -LiteralPath $Target -ErrorAction Stop } catch { }   # drop mark-of-the-web
    $kb = [Math]::Round((Get-Item -LiteralPath $Target).Length / 1KB)
    Write-Log ('{0:N0} KB in {1:N0}s' -f $kb, $sw.Elapsed.TotalSeconds) 8
}

function Expand-TarGz([string]$Archive, [string]$OutDir) {
    try { Add-Type -AssemblyName System.Formats.Tar -ErrorAction Stop } catch { }
    $tarType = 'System.Formats.Tar.TarFile' -as [type]
    if ($tarType) {
        $fs = [IO.File]::OpenRead($Archive)
        try {
            $gz = New-Object System.IO.Compression.GZipStream($fs, [IO.Compression.CompressionMode]::Decompress)
            $tarType::ExtractToDirectory($gz, $OutDir, $false)
        }
        finally { $fs.Dispose() }
        return
    }
    $tar = $null
    if ($env:SystemRoot) { $tar = Join-Path $env:SystemRoot 'System32\tar.exe' }
    if (-not $tar -or -not (Test-Path -LiteralPath $tar)) {
        throw 'no tar support: needs PowerShell 7.4+ or the Windows tar.exe'
    }
    $r = Invoke-Proc $tar @('-xzf', $Archive, '-C', $OutDir) 900
    if ($r.Status -ne 'DONE' -or $r.Code -ne 0) { throw "tar.exe failed: $(Get-FirstLine $r.Output)" }
}

function Expand-Download([string]$Archive, [string]$OutDir) {
    $n = $Archive.ToLower()
    try {
        if ($n.EndsWith('.zip')) {
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            [System.IO.Compression.ZipFile]::ExtractToDirectory($Archive, $OutDir)
        }
        elseif ($n.EndsWith('.tar.gz') -or $n.EndsWith('.tgz')) {
            Expand-TarGz $Archive $OutDir
        }
        elseif ($n.EndsWith('.7z')) {
            $7z = Find-7Zip
            if (-not $7z) { Write-Log '[!] .7z asset but 7-Zip not found, left on disk' 8; return $false }
            $r = Invoke-Proc $7z @('x', '-y', "-o$OutDir", $Archive) 900
            if ($r.Status -ne 'DONE' -or $r.Code -ne 0) { throw "7-Zip failed: $(Get-FirstLine $r.Output)" }
        }
        else { return $false }
        Remove-Item -LiteralPath $Archive -Force
        return $true
    }
    catch {
        Write-Log "[!] extraction failed: $($_.Exception.Message). Archive left on disk." 8
        return $false
    }
}

function Invoke-Flatten([string]$OutDir) {
    $kids = @(Get-ChildItem -LiteralPath $OutDir -Force)
    if ($kids.Count -eq 1 -and $kids[0].PSIsContainer) {
        $tmpName = '_flatten_' + [guid]::NewGuid().ToString('N')
        $tmp = Join-Path $OutDir $tmpName
        Rename-Item -LiteralPath $kids[0].FullName -NewName $tmpName
        Get-ChildItem -LiteralPath $tmp -Force | Move-Item -Destination $OutDir
        Remove-Item -LiteralPath $tmp -Force -Recurse
        Write-Log 'flattened nested folder' 8
    }
}

# ================================================================ fetchers

function New-Result([string]$Status, $Version = $null) {
    return [pscustomobject]@{ Status = $Status; Version = $Version }
}

function Install-GitHubTool([string]$Name, $Spec) {
    $outdir = Join-Path $DestPath $Name
    if (-not $List -and (Test-NonEmpty $outdir)) {
        Write-Log 'already present, skipping' 8
        return (New-Result 'present' (Get-PrevVersion $Name))
    }

    $rel = Get-Release $Spec (Join-Path $DestPath '.cache')
    $tag = $rel.tag_name
    Write-Log "release: $tag" 8
    $assets = @()
    if ($rel.PSObject.Properties['assets'] -and $rel.assets) { $assets = @($rel.assets) }

    if ($List) {
        foreach ($row in (@(Get-RankedAssets $assets $Spec) | Select-Object -First 8)) {
            Write-Log ('{0,4}  {1}  ({2} KB)' -f $row.Score, $row.Asset.name, [int]($row.Asset.size / 1KB)) 10
        }
        return (New-Result 'listed' $tag)
    }
    if ($assets.Count -eq 0) {
        Write-Log '[!] release has no downloadable assets' 8
        return (New-Result 'no assets' $tag)
    }

    $asset = Select-Asset $assets $Spec ([bool]$Yes)
    if (-not $asset) { return (New-Result 'skipped' $tag) }

    New-Item -ItemType Directory -Force -Path $outdir | Out-Null
    $archive = Join-Path $outdir $asset.name
    Write-Log "downloading $($asset.name)" 8
    try { Save-Url $asset.browser_download_url $archive }
    catch {
        # nothing was there before, so a failed download must not leave a
        # half-filled folder that the next run would report as "present"
        Remove-Item -LiteralPath $outdir -Recurse -Force -ErrorAction SilentlyContinue
        throw
    }
    if (Expand-Download $archive $outdir) { Invoke-Flatten $outdir }

    $hits = @(Get-ChildItem -LiteralPath $outdir -Recurse -File -ErrorAction SilentlyContinue |
              Where-Object { $_.Extension -in @('.exe', '.sh', '.html', '.yml', '.bat') } |
              Select-Object -First 1)
    if ($hits.Count -gt 0) { return (New-Result 'ok' $tag) }
    return (New-Result 'check manually' $tag)
}

function Install-WingetTool([string]$Name, $Spec) {
    if ($List) {
        Write-Log "would run: winget install --id $($Spec.id) -e --source winget" 8
        return (New-Result 'listed')
    }
    if ($Name -eq 'python' -and $PortablePython -and (Test-Path -LiteralPath (Get-PortablePythonExe))) {
        return (Install-PortablePython)
    }
    $wg = Get-WingetExe
    if (-not $wg) {
        Write-Log '[!] winget not found: install App Installer from the Microsoft Store' 8
        return (New-Result 'no winget')
    }
    $common = @('--silent', '--disable-interactivity',
                '--accept-package-agreements', '--accept-source-agreements')
    $code = Invoke-Visible $wg (@('install', '--id', $Spec.id, '-e') + $WINGET_SOURCE + $common)
    $hex = Get-Hex $code

    if ($hex -eq $WINGET_NOT_FOUND) {
        Write-Log 'exact id not found, retrying without -e' 8
        $code = Invoke-Visible $wg (@('install', '--id', $Spec.id) + $WINGET_SOURCE + $common)
        $hex = Get-Hex $code
    }
    if ($code -eq 0) { Update-SessionPath; return (New-Result 'ok') }
    if ($WINGET_PRESENT -contains $hex) {
        Write-Log "already installed ($hex)" 8
        return (New-Result 'present')
    }
    Write-Log "[!] winget failed (exit $hex). Look it up with: winget error $hex" 8
    if ($hex -eq $WINGET_POLICY) {
        Write-Log 'Blocked by an organization policy (AppLocker, WDAC, MSI or Intune restrictions are typical).' 8
        if ($Name -eq 'python') {
            if ($PortablePython) {
                Write-Log 'falling back to the portable python.org NuGet package' 8
                return (Install-PortablePython)
            }
            Write-Log 'Re-run with -PortablePython to use the portable python.org NuGet package instead.' 8
        }
        return (New-Result "blocked by policy ($hex)")
    }
    if ($hex -eq $WINGET_CERT_PIN) {
        Write-Log 'Certificate pinning mismatch: TLS inspection between this VM and the Microsoft Store source.' 8
        Write-Log 'See: learn.microsoft.com/windows/package-manager (BypassCertificatePinningForMicrosoftStore)' 8
    }
    Write-Log 'Candidates:' 8
    [void](Invoke-Visible $wg (@('search', '--id', $Spec.id) + $WINGET_SOURCE + @('--accept-source-agreements')))
    return (New-Result "winget failed ($hex)")
}

function Install-DirectTool([string]$Name, $Spec) {
    $outdir = Join-Path $DestPath $Name
    if ($List) {
        Write-Log "would download: $($Spec.url)" 8
        return (New-Result 'listed')
    }
    if (Test-NonEmpty $outdir) {
        Write-Log 'already present, skipping' 8
        return (New-Result 'present')
    }
    New-Item -ItemType Directory -Force -Path $outdir | Out-Null
    $target = Join-Path $outdir ($Spec.url -split '/')[-1]
    try {
        Write-Log "downloading $(Split-Path $target -Leaf)" 8
        Save-Url $Spec.url $target
    }
    catch {
        Remove-Item -LiteralPath $outdir -Recurse -Force -ErrorAction SilentlyContinue
        Write-Log "[!] failed: $($_.Exception.Message)" 8
        Write-Log "    fetch by hand: $($Spec.url)" 8
        return (New-Result 'direct failed')
    }
    if ((Get-Item -LiteralPath $target).Length -lt 2048) {
        Remove-Item -LiteralPath $outdir -Recurse -Force -ErrorAction SilentlyContinue
        Write-Log '[!] suspiciously small, probably an error page, not the file' 8
        return (New-Result 'direct failed')
    }
    if (Expand-Download $target $outdir) { Invoke-Flatten $outdir }
    if ($Spec.post) { Write-Log ('NEXT: ' + ($Spec.post -replace '\{DIR\}', $outdir)) 8 }
    return (New-Result 'ok')
}

# Official python.org build published on nuget.org; the .nupkg is a zip whose
# tools\ folder is a complete Python (docs.python.org, "The nuget.org packages").
function Get-PortablePythonExe { return (Join-Path $DestPath 'python\tools\python.exe') }

function Install-PortablePython {
    $outdir = Join-Path $DestPath 'python'
    $exe = Get-PortablePythonExe
    if (Test-Path -LiteralPath $exe) {
        Write-Log 'portable Python already present' 8
        $script:PythonExe = $exe
        return (New-Result 'present' (Get-PrevVersion 'python'))
    }
    $idx = Invoke-RestMethod -Uri 'https://api.nuget.org/v3-flatcontainer/python/index.json' -UserAgent $UA -UseBasicParsing
    $ver = @($idx.versions | Where-Object { $_ -match '^3\.12\.\d+$' } |
             Sort-Object { [version]$_ }) | Select-Object -Last 1
    if (-not $ver) { throw 'no Python 3.12.x package found on nuget.org' }
    Write-Log "nuget.org python $ver" 8
    New-Item -ItemType Directory -Force -Path $outdir | Out-Null
    $pkg = Join-Path $outdir "python.$ver.zip"
    try {
        Save-Url "https://api.nuget.org/v3-flatcontainer/python/$ver/python.$ver.nupkg" $pkg
        if (-not (Expand-Download $pkg $outdir) -or -not (Test-Path -LiteralPath $exe)) {
            throw 'package extracted, but tools\python.exe is missing'
        }
        $r = Invoke-Proc $exe @('-m', 'pip', '--version') 60
        if ($r.Status -ne 'DONE' -or $r.Code -ne 0) {
            Write-Log 'pip missing, bootstrapping with ensurepip' 8
            $r = Invoke-Proc $exe @('-m', 'ensurepip', '--upgrade') 600
            if ($r.Status -ne 'DONE' -or $r.Code -ne 0) { throw "ensurepip failed: $(Get-FirstLine $r.Output)" }
        }
    }
    catch {
        Remove-Item -LiteralPath $outdir -Recurse -Force -ErrorAction SilentlyContinue
        throw
    }
    $script:PythonExe = $exe
    return (New-Result 'ok' "portable $ver")
}

function Install-PipTool([string]$Name, $Spec) {
    if ($List) {
        Write-Log "would run: python -m pip install $($Spec.id)" 8
        return (New-Result 'listed')
    }
    $py = Get-PythonExe
    if (-not $py) {
        Write-Log '[!] no working Python found (the WindowsApps alias does not count). Install the "python" item first.' 8
        return (New-Result 'no python')
    }
    $code = Invoke-Visible $py @('-m', 'pip', 'install', '-U', '--disable-pip-version-check', $Spec.id)
    if ($code -eq 0) { return (New-Result 'ok') }
    Write-Log "[!] pip failed (exit $code). Check the output above; a build error usually means there is no wheel for this Python version." 8
    return (New-Result 'pip failed')
}

# ================================================================== verify

# Rank candidate exes: x64 first, 32-bit and ARM last, then by size.
function Get-ArchRank([string]$Path) {
    $l = $Path.ToLower()
    if ($l -match 'arm64|aarch64|[\\/_-]arm[\\/_.-]') { return 0 }
    if ($l -match 'x64|amd64|x86_64|win64|64bit') { return 2 }
    if ($l -match 'x86|i386|i686|win32|32bit|x32') { return 0 }
    return 1
}

function Find-ToolExe([string]$Folder, [string]$Pattern) {
    $hits = @(Get-ChildItem -LiteralPath $Folder -Recurse -File -Filter $Pattern -ErrorAction SilentlyContinue)
    if ($hits.Count -eq 0) { return $null }
    return ($hits | Sort-Object -Property @{ Expression = { Get-ArchRank $_.FullName }; Descending = $true },
                                          @{ Expression = { $_.Length }; Descending = $true } |
            Select-Object -First 1)
}

function Get-FileCount([string]$Folder) {
    return @(Get-ChildItem -LiteralPath $Folder -Recurse -File -ErrorAction SilentlyContinue).Count
}

function Invoke-Verify {
    if (-not (Test-Path -LiteralPath $DestPath)) {
        Write-Log "No such folder: $DestPath"
        exit 1
    }
    Write-Log "Verifying $DestPath"
    Write-Log
    $rows = New-Object System.Collections.ArrayList
    $counts = [ordered]@{}
    $wg = Get-WingetExe

    foreach ($name in $CATALOG.Keys) {
        $spec = $CATALOG[$name]
        $v = $spec.verify
        $folder = Join-Path $DestPath $name
        $exe = ''
        $status = ''
        $detail = ''

        if ($name -eq 'python' -and (Test-Path -LiteralPath (Get-PortablePythonExe))) {
            $status = 'INSTALLED'; $detail = "portable: $(Get-PortablePythonExe)"
        }
        elseif ($spec.kind -eq 'winget') {
            if (-not $wg) { $status = 'UNKNOWN'; $detail = 'winget not available' }
            else {
                $r = Invoke-Proc $wg (@('list', '--id', $spec.id, '-e') + $WINGET_SOURCE + @('--accept-source-agreements')) 120
                if ($r.Status -eq 'DONE' -and $r.Code -eq 0) { $status = 'INSTALLED'; $detail = "winget: $($spec.id)" }
                elseif ($r.Status -ne 'DONE') { $status = 'UNKNOWN'; $detail = "winget list: $($r.Output)" }
                else { $status = 'MISSING'; $detail = "winget list: not installed ($(Get-Hex $r.Code))" }
            }
        }
        elseif ($spec.kind -eq 'pip') {
            $py = Get-PythonExe
            if (-not $py) { $status = 'MISSING'; $detail = 'no working Python found' }
            else {
                $r = Invoke-Proc $py @('-m', 'pip', 'show', $spec.id) 60
                if ($r.Status -eq 'DONE' -and $r.Code -eq 0) {
                    $ver = $r.Output -split "`r?`n" | Where-Object { $_ -like 'Version:*' } | Select-Object -First 1
                    $status = 'INSTALLED'; $detail = "pip: $($spec.id) $ver".Trim()
                }
                else { $status = 'MISSING'; $detail = "pip show: $($spec.id) not installed" }
            }
        }
        elseif (-not (Test-NonEmpty $folder)) {
            $status = 'MISSING'; $detail = 'not installed'
        }
        elseif ($v.data) {
            $status = 'DATA'; $detail = "$($v.data)  ($(Get-FileCount $folder) files)"
        }
        else {
            $found = Find-ToolExe $folder $v.exe
            if (-not $found) {
                $status = 'FAIL'; $detail = "$($v.exe) not found ($(Get-FileCount $folder) files)"
            }
            else {
                $exe = $found.FullName.Substring($DestPath.Length).TrimStart('\', '/')
                if ($v.gui) { $status = 'GUI'; $detail = 'found, open once by hand' }
                else {
                    $r = Invoke-Proc $found.FullName @($v.arg) $Timeout
                    if ($r.Status -eq 'TIMEOUT') { $status = 'TIMEOUT'; $detail = $r.Output }
                    elseif ($r.Status -eq 'FAIL') { $status = 'FAIL'; $detail = (Get-FirstLine $r.Output) }
                    else {
                        $line = Get-FirstLine $r.Output
                        if ($r.Code -eq 0) {
                            $status = 'OK'
                            if ($line) { $detail = $line } else { $detail = 'ran, exit 0, no output' }
                        }
                        else { $status = 'EXIT'; $detail = "exit $($r.Code): $line" }
                    }
                }
            }
        }

        if ($spec.needs -and (Test-Path -LiteralPath $folder)) {
            $missing = @(foreach ($d in $spec.needs) {
                $hit = Get-ChildItem -LiteralPath $folder -Recurse -Filter $d -ErrorAction SilentlyContinue | Select-Object -First 1
                if (-not $hit) { $d }
            })
            if ($missing.Count -gt 0) {
                $detail += "  [MISSING: $($missing -join ', ')]"
                if ($status -eq 'OK') { $status = 'NO DATA' }
            }
        }

        if ($counts.Contains($status)) { $counts[$status]++ } else { $counts[$status] = 1 }
        [void]$rows.Add([pscustomobject]@{ Name = $name; Exe = $exe; Status = $status; Detail = $detail })
    }

    $w1 = ($rows | ForEach-Object { $_.Name.Length } | Measure-Object -Maximum).Maximum + 2
    $w2 = [Math]::Min(42, ($rows | ForEach-Object { $_.Exe.Length } | Measure-Object -Maximum).Maximum + 2)
    $w2 = [Math]::Max($w2, 5)
    Write-Log (('TOOL'.PadRight($w1)) + ('EXE'.PadRight($w2)) + ('STATUS'.PadRight(10)) + 'DETAIL')
    Write-Log ('-' * ($w1 + $w2 + 10 + 40))
    foreach ($r in $rows) {
        $e = $r.Exe
        if ($e.Length -gt ($w2 - 2)) { $e = $e.Substring(0, $w2 - 2) }
        Write-Log ($r.Name.PadRight($w1) + $e.PadRight($w2) + $r.Status.PadRight(10) + $r.Detail)
    }
    Write-Log
    Write-Log (($counts.Keys | Sort-Object | ForEach-Object { "$_ $($counts[$_])" }) -join '  ')

    $bad = @($rows | Where-Object { $_.Status -in @('FAIL', 'TIMEOUT', 'MISSING', 'NO DATA', 'EXIT', 'UNKNOWN') })
    if ($bad.Count -gt 0) {
        Write-Log
        Write-Log 'Needs attention (EXIT can be normal for a help or no-argument call, check the detail):'
        foreach ($r in $bad) { Write-Log ($r.Name.PadRight(20) + ' ' + $r.Status.PadRight(9) + ' ' + $r.Detail) 2 }
    }
    else {
        Write-Log
        Write-Log 'All installed tools verified.'
    }

    Write-Log
    Write-Log 'Not checkable automatically, do these by hand:'
    Write-Log 'EZ Tools maps: EvtxECmd output must show Map Description and Payload Data' 2
    Write-Log 'Hayabusa rules: the startup banner must report thousands of rules loaded' 2
    Write-Log 'Read-only mount: writing to a mounted image must be REFUSED' 2
}

# ============================================================ manifest, PATH

function Get-ManifestPath { return (Join-Path $DestPath 'MANIFEST.json') }

function Read-Manifest {
    $map = [ordered]@{}
    $p = Get-ManifestPath
    if (Test-Path -LiteralPath $p) {
        try {
            foreach ($m in @(Get-Content -LiteralPath $p -Raw | ConvertFrom-Json | ForEach-Object { $_ })) {
                if ($m.tool) { $map[$m.tool] = $m }
            }
        }
        catch { Write-Log "[!] existing MANIFEST.json unreadable, starting a new one" }
    }
    return $map
}

function Get-PrevVersion([string]$Name) {
    if ($script:PrevManifest.Contains($Name)) { return $script:PrevManifest[$Name].version }
    return $null
}

function Write-Helpers($RunEntries) {
    # merge with earlier runs, so a partial or resumed run keeps what is already installed
    $merged = Read-Manifest
    foreach ($m in $RunEntries) {
        $prev = $null
        if ($merged.Contains($m.tool)) { $prev = $merged[$m.tool] }
        $keepPrev = $prev -and ($prev.status -in @('ok', 'present')) -and
                    ($m.status -in @('rate limited', 'skipped', 'listed'))
        if (-not $keepPrev) { $merged[$m.tool] = $m }
    }
    $allEntries = @($merged.Values | ForEach-Object { $_ })
    Set-Content -LiteralPath (Get-ManifestPath) -Value (ConvertTo-Json -InputObject $allEntries -Depth 5) -Encoding UTF8

    # PATH entries: the folder that actually holds the exe, not the tool root
    $dirs = New-Object System.Collections.ArrayList
    foreach ($m in $allEntries) {
        if ($m.status -notin @('ok', 'present')) { continue }
        if (-not $CATALOG.Contains($m.tool)) { continue }
        $spec = $CATALOG[$m.tool]
        if ($spec.kind -notin @('github', 'direct') -or -not $spec.verify.exe) { continue }
        $folder = Join-Path $DestPath $m.tool
        if (-not (Test-Path -LiteralPath $folder)) { continue }
        $f = Find-ToolExe $folder $spec.verify.exe
        if ($f -and -not $dirs.Contains($f.DirectoryName)) { [void]$dirs.Add($f.DirectoryName) }
    }
    $pyTools = Join-Path $DestPath 'python\tools'
    if (Test-Path -LiteralPath (Join-Path $pyTools 'python.exe')) {
        foreach ($d in @($pyTools, (Join-Path $pyTools 'Scripts'))) {
            if (-not $dirs.Contains($d)) { [void]$dirs.Add($d) }
        }
    }
    $dirLines = ($dirs | ForEach-Object { "    '" + ($_ -replace "'", "''") + "'" }) -join ("," + [Environment]::NewLine)
    $body = @'
# Generated by forensic_vm.ps1. PATH for the portable tools.
#   .\add_to_path.ps1            current session only
#   .\add_to_path.ps1 -Persist   also append missing folders to the User PATH
param([switch]$Persist)

$dirs = @(
__DIRS__
)

$session = @($env:Path -split ';' | Where-Object { $_ })
foreach ($d in $dirs) { if ($session -notcontains $d) { $env:Path += ";$d" } }
Write-Host "Session PATH: $($dirs.Count) tool folder(s) available."

if ($Persist) {
    # read the User scope only; writing $env:Path back would copy the Machine PATH into it
    $user = [Environment]::GetEnvironmentVariable('Path', 'User')
    $parts = @($user -split ';' | Where-Object { $_ })
    $add = @($dirs | Where-Object { $parts -notcontains $_ })
    if ($add.Count -gt 0) {
        [Environment]::SetEnvironmentVariable('Path', (($parts + $add) -join ';'), 'User')
        Write-Host "User PATH: added $($add.Count) folder(s). New consoles pick it up."
    } else {
        Write-Host 'User PATH: already up to date.'
    }
}
'@
    $body = $body.Replace('__DIRS__', $dirLines)
    Set-Content -LiteralPath (Join-Path $DestPath 'add_to_path.ps1') -Value $body -Encoding UTF8
    Write-Log
    Write-Log "Wrote $(Get-ManifestPath) and $(Join-Path $DestPath 'add_to_path.ps1') ($($dirs.Count) PATH folders)"
    return $allEntries
}

# ==================================================================== main

if ($Token) {
    $env:GITHUB_TOKEN = $Token
    Write-Log '[!] -Token is visible in the shell history and process list; prefer $env:GITHUB_TOKEN.'
}

if ([IO.Path]::IsPathRooted($Dest)) { $DestPath = $Dest }
else { $DestPath = Join-Path (Get-Location).ProviderPath $Dest }
$DestPath = [IO.Path]::GetFullPath($DestPath).TrimEnd('\', '/')
if ($env:SystemRoot -and ($DestPath + '\').StartsWith($env:SystemRoot.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) {
    Write-Log "Refusing to use $DestPath : it is inside the Windows folder."
    Write-Log 'An elevated console starts in C:\Windows\System32, so a relative -Dest lands there. Use e.g. -Dest C:\tools'
    exit 1
}
if (-not $PSCommandPath) {
    Write-Log '[!] The script was pasted into the console, not run as a file. Save it as forensic_vm.ps1 and run .\forensic_vm.ps1 so the parameters work.'
}

if ($Manual) {
    Write-Log
    Write-Log 'NOT installed by this script, and why:'
    Write-Log
    foreach ($m in $MANUAL_ITEMS) {
        Write-Log $m[0] 2
        Write-Log $m[1] 6
        Write-Log $m[2] 6
    }
    return
}

if ($Verify) {
    Invoke-Verify
    return
}

if ($Tools) {
    $unknown = @($Tools | Where-Object { -not $CATALOG.Contains($_) })
    if ($unknown.Count -gt 0) {
        Write-Log "Unknown: $($unknown -join ', ')"
        Write-Log
        Write-Log 'Known:'
        foreach ($k in ($CATALOG.Keys | Sort-Object)) { Write-Log $k 2 }
        exit 1
    }
    $wanted = @($Tools)
}
elseif ($Category) {
    $wanted = @($CATALOG.Keys | Where-Object { $CATALOG[$_].category -eq $Category })
    if ($wanted.Count -eq 0) {
        $cats = $CATALOG.Values | ForEach-Object { $_.category } | Sort-Object -Unique
        Write-Log "No such category. Available: $($cats -join ', ')"
        exit 1
    }
}
elseif ($All) {
    $wanted = @($CATALOG.Keys)
}
else {
    $wanted = @($CATALOG.Keys | Where-Object { -not $CATALOG[$_].group -or $CATALOG[$_].group -eq 'win' })
}

if ($SkipWinget) { $wanted = @($wanted | Where-Object { $CATALOG[$_].kind -ne 'winget' }) }

New-Item -ItemType Directory -Force -Path $DestPath | Out-Null
$script:PrevManifest = Read-Manifest

Write-Log "Destination : $DestPath"
Write-Log "Selected    : $($wanted.Count) items"
if ($env:GITHUB_TOKEN) { Write-Log 'GitHub auth : token set' }
else { Write-Log 'GitHub auth : ANONYMOUS (60 requests/hour)' }
if ($Yes -or -not (Test-CanPrompt)) { Write-Log 'Prompts     : disabled (best guess will be used)' }

$needsAdmin = @($wanted | Where-Object { $CATALOG[$_].kind -eq 'winget' }).Count -gt 0
if ($needsAdmin -and -not $List) {
    $isAdmin = $false
    try {
        $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { }
    if (-not $isAdmin) { Write-Log '[!] not elevated: machine-scope winget installs may prompt for UAC or fail' }
}

$transcript = $null
if (-not $List) {
    $logDir = Join-Path $DestPath 'logs'
    New-Item -ItemType Directory -Force -Path $logDir | Out-Null
    $transcript = Join-Path $logDir ('build_{0:yyyyMMdd_HHmmss}.log' -f (Get-Date))
    try { Start-Transcript -LiteralPath $transcript | Out-Null } catch { $transcript = $null }
}

$manifest = New-Object System.Collections.ArrayList
$rateLimited = $false
$completed = $false
try {
    foreach ($name in $wanted) {
        $spec = $CATALOG[$name]
        Write-Log
        Write-Log "[$name]  ($($spec.kind), $($spec.category))"
        Write-Log $spec.note 8

        try {
            if ($spec.kind -eq 'github') { $res = Install-GitHubTool $name $spec }
            elseif ($spec.kind -eq 'winget') { $res = Install-WingetTool $name $spec }
            elseif ($spec.kind -eq 'direct') { $res = Install-DirectTool $name $spec }
            elseif ($spec.kind -eq 'pip') { $res = Install-PipTool $name $spec }
            else { $res = New-Result 'unknown kind' }
        }
        catch {
            $msg = $_.Exception.Message
            if ($msg -eq 'RATELIMIT') {
                # only uncached GitHub items stop; cached ones, winget, pip and direct keep going
                if (-not $rateLimited) { Write-Log '[!] GitHub API rate limit reached, only cached release data is used from now on' 8 }
                else { Write-Log 'skipped: GitHub rate limit, no cached release data' 8 }
                $rateLimited = $true
                $res = New-Result 'rate limited'
            }
            else {
                Write-Log "[!] $msg" 8
                $res = New-Result "failed: $msg"
            }
        }
        Write-Log "-> $($res.Status)" 8

        $source = $spec.repo
        if (-not $source) { $source = $spec.id }
        if (-not $source) { $source = $spec.url }
        [void]$manifest.Add([pscustomobject]@{
            tool = $name; kind = $spec.kind; category = $spec.category
            source = $source; version = $res.Version; status = $res.Status
        })
    }
    $completed = $true
}
finally {
    # also runs on Ctrl+C, so an interrupted build still records its progress
    if (-not $List -and $manifest.Count -gt 0) { [void](Write-Helpers $manifest) }
    if (-not $completed) { Write-Log 'interrupted: run the same command again to resume.' }
}

if ($List) { return }

$done = @($manifest | Where-Object { $_.status -in @('ok', 'present') }).Count
Write-Log
Write-Log "$done/$($wanted.Count) ready."
$problems = @($manifest | Where-Object { $_.status -notin @('ok', 'present', 'listed') })
if ($problems.Count -gt 0) {
    Write-Log
    Write-Log 'Needs attention:'
    foreach ($m in $problems) { Write-Log ($m.tool.PadRight(20) + ' ' + $m.status) 4 }
}

if ($rateLimited) {
    $when = 'within the hour'
    if ($script:RateLimitReset -gt 0) {
        $when = [DateTimeOffset]::FromUnixTimeSeconds($script:RateLimitReset).LocalDateTime.ToString('HH:mm:ss')
    }
    Write-Log
    Write-Log ('=' * 62)
    Write-Log "GitHub API rate limit reached. Resets at: $when"
    Write-Log 'winget, pip and direct items were still processed.'
    Write-Log
    Write-Log 'Fix it now instead of waiting: create a token at'
    Write-Log '  github.com/settings/tokens  (classic, NO scopes needed)'
    Write-Log 'then:'
    Write-Log '  $env:GITHUB_TOKEN = "ghp_..."'
    Write-Log '  and run the SAME command again.'
    Write-Log
    Write-Log 'Completed downloads are kept and skipped on the next run.'
    Write-Log 'Cached release data is reused for 24 hours.'
    Write-Log ('=' * 62)
}

$self = 'forensic_vm.ps1'
if ($PSCommandPath) { $self = Split-Path -Leaf $PSCommandPath }
Write-Log
Write-Log "Next: .\$self -Verify -Dest `"$DestPath`""
Write-Log "      & `"$(Join-Path $DestPath 'add_to_path.ps1')`" -Persist"
if ($transcript) {
    Write-Log "Log : $transcript (winget and pip output is shown on screen only)"
    try { Stop-Transcript | Out-Null } catch { }
}
