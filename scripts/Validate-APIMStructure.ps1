[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory, Position=0)]
    [ValidateNotNullOrEmpty()]
    [string]$RootPath,

    [string[]]$ParentFolders = @('external','internal'),

    [string[]]$Environments  = @('base','dev','test','pre'),

    [ValidateSet('Console','Json','AzurePipelines')]
    [string]$Output = 'Console',

    # Write a machine-readable JSON summary here (default: ./apim-validate-summary.json)
    [string]$LogPath,

    # Treat warnings as errors (useful in release pipelines)
    [switch]$FailOnWarning,

    # Stricter runtime (recommended in CI)
    [switch]$Strict
)

if ($Strict) { Set-StrictMode -Version Latest }  # Require good hygiene in script code
$ErrorActionPreference = 'Stop'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

# --- Required structure ---
$RequiredStructure = [ordered]@{
    'apis'         = @('apiInformation.json','Specification.yaml','Policy.xml')
    'products'     = @('productInformation.json','productApiInformation.json')
    'version sets' = @('versionSetInformation.json')
    'named values' = @('namedValueInformation.json')
}

# --- Logging helpers (Console/ADO-friendly) ---
function Start-LogGroup([string]$Name) {
    if ($Output -eq 'AzurePipelines') { Write-Host "##[group]$Name" } else { Write-Verbose "== $Name ==" }
}
function End-LogGroup() {
    if ($Output -eq 'AzurePipelines') { Write-Host "##[endgroup]" }
}
function Write-Info([string]$Message) {
    if ($Output -eq 'AzurePipelines') { Write-Host "##[section]$Message" } else { Write-Host $Message }
}
function Write-Warn2([string]$Message) {
    if ($Output -eq 'AzurePipelines') { Write-Host "##[warning]$Message" } else { Write-Warning $Message }
}
function Write-Err2([string]$Message) {
    if ($Output -eq 'AzurePipelines') { Write-Host "##[error]$Message" } else { Write-Error $Message }
}
function Fail-Task([string]$Message) {
    if ($Output -eq 'AzurePipelines') {
        Write-Host "##vso[task.logissue type=error]$Message"
        Write-Host "##vso[task.complete result=Failed]"
    }
    throw $Message
}

# --- Utilities ---
function Resolve-Json($file) {
    try { Get-Content -LiteralPath $file -Raw | ConvertFrom-Json -ErrorAction Stop }
    catch { throw "Invalid JSON format: $file :: $($_.Exception.Message)" }
}
function Test-JsonFields {
    param(
        [Parameter(Mandatory)][psobject]$Json,
        [Parameter(Mandatory)][string[]]$Paths,
        [string]$File
    )
    $errors = @()
    foreach ($p in $Paths) {
        $cursor = $Json
        $found  = $true
        foreach ($seg in $p -split '\.') {
            if ($null -eq $cursor) { $found = $false; break }
            if ($cursor.PSObject.Properties.Name -notcontains $seg) { $found = $false; break }
            $cursor = $cursor.$seg
        }
        if (-not $found -or ($null -eq $cursor -and $p -notmatch '\.tags$')) {
            $errors += "Missing '$p' in $File"
        }
    }
    return $errors
}

function Validate-PolicyXml {
    param([string]$FilePath)
    $errs = @()
    try {
        [xml]$xml = Get-Content -LiteralPath $FilePath -Raw
    } catch {
        return ,("Malformed policy XML: $FilePath :: $($_.Exception.Message)")
    }

    # Must-have sections
    if (-not $xml.policies) { $errs += "Missing <policies> root in $FilePath" }
    foreach ($sec in 'inbound','outbound','on-error') {
        if (-not ($xml.policies.$sec)) { $errs += "Missing <$sec> in $FilePath" }
        elseif (-not ($xml.policies.$sec.base)) { $errs += "Missing <base/> under <$sec> in $FilePath" }
    }

    # Optional hygiene checks -> warnings (not fatal)
    try {
        $nsMgr = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
        $jwt   = $xml.SelectSingleNode('//validate-jwt', $nsMgr)
        if ($jwt) {
            if (-not $jwt.'openid-config') { $errs += "[warn] <validate-jwt> without <openid-config> in $FilePath" }
            if (-not $jwt.audiences.audience) { $errs += "[warn] <validate-jwt> missing <audiences>/<audience> in $FilePath" }
            if (-not $jwt.issuers.issuer)     { $errs += "[warn] <validate-jwt> missing <issuers>/<issuer> in $FilePath" }
        }
        $rl = $xml.SelectSingleNode('//rate-limit | //rate-limit-by-key', $nsMgr)
        if ($rl) {
            if (-not $rl.Attributes['calls'] -or -not $rl.Attributes['renewal-period']) {
                $errs += "[warn] <rate-limit*> missing calls/renewal-period in $FilePath"
            }
        }
    } catch { $errs += "[warn] Policy heuristic checks failed in $FilePath :: $($_.Exception.Message)" }

    return $errs
}

function Validate-YamlOpenAPI {
    param([string]$FilePath)
    $errs = @()
    try {
        $raw = Get-Content -LiteralPath $FilePath -Raw
        if ($raw -notmatch '(?ms)^\s*(openapi|swagger)\s*:\s*') { $errs += "Missing OpenAPI/Swagger version in $FilePath" }
        if ($raw -notmatch '(?ms)^\s*info\s*:')                  { $errs += "Missing 'info' section in $FilePath" }
        if ($raw -notmatch '(?ms)^\s*paths\s*:')                 { $errs += "Missing 'paths' section in $FilePath" }
    } catch {
        $errs += "Unreadable YAML: $FilePath :: $($_.Exception.Message)"
    }
    return $errs
}

# Named Values set in repo (directory names under "named values")
function Get-NamedValueNames([string]$root) {
    $dirs = Get-ChildItem -Path $root -Recurse -Directory -Filter 'named values' -ErrorAction SilentlyContinue
    $names = @()
    foreach ($d in $dirs) {
        $names += (Get-ChildItem -Path $d.FullName -Directory | Select-Object -ExpandProperty Name)
    }
    $names | Sort-Object -Unique
}

# Scan policies for {{Placeholders}} and ensure the Named Value exists
function Check-PolicyPlaceholders([string]$FilePath, [string[]]$KnownNames) {
    $warns = @()
    $text = Get-Content -LiteralPath $FilePath -Raw
    $rx = [regex]'{{\s*([A-Za-z0-9_.-]+)\s*}}'
    foreach ($m in $rx.Matches($text)) {
        $name = $m.Groups[1].Value
        if ($KnownNames -notcontains $name) {
            $warns += "[warn] Unknown Named Value '{{${name}}}' in $FilePath"
        }
    }
    $warns
}

# --- Execution ---
$issues = New-Object System.Collections.Generic.List[psobject]
$knownNamedValues = Get-NamedValueNames -root $RootPath

foreach ($parent in $ParentFolders) {
    foreach ($env in $Environments) {

        Start-LogGroup "Validating: $parent -> $env"
        foreach ($folder in $RequiredStructure.Keys) {

            $folderPath = Join-Path -Path $RootPath -ChildPath (Join-Path $parent (Join-Path $env $folder))
            if (-not (Test-Path -LiteralPath $folderPath)) {
                Write-Warn2 "Missing folder: $folderPath"
                $issues.Add([pscustomobject]@{ Severity='Warning'; Path=$folderPath; Message="Missing folder: $folderPath" })
                continue
            }
            Write-Info "✓ Folder exists: $folderPath"

            # Files (case-insensitive)
            $present = Get-ChildItem -LiteralPath $folderPath -File -ErrorAction SilentlyContinue
            foreach ($file in $RequiredStructure[$folder]) {
                $match = $present | Where-Object { $_.Name -ieq $file } | Select-Object -First 1
                if (-not $match) {
                    $msg = "Missing file: $folderPath/$file"
                    Write-Warn2 $msg
                    $issues.Add([pscustomobject]@{ Severity='Warning'; Path="$folderPath/$file"; Message=$msg })
                    continue
                }

                # Content validators
                $filePath = $match.FullName
                Write-Info "✓ File exists: $filePath"

                $errs = @()
                switch -Wildcard ($file) {
                    'apiInformation.json' {
                        $json = Resolve-Json $filePath
                        $errs += Test-JsonFields -Json $json -Paths @(
                            'properties.path','properties.apiVersion','properties.apiVersionSetId',
                            'properties.isCurrent','properties.displayName','properties.protocols',
                            'properties.serviceUrl','properties.subscriptionRequired'
                        ) -File $filePath
                    }
                    'Policy.xml' {
                        $errs += Validate-PolicyXml -FilePath $filePath
                        $errs += Check-PolicyPlaceholders -FilePath $filePath -KnownNames $knownNamedValues
                    }
                    'Specification.yaml' {
                        $errs += Validate-YamlOpenAPI -FilePath $filePath
                    }
                    'namedValueInformation.json' {
                        $json = Resolve-Json $filePath
                        $errs += Test-JsonFields -Json $json -Paths @(
                            'properties.displayName','properties.secret','properties.tags','properties.value'
                        ) -File $filePath
                    }
                    'productInformation.json' {
                        $json = Resolve-Json $filePath
                        $errs += Test-JsonFields -Json $json -Paths @(
                            'properties.displayName','properties.description',
                            'properties.state','properties.subscriptionRequired'
                        ) -File $filePath
                    }
                    'versionSetInformation.json' {
                        $json = Resolve-Json $filePath
                        $errs += Test-JsonFields -Json $json -Paths @(
                            'properties.displayName','properties.versioningScheme'
                        ) -File $filePath
                    }
                }

                foreach ($e in $errs) {
                    if ($e -like '[warn]*') {
                        $msg = $e -replace '^\[warn\]\s*',''
                        Write-Warn2 $msg
                        $issues.Add([pscustomobject]@{ Severity='Warning'; Path=$filePath; Message=$msg })
                    } else {
                        Write-Err2 $e
                        $issues.Add([pscustomobject]@{ Severity='Error'; Path=$filePath; Message=$e })
                    }
                }
            }
        }
        End-LogGroup
    }
}

# --- Output summary & pipeline integration ---
$summary = [ordered]@{
    Timestamp = (Get-Date).ToString('o')
    RootPath  = $RootPath
    Totals    = @{
        Errors   = ($issues | Where-Object Severity -eq 'Error').Count
        Warnings = ($issues | Where-Object Severity -eq 'Warning').Count
    }
    Issues    = $issues
}

# Write JSON summary to disk if requested
$outFile = $LogPath
if (-not $outFile) { $outFile = Join-Path -Path (Get-Location) -ChildPath 'apim-validate-summary.json' }
$summary | ConvertTo-Json -Depth 10 | Set-Content -Path $outFile -Encoding UTF8
Write-Info "Summary written to $outFile"

# Upload a nice Markdown summary to ADO, if chosen
if ($Output -eq 'AzurePipelines') {
    $md = @"
# APIM Validation Summary

* **Root**: $RootPath  
* **Errors**: $($summary.Totals.Errors)  
* **Warnings**: $($summary.Totals.Warnings)

"@
    $tmp = New-TemporaryFile
    $md | Set-Content -Path $tmp -Encoding UTF8
    Write-Host "##vso[task.uploadsummary]$tmp"
}

# Determine exit status
$errCount  = $summary.Totals.Errors
$warnCount = $summary.Totals.Warnings

if ($errCount -gt 0 -or ($FailOnWarning -and $warnCount -gt 0)) {
    Fail-Task "Validation FAILED: $errCount error(s), $warnCount warning(s)."
} else {
    Write-Info "Validation PASSED."
    exit 0
}
