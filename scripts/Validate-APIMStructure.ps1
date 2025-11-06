<#
 .SYNOPSIS
   Validates APIM repository structure for the new “journeys” & “environments”.

 .DESCRIPTION
   - Supports journeys: external, internal, both
   - Supports environments: base, dev, pre, tst, all
   - Enforces mandatory files at the precise subpaths you provided
   - Performs light JSON/YAML/XML content checks
   - Produces GitHub Actions step summary and outputs, and non-zero exit when errors

 .EXAMPLES
   pwsh -File .\Validate-APIMStructure.ps1 -Journey external -Environment base -FailOnError
   pwsh -File .\Validate-APIMStructure.ps1 -Journey both -Environment all -FailOnError
#>

param(
    [string]$RootPath = ".",

    [ValidateSet('external','internal','both')]
    [string]$Journey = 'both',

    [ValidateSet('base','dev','pre','tst','all')]
    [string]$Environment = 'all',

    # Resource names (override if needed)
    [string]$ApiName            = 'address-lookup-v10',
    [string]$ProductName        = 'addresslookup-product',
    [string]$VersionSetName     = 'addressLookupVersionset',
    [string]$NamedValueName     = 'addresslookupv10-backend-scopeid',

    [switch]$FailOnError
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ------- Helpers -------
function Write-Info($m){ Write-Host "[INFO ] $m" -ForegroundColor Cyan }
function Write-Warn($m){ Write-Host "[WARN ] $m" -ForegroundColor Yellow }
function Write-Err ($m){ Write-Host "[ERROR] $m" -ForegroundColor Red }

# Case-insensitive file resolver
function Resolve-File {
    param([string]$Dir, [string[]]$Candidates)
    if (-not (Test-Path -LiteralPath $Dir)) { return $null }
    $entries = Get-ChildItem -LiteralPath $Dir -File -Force
    foreach ($cand in $Candidates) {
        $hit = $entries | Where-Object { $_.Name -ieq $cand } | Select-Object -First 1
        if ($hit) { return $hit.FullName }
    }
    return $null
}

# Content validators (adapted from your original)
function Validate-NestedJsonFields {
    param($filePath, $nestedFields)
    try {
        $json = Get-Content $filePath -Raw | ConvertFrom-Json
        foreach ($field in $nestedFields) {
            switch ($field) {
                # apiInformation.json
                'properties.path'                 { if (-not $json.properties.path)                 { return "Missing 'properties.path' in $filePath" } }
                'properties.apiVersion'           { if (-not $json.properties.apiVersion)           { return "Missing 'properties.apiVersion' in $filePath" } }
                'properties.apiVersionSetId'      { if (-not $json.properties.apiVersionSetId)      { return "Missing 'properties.apiVersionSetId' in $filePath" } }
                'properties.isCurrent'            { if ($null -eq $json.properties.isCurrent)       { return "Missing 'properties.isCurrent' in $filePath" } }
                'properties.displayName'          { if (-not $json.properties.displayName)          { return "Missing 'properties.displayName' in $filePath" } }
                'properties.protocols'            { if (-not $json.properties.protocols)            { return "Missing 'properties.protocols' in $filePath" } }
                'properties.serviceUrl'           { if (-not $json.properties.serviceUrl)           { return "Missing 'properties.serviceUrl' in $filePath" } }
                'properties.subscriptionRequired' { if ($null -eq $json.properties.subscriptionRequired) { return "Missing 'properties.subscriptionRequired' in $filePath" } }
                # namedValueInformation.json
                'properties.displayName'          { if (-not $json.properties.displayName)          { return "Missing 'properties.displayName' in $filePath" } }
                'properties.secret'               { if ($null -eq $json.properties.secret)          { return "Missing 'properties.secret' in $filePath" } }
                'properties.tags'                 { if ($null -eq $json.properties.tags)            { return "Missing 'properties.tags' in $filePath" } }
                'properties.value'                { if (-not $json.properties.value)                { return "Missing 'properties.value' in $filePath" } }
                # productInformation.json
                'properties.description'          { if (-not $json.properties.description)          { return "Missing 'properties.description' in $filePath" } }
                'properties.state'                { if (-not $json.properties.state)                { return "Missing 'properties.state' in $filePath" } }
                # versionSetInformation.json
                'properties.versioningScheme'     { if (-not $json.properties.versioningScheme)     { return "Missing 'properties.versioningScheme' in $filePath" } }
            }
        }
    } catch {
        return "Invalid JSON format in $filePath"
    }
    return $null
}

function Validate-PolicyXml {
    param($filePath)
    try {
        $content = Get-Content $filePath -Raw
        if ($content -notmatch '<policies>') { return 'Missing <policies> root element' }
        if ($content -notmatch '<inbound>')  { return 'Missing <inbound> section' }
        # Keep checks minimal; teams' policies vary. Add stricter checks if you need them.
    } catch {
        return 'Error reading Policy.xml'
    }
    return $null
}

function Validate-YamlOpenAPI {
    param($filePath)
    try {
        $content = Get-Content $filePath -Raw

        # Strip UTF-8 BOM if present (U+FEFF) so ^ anchors work
        if ($content.Length -gt 0 -and $content[0] -eq [char]0xFEFF) {
            $content = $content.Substring(1)
        }

        # Allow leading spaces and optional quotes around the version
        if ($content -notmatch "(?im)^\s*(openapi|swagger)\s*:\s*['""]?\d") {
            return "Missing OpenAPI/Swagger version in $filePath"
        }
        if ($content -notmatch "(?im)^\s*info\s*:")  { return "Missing 'info' section in $filePath" }
        if ($content -notmatch "(?im)^\s*paths\s*:") { return "Missing 'paths' section in $filePath" }
    } catch {
        return "Invalid YAML format in $filePath"
    }
    return $null
}

# ------- Build target sets from parameters -------
$JourneyList = if ($Journey -eq 'both') { @('external','internal') } else { @($Journey) }
$EnvList     = if ($Environment -eq 'all') { @('base','dev','pre','tst') } else { @($Environment) }

# ------- Expected items (strict to your new spec) -------
# Each entry describes a directory and the mandatory files inside it.
$Expectations = @(
    # APIs
    @{
        RelDir = { param($j,$e,$n) Join-Path -Path (Join-Path (Join-Path $j $e) "apis") $n }
        Name   = "apis/$ApiName"
        Required = @(
            @('apiInformation.json','apinformation.json'), # accept either (case-insensitive)
            @('Specification.yaml','specification.yaml','specification.yml'),
            @('Policy.xml','policy.xml')
        )
        Validators = @{
            'apiInformation.json|apinformation.json' = { param($p) Validate-NestedJsonFields $p @(
                'properties.path','properties.apiVersion','properties.apiVersionSetId',
                'properties.isCurrent','properties.displayName','properties.protocols',
                'properties.serviceUrl','properties.subscriptionRequired'
            )}
            'Specification.yaml|specification.yaml|specification.yml' = { param($p) Validate-YamlOpenAPI $p }
            'Policy.xml|policy.xml' = { param($p) Validate-PolicyXml $p }
        }
    },
    # Products (root)
    @{
        RelDir = { param($j,$e,$n) Join-Path -Path (Join-Path (Join-Path $j $e) "products") $n }
        Name   = "products/$ProductName"
        Required = @(
            @('productInformation.json')
        )
        Validators = @{
            'productInformation.json' = { param($p) Validate-NestedJsonFields $p @(
                'properties.displayName','properties.description','properties.state'
            )}
        }
    },
    # Products -> apis/<apiName>
    @{
        RelDir = { param($j,$e,$n) Join-Path -Path (Join-Path (Join-Path (Join-Path $j $e) "products") $ProductName) (Join-Path 'apis' $ApiName) }
        Name   = "products/$ProductName/apis/$ApiName"
        Required = @(
            @('productApiInformation.json')
        )
        Validators = @{}
    },
    # Version Sets
    @{
        RelDir = { param($j,$e,$n) Join-Path -Path (Join-Path (Join-Path $j $e) "version sets") $n }
        Name   = "version sets/$VersionSetName"
        Required = @(
            @('versionSetInformation.json')
        )
        Validators = @{
            'versionSetInformation.json' = { param($p) Validate-NestedJsonFields $p @(
                'properties.displayName','properties.versioningScheme'
            )}
        }
    },
    # Named Values
    @{
        RelDir = { param($j,$e,$n) Join-Path -Path (Join-Path (Join-Path $j $e) "named values") $n }
        Name   = "named values/$NamedValueName"
        Required = @(
            @('namedValueInformation.json')
        )
        Validators = @{
            'namedValueInformation.json' = { param($p) Validate-NestedJsonFields $p @(
                'properties.displayName','properties.secret','properties.tags','properties.value'
            )}
        }
    }
)

# ------- Run validation -------
$Errors       = @()
$SummaryLines = @()

foreach ($journey in $JourneyList) {
    foreach ($env in $EnvList) {
        $envPath = Join-Path $RootPath (Join-Path $journey $env)
        if (-not (Test-Path $envPath)) {
            $Errors += "Missing environment folder: $envPath"
            $SummaryLines += "$journey | $env | (folder) | ❌ Missing environment folder"
            continue
        }

        foreach ($exp in $Expectations) {
            $dir = & $exp.RelDir $journey $env $(
                if ($exp.Name -like 'apis/*')         { $ApiName }
                elseif ($exp.Name -like 'products/*')  { $ProductName }
                elseif ($exp.Name -like 'version*')    { $VersionSetName }
                else                                   { $NamedValueName }
            )

            if (-not (Test-Path $dir)) {
                $Errors += "Missing folder: $dir"
                $SummaryLines += "$journey | $env | $($exp.Name) | ❌ Missing folder"
                continue
            }

            # Required files
            foreach ($group in $exp.Required) {
                $resolved = Resolve-File -Dir $dir -Candidates $group
                if (-not $resolved) {
                    $Errors += "Missing file in '$dir': one of [$(($group -join ', '))]"
                    $SummaryLines += "$journey | $env | $($exp.Name) | ❌ Missing $(($group -join ' | '))"
                } else {
                    $leaf = (Split-Path $resolved -Leaf)
                    $SummaryLines += "$journey | $env | $($exp.Name) | ✅ $leaf"
                    # Optional content validation
                    foreach ($key in $exp.Validators.Keys) {
                        $alts = $key -split '\|'
                        if ($alts -contains $leaf) {
                            $r = & $exp.Validators[$key] $resolved
                            if ($r) {
                                $Errors += $r
                                $SummaryLines += "$journey | $env | $($exp.Name) | ❌ $r"
                            }
                        }
                    }
                }
            }
        }
    }
}

# ------- Output summary (GitHub Actions friendly) -------
$EOL = "`r`n"

$header = @"
## 🔎 APIM Validation Summary

Journeys:     $(($JourneyList -join ', '))
Environments: $(($EnvList -join ', '))

Journey | Env | Item | Status
------ | --- | ---- | ------
"@

# Join rows with CRLF and put a CRLF between the header and the first row
$body = ($SummaryLines -join $EOL)

if ($Errors.Count -gt 0) {
    $status = "❌ Validation FAILED. $($Errors.Count) issue(s) found."
    $footer = "### Issues:$EOL" + ($Errors -join $EOL)
    $exit = 1
} else {
    $status = "✅ Validation PASSED. All checks successful."
    $footer = ""
    $exit = 0
}

# Ensure clear line breaks:
$full = $header + $EOL + $body + $EOL + $EOL + $status + $EOL + $footer + $EOL

if ($env:GITHUB_STEP_SUMMARY) {
    # UTF-8 without BOM
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($env:GITHUB_STEP_SUMMARY, $full, $utf8NoBom)
} else {
    Write-Host "`n--- Summary (Local Preview) ---`n$full"
}

if ($env:GITHUB_OUTPUT) {
    "result=$status"  | Out-File -FilePath $env:GITHUB_OUTPUT -Encoding utf8 -Append
    "exit_code=$exit" | Out-File -FilePath $env:GITHUB_OUTPUT -Encoding utf8 -Append
}
if ($FailOnError -and $exit -ne 0) { exit $exit }