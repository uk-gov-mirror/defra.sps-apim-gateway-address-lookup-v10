param(
    [string]$RootPath,
    [string[]]$ParentFolders = @("external", "internal"),
    [string[]]$Environments = @("base", "dev", "test", "pre")
)

# Convert comma-separated strings to arrays
$ParentFolders = $ParentFolders -split ','
$Environments = $Environments -split ','

# Define required folders and files
$RequiredStructure = @{
    "apis" = @("apiInformation.json", "Specification.yaml", "Policy.xml")
    "products" = @("productInformation.json", "productApiInformation.json")
    "version sets" = @("versionSetInformation.json")
    "named values" = @("namedValueInformation.json")
}
$Errors = @()
$SummaryTable = @()
# --- Validation Functions ---
function Validate-NestedJsonFields {
    param($filePath, $nestedFields)
    try {
        $json = Get-Content $filePath | ConvertFrom-Json
        foreach ($field in $nestedFields) {
            switch ($field) {
                # apiInformation.json
                "properties.path" { if (-not $json.properties.path) { return "Missing 'properties.path' in $filePath" } }
                "properties.apiVersion" { if (-not $json.properties.apiVersion) { return "Missing 'properties.apiVersion' in $filePath" } }
                "properties.apiVersionSetId" { if (-not $json.properties.apiVersionSetId) { return "Missing 'properties.apiVersionSetId' in $filePath" } }
                "properties.isCurrent" { if ($null -eq $json.properties.isCurrent) { return "Missing 'properties.isCurrent' in $filePath" } }
                "properties.displayName" { if (-not $json.properties.displayName) { return "Missing 'properties.displayName' in $filePath" } }
                "properties.protocols" { if (-not $json.properties.protocols) { return "Missing 'properties.protocols' in $filePath" } }
                "properties.serviceUrl" { if (-not $json.properties.serviceUrl) { return "Missing 'properties.serviceUrl' in $filePath" } }
                "properties.subscriptionRequired" { if ($null -eq $json.properties.subscriptionRequired) { return "Missing 'properties.subscriptionRequired' in $filePath" } }

                # namedValueInformation.json
                "properties.secret" { if ($null -eq $json.properties.secret) { return "Missing 'properties.secret' in $filePath" } }
                "properties.tags" { if ($null -eq $json.properties.tags) { return "Missing 'properties.tags' in $filePath" } }
                "properties.value" { if (-not $json.properties.value) { return "Missing 'properties.value' in $filePath" } }

                # productInformation.json
                "properties.description" { if (-not $json.properties.description) { return "Missing 'properties.description' in $filePath" } }
                "properties.state" { if (-not $json.properties.state) { return "Missing 'properties.state' in $filePath" } }
                "properties.subscriptionRequired" { if ($null -eq $json.properties.subscriptionRequired) { return "Missing 'properties.subscriptionRequired' in $filePath" } }

                # versionSetInformation.json
                "properties.versioningScheme" { if (-not $json.properties.versioningScheme) { return "Missing 'properties.versioningScheme' in $filePath" } }
            }
        }
    } catch {
        return "Invalid JSON format in $filePath"
    }
    return $null
}

# Regex-based XML validation for Policy.xml
function Validate-PolicyXml {
    param($filePath)
    try {
        $content = Get-Content $filePath -Raw

        if ($content -notmatch '<policies>') { return 'Missing <policies> root element in file' }
        if ($content -notmatch '<inbound>') { return 'Missing <inbound> section in file' }

        if ($content -notmatch '<rate-limit') { return 'Missing <rate-limit> in file' }
        if ($content -notmatch 'calls="\d+"') { return 'Missing or invalid calls attribute in <rate-limit>' }
        if ($content -notmatch 'renewal-period="\d+"') { return 'Missing or invalid renewal-period attribute in <rate-limit>' }

        if ($content -notmatch '<validate-jwt') { return 'Missing <validate-jwt> block in file' }
        if ($content -notmatch '<openid-config') { return 'Missing <openid-config> in <validate-jwt>' }
        if ($content -notmatch '<audience>') { return 'Missing <audience> in <validate-jwt>' }
        if ($content -notmatch '<issuer>') { return 'Missing <issuer> in <validate-jwt>' }
        if ($content -notmatch '<claim name="appid"') { return 'Missing <claim name="appid"> in <validate-jwt>' }
        if ($content -notmatch '<value>') { return 'Missing <value> inside <claim> in <validate-jwt>' }

    } catch {
        return 'Error reading Policy.xml'
    }
    return $null
}

function Validate-YamlOpenAPI {
    param($filePath)
    try {
        $content = Get-Content $filePath -Raw
        if ($content -notmatch "openapi|swagger") { return "Missing OpenAPI/Swagger version in $filePath" }
        if ($content -notmatch "info:") { return "Missing 'info' section in $filePath" }
        if ($content -notmatch "paths:") { return "Missing 'paths' section in $filePath" }
    } catch {
        return "Invalid YAML format in $filePath"
    }
    return $null
}

# --- Main Validation ---
foreach ($parent in $ParentFolders) {
    foreach ($env in $Environments) {
        Write-Host "`nValidating: $parent -> $env"

        foreach ($folder in $RequiredStructure.Keys) {
            $folderPath = Join-Path $RootPath "$parent/$env/$folder"

            # Always add a row for folder check
            if (-Not (Test-Path $folderPath)) {
                $Errors += "Missing folder: $folderPath"
                $SummaryTable += "| $parent | $env | $folder | ❌ Missing folder |"
                Write-Host "❌ Folder missing: $folderPath" -ForegroundColor Red
            } else {
                Write-Host "✅ Folder exists: $folderPath" -ForegroundColor Green
                $SummaryTable += "| $parent | $env | $folder | ✅ Folder exists |"

                # Check mandatory files inside folder
                foreach ($file in $RequiredStructure[$folder]) {
                    $filePath = Join-Path $folderPath $file
                    if (-Not (Test-Path $filePath)) {
                        $Errors += "Missing file: $filePath"
                        $SummaryTable += "| $parent | $env | $folder | ❌ Missing file: $file |"
                        Write-Host "❌ File missing: $filePath" -ForegroundColor Red
                    } else {
                        Write-Host "✅ File exists: $filePath" -ForegroundColor Green
                        $SummaryTable += "| $parent | $env | $folder | ✅ $file |"

                        # Content validation based on file type
                        switch -Wildcard ($file) {
                            "apiInformation.json" {
                                $result = Validate-NestedJsonFields $filePath @(
                                    "properties.path","properties.apiVersion","properties.apiVersionSetId",
                                    "properties.isCurrent","properties.displayName","properties.protocols",
                                    "properties.serviceUrl","properties.subscriptionRequired"
                                )
                                if ($result) {
                                    $Errors += $result
                                    $SummaryTable += "| $parent | $env | $folder | ❌ $result |"
                                    Write-Host "❌ $result" -ForegroundColor Red
                                }
                            }
                            "Policy.xml" {
                                $result = Validate-PolicyXml $filePath
                                if ($result) {
                                    $Errors += $result
                                    $SummaryTable += "| $parent | $env | $folder | ❌ $result |"
                                    Write-Host "❌ $result" -ForegroundColor Red
                                }
                            }
                            "Specification.yaml" {
                                $result = Validate-YamlOpenAPI $filePath
                                if ($result) {
                                    $Errors += $result
                                    $SummaryTable += "| $parent | $env | $folder | ❌ $result |"
                                    Write-Host "❌ $result" -ForegroundColor Red
                                }
                            }
                            "namedValueInformation.json" {
                                $result = Validate-NestedJsonFields $filePath @(
                                    "properties.displayName","properties.secret","properties.tags","properties.value"
                                )
                                if ($result) {
                                    $Errors += $result
                                    $SummaryTable += "| $parent | $env | $folder | ❌ $result |"
                                    Write-Host "❌ $result" -ForegroundColor Red
                                }
                            }
                            "productInformation.json" {
                                $result = Validate-NestedJsonFields $filePath @(
                                    "properties.displayName","properties.description","properties.state","properties.subscriptionRequired"
                                )
                                if ($result) {
                                    $Errors += $result
                                    $SummaryTable += "| $parent | $env | $folder | ❌ $result |"
                                    Write-Host "❌ $result" -ForegroundColor Red
                                }
                            }
                            "versionSetInformation.json" {
                                $result = Validate-NestedJsonFields $filePath @(
                                    "properties.displayName","properties.versioningScheme"
                                )
                                if ($result) {
                                    $Errors += $result
                                    $SummaryTable += "| $parent | $env | $folder | ❌ $result |"
                                    Write-Host "❌ $result" -ForegroundColor Red
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

# --- Build GitHub Actions Summary ---
$summaryHeader = @"
## 🔍 APIM Validation Summary
Checked Folders: $($ParentFolders -join ', ')
Environments: $($Environments -join ', ')

| Parent | Environment | Folder | Status |
|--------|-------------|--------|--------|

"@

$summaryBody = ($SummaryTable -join "`n")

if ($Errors.Count -gt 0) {
    $status = "❌ Validation FAILED. $($Errors.Count) issue(s) found."
    $summaryFooter = "`n### Issues:`n" + ($Errors -join "`n")
    $exitCode = 1
} else {
    $status = "✅ Validation PASSED. All checks successful."
    $summaryFooter = ""
    $exitCode = 0
}

$fullSummary = "$summaryHeader$summaryBody`n`n$status`n$summaryFooter"

# Write summary for GitHub Actions or local preview
if ($env:GITHUB_STEP_SUMMARY) {
    $fullSummary | Out-File -FilePath $env:GITHUB_STEP_SUMMARY -Encoding utf8
} else {
    Write-Host "`n--- GitHub Summary (Local Preview) ---`n$fullSummary"
}

# Outputs for workflow
if ($env:GITHUB_OUTPUT) {
    "result=$status" | Out-File -FilePath $env:GITHUB_OUTPUT -Encoding utf8 -Append
    "exit_code=$exitCode" | Out-File -FilePath $env:GITHUB_OUTPUT -Encoding utf8 -Append
} else {
    Write-Host "`nOutputs:`nresult=$status`nexit_code=$exitCode"
}

exit $exitCode
