<#
.SYNOPSIS
    Generates a structured, deduplicated, user-friendly changelog from git commit history.

.DESCRIPTION
    - Reads commits between $FromTag and HEAD (or all commits if no tag)
    - Filters noise: lazy commits, merge commits, version bumps, file-only updates
    - Groups by conventional commit type with friendly emoji headers
    - Deduplicates: exact matches + near-duplicate collapsing (same words, different casing/punctuation)
    - Scope-aware grouping: all scoped commits go under their parent category together
    - Breaking changes bubble to the top in a dedicated callout block
    - Collapses large categories gracefully with a summary instead of a wall of text
    - Outputs clean GitHub-flavored Markdown readable in ShieldDNS's update checker

.PARAMETER FromTag
    Git ref to start log from. Empty = all history (capped at 2000).

.PARAMETER TotalCommits
    Raw commit count to show in footer (passed by caller to avoid double git call).
#>
param(
    [string]$FromTag = "",
    [string]$TotalCommits = "",
    [string]$Repo = ""
)

Set-StrictMode -Version 3.0

# ---------------------------------------------------------------------------
# Noise filter — commits matching ANY pattern are silently dropped
# Order matters: cheap checks first
# ---------------------------------------------------------------------------
$noisePatterns = [System.Collections.Generic.List[string]]@(
    # Blank / whitespace-only
    '^\s*$'
    # Lazy file-only commits: "Update foo.bar", "Add config.yml", "Delete old.py" etc.
    '^(Update|Aktualisier[et]?|Add|Adds|Adde|Delete|Deletes|Remove|Removes|Rename|Renames|Move|Moves|Fix|Edit|Change|Modify)\s+[\w\-\.\/]+\.\w{1,10}\s*$'
    # Merge commits
    '^Merge (pull request|branch|remote-tracking branch)\b'
    '^Merge from\b'
    # Version bumps committed by bots
    '^(chore|build)(\([^)]*\))?:\s*(bump|release|version)\b'
    '^(bump|release)(\s+version)?\s+v?\d'
    '^v?\d+\.\d+\.\d+\s*$'
    # CI skip markers
    '^\[skip[- ]ci\]'
    '^chore: regenerate (manifest|connections|changelog)\b'
    '^chore: update (project_manifest|project_connections|contributors)\b'
    # Bot / automated commits
    '^(auto.?generated?|automated?|bot:)\b'
    '^Revert "Revert'                        # double-reverts are noise
    '^Initial commit\s*$'
    '^WIP\b'
    '^wip\b'
    # Single character or trivially short
    '^.{1,3}$'
    # Trailing [skip ci] anywhere
    '\[skip[- ]ci\]\s*$'
)

# ---------------------------------------------------------------------------
# Category order & display labels
# Breaking changes go first, always
# ---------------------------------------------------------------------------
$categoryOrder  = @('breaking','feat','fix','security','perf','refactor','api','db','ui','docs','test','ci','chore','other')
$categoryEmoji  = @{
    breaking  = '💥 Breaking Changes'
    feat      = '✨ New Features'
    fix       = '🐛 Bug Fixes'
    security  = '🔒 Security'
    perf      = '⚡ Performance'
    refactor  = '♻️ Code Improvements'
    api       = '🔌 API Changes'
    db        = '🗄️ Database'
    ui        = '🎨 UI / UX'
    docs      = '📚 Documentation'
    test      = '🧪 Tests'
    ci        = '🔄 CI / CD'
    chore     = '🔧 Maintenance'
    other     = '📦 Other Changes'
}

# Conventional commit type → bucket mapping
$typeMap = @{
    feat      = 'feat'
    feature   = 'feat'
    fix       = 'fix'
    bugfix    = 'fix'
    hotfix    = 'fix'
    security  = 'security'
    sec       = 'security'
    perf      = 'perf'
    optim     = 'perf'
    refactor  = 'refactor'
    refact    = 'refactor'
    api       = 'api'
    db        = 'db'
    migration = 'db'
    migrate   = 'db'
    schema    = 'db'
    ui        = 'ui'
    style     = 'ui'
    ux        = 'ui'
    docs      = 'docs'
    doc       = 'docs'
    test      = 'test'
    tests     = 'test'
    ci        = 'ci'
    cd        = 'ci'
    build     = 'ci'
    chore     = 'chore'
    maint     = 'chore'
    infra     = 'chore'
    deps      = 'chore'
    dep       = 'chore'
    bump      = 'chore'
    revert    = 'fix'   # reverts usually fix something
}

# Scope overrides — certain scopes always go to a specific bucket regardless of type
$scopeMap = @{
    api        = 'api'
    endpoint   = 'api'
    router     = 'api'
    route      = 'api'
    db         = 'db'
    database   = 'db'
    migration  = 'db'
    schema     = 'db'
    model      = 'db'
    ui         = 'ui'
    frontend   = 'ui'
    fe         = 'ui'
    component  = 'ui'
    modal      = 'ui'
    dashboard  = 'ui'
    security   = 'security'
    auth       = 'security'
    authz      = 'security'
    authn      = 'security'
    jwt        = 'security'
    rbac       = 'security'
    ci         = 'ci'
    cd         = 'ci'
    workflow   = 'ci'
    docker     = 'ci'
    dockerfile = 'ci'
    actions    = 'ci'
}

# Max items shown per section before collapsing to "…and N more"
$maxPerSection = 15
# Sections with these keys always show all items (even if > max)
$neverCollapse = @('breaking','security')

# ---------------------------------------------------------------------------
# Helper: normalise a message for deduplication
# ---------------------------------------------------------------------------
function Get-NormKey([string]$msg) {
    # Lower, strip leading type+scope, remove punctuation & articles
    $n = $msg.ToLower()
    $n = $n -replace '^(feat|fix|docs|style|refactor|perf|test|chore|ci|security|build|api|db|ui|ux|revert)(\([^)]*\))?(!)?:\s*',''
    $n = $n -replace '[\.\!\?\,\;\:\"''`]',''
    $n = $n -replace '\b(the|a|an|for|of|in|to|with|from|on|at|by)\b',''
    $n = $n -replace '\s+',' '
    return $n.Trim()
}

# Helper to format item display text with commit links
function Get-FormattedItem([PSCustomObject]$item, [string]$repo) {
    if ($item.hashes.Count -gt 0) {
        $links = @()
        foreach ($h in $item.hashes) {
            if ($repo) {
                $links += "[$h](https://github.com/$repo/commit/$h)"
            } else {
                $links += "``$h``"
            }
        }
        $hashStr = $links -join ", "
        return "$($item.display) ($hashStr)"
    }
    return $item.display
}

# ---------------------------------------------------------------------------
# Fetch raw commit subjects with short hashes
# ---------------------------------------------------------------------------
if ($FromTag) {
    $rawLines = git log "${FromTag}..HEAD" --pretty=format:"%h %s" 2>$null
} else {
    $rawLines = git log --pretty=format:"%h %s" --max-count=2000 2>$null
}

$commitLines = if ($rawLines) { @($rawLines) } else { @() }
$totalRaw    = if ($TotalCommits -and $TotalCommits -ne '') { [int]$TotalCommits } else { $commitLines.Count }

# ---------------------------------------------------------------------------
# Initialise buckets
# ---------------------------------------------------------------------------
$buckets = @{}
foreach ($k in $categoryOrder) {
    $buckets[$k] = [System.Collections.Generic.List[PSCustomObject]]::new()
}

# Map of normalized key -> PSCustomObject
$seenItems = @{}

# ---------------------------------------------------------------------------
# Process each commit
# ---------------------------------------------------------------------------
foreach ($line in $commitLines) {
    $hash = ""
    $msg = ""
    if ($line -match '^([0-9a-fA-F]+)\s+(.*)$') {
        $hash = $Matches[1]
        $msg = $Matches[2].Trim()
    } else {
        $msg = $line.Trim()
    }
    if (-not $msg) { continue }

    # --- Noise filter ---
    $skip = $false
    foreach ($p in $noisePatterns) {
        if ($msg -match $p) { $skip = $true; break }
    }
    if ($skip) { continue }

    # --- Parse conventional commit ---
    $bucket   = 'other'
    $display  = $msg
    $isBreak  = $false

    # Pattern: type[(scope)][!]: description
    # Also handles: type[(scope)]: description  where type is case-insensitive
    if ($msg -match '^([A-Za-z][A-Za-z0-9_-]*)(\([^)]*\))?(!)?:\s*(.+)$') {
        $rawType  = $Matches[1].ToLower()
        $rawScope = if ($Matches[2]) { ($Matches[2] -replace '[()]','').ToLower().Trim() } else { '' }
        $isBreak  = ($Matches[3] -eq '!')
        $desc     = $Matches[4].Trim()

        # Determine bucket: scope override wins over type map
        if ($rawScope -and $scopeMap.ContainsKey($rawScope)) {
            $bucket = $scopeMap[$rawScope]
        } elseif ($typeMap.ContainsKey($rawType)) {
            $bucket = $typeMap[$rawType]
        }

        # Format display text
        # Capitalise first letter of description
        $descCap = if ($desc.Length -gt 0) { $desc.Substring(0,1).ToUpper() + $desc.Substring(1) } else { $desc }

        if ($rawScope) {
            $display = "**$($rawScope):** $descCap"
        } else {
            $display = $descCap
        }
    } else {
        # Non-conventional commit — capitalise and use as-is
        $display = if ($msg.Length -gt 0) { $msg.Substring(0,1).ToUpper() + $msg.Substring(1) } else { $msg }

        # Keyword-based fallback categorization for free-form messages
        $msgLower = $msg.ToLower()
        if ($msgLower -match '\b(general\s+fix|small\s+fix|bug\s+fix|fix(es|ed)?\b|fix\s+\w|general\s+improve|improvements?\s+reported)') {
            $bucket = 'fix'
        } elseif ($msgLower -match '\b(ci\b|linter?|lint\s+fix|pipeline|workflow|github\s+action|generate[_\s]changelog|changelog\s+(categor|generat|script|fix)|test\s+crawler|docker(file)?|container)\b') {
            $bucket = 'ci'
        } elseif ($msgLower -match '\b(update\s+depend|bump\s+depend|renovate|dependency\s+update|upgrade\s+dep)') {
            $bucket = 'chore'
        } elseif ($msgLower -match '\b(add\s+missing\s+ui|improved?\s+shielddns|add(ed|s)?\s+(missing\s+)?(ui|feature|support|ability)|new\s+feature)') {
            $bucket = 'feat'
        } elseif ($msgLower -match '\b(security|vulnerability|cve|auth(en|oriz))') {
            $bucket = 'security'
        } elseif ($msgLower -match '\b(perf(ormance)?|speed|faster|slower|optim|latency|throughput)') {
            $bucket = 'perf'
        } elseif ($msgLower -match '\b(refactor(ing)?|restructur(e|ing)|rewrite|clean.?up|improve(d|s|ment|ing)?s?)\b') {
            $bucket = 'refactor'
        } elseif ($msgLower -match '\b(doc(s|ument(ation)?)?|readme|wiki|guide)\b') {
            $bucket = 'docs'
        } elseif ($msgLower -match '\b(test(s|ing)?|spec|unit\s+test|e2e)') {
            $bucket = 'test'
        } elseif ($msgLower -match '\b(changelog)') {
            $bucket = 'ci'
        } elseif ($msgLower -match '\b(ui\b|ux\b|frontend|layout|style|theme|design|modal|component|dashboard|template)') {
            $bucket = 'ui'
        } elseif ($msgLower -match '\b(api\b|endpoint|route|router|swagger|openapi)') {
            $bucket = 'api'
        } elseif ($msgLower -match '\b(db\b|database|migration|schema|model|sql)') {
            $bucket = 'db'
        } elseif ($msgLower -match '\b(chore|maint(enance)?|housekeep|dependen|package|infra)') {
            $bucket = 'chore'
        }
    }

    $normKey = Get-NormKey $display

    # Breaking changes always go into the breaking bucket (also kept in original bucket)
    if ($isBreak) {
        $breakDisplay = "**$display**"
        $breakKey = "breaking:$normKey"
        if ($seenItems.ContainsKey($breakKey)) {
            $existingBreak = $seenItems[$breakKey]
            if ($hash -and $existingBreak.hashes -notcontains $hash) {
                $existingBreak.hashes.Add($hash)
            }
        } else {
            $breakItem = [PSCustomObject]@{
                display = $breakDisplay
                hashes  = [System.Collections.Generic.List[string]]::new()
            }
            if ($hash) { $breakItem.hashes.Add($hash) }
            $seenItems[$breakKey] = $breakItem
            $buckets['breaking'].Add($breakItem)
        }
    }

    # Dedup check
    if ($seenItems.ContainsKey($normKey)) {
        $existingItem = $seenItems[$normKey]
        if ($hash -and $existingItem.hashes -notcontains $hash) {
            $existingItem.hashes.Add($hash)
        }
        continue
    }

    # First time seeing this change
    $item = [PSCustomObject]@{
        display = $display
        hashes  = [System.Collections.Generic.List[string]]::new()
    }
    if ($hash) { $item.hashes.Add($hash) }
    $seenItems[$normKey] = $item

    # Add to bucket
    $buckets[$bucket].Add($item)
}

# ---------------------------------------------------------------------------
# Build output markdown
# ---------------------------------------------------------------------------
$out = [System.Collections.Generic.List[string]]::new()

$hasAny        = $false
$filteredCount = 0
foreach ($k in $categoryOrder) { $filteredCount += $buckets[$k].Count }

# --- Breaking changes callout (if any) ---
if ($buckets['breaking'].Count -gt 0) {
    $hasAny = $true
    $out.Add('> [!CAUTION]')
    $out.Add('> **This release contains breaking changes. Please review before updating.**')
    $out.Add('>')
    foreach ($item in $buckets['breaking']) {
        $formatted = Get-FormattedItem $item $Repo
        $out.Add("> - $formatted")
    }
    $out.Add('')
}

# --- Per-category sections ---
foreach ($key in $categoryOrder) {
    if ($key -eq 'breaking') { continue }   # already rendered above
    $bucket = $buckets[$key]
    if ($bucket.Count -eq 0) { continue }
    $hasAny = $true

    $out.Add("### $($categoryEmoji[$key])")
    $out.Add('')

    $collapse = ($bucket.Count -gt $maxPerSection) -and ($key -notin $neverCollapse)

    if ($collapse) {
        # Show first $maxPerSection, then summary
        for ($i = 0; $i -lt $maxPerSection; $i++) {
            $formatted = Get-FormattedItem $bucket[$i] $Repo
            $out.Add("- $formatted")
        }
        $remaining = $bucket.Count - $maxPerSection
        $out.Add('')
        $out.Add("<details>")
        $out.Add("<summary>Show $remaining more changes…</summary>")
        $out.Add('')
        for ($i = $maxPerSection; $i -lt $bucket.Count; $i++) {
            $formatted = Get-FormattedItem $bucket[$i] $Repo
            $out.Add("- $formatted")
        }
        $out.Add('')
        $out.Add("</details>")
    } else {
        foreach ($item in $bucket) {
            $formatted = Get-FormattedItem $item $Repo
            $out.Add("- $formatted")
        }
    }
    $out.Add('')
}

# --- Empty state ---
if (-not $hasAny) {
    $out.Add('> *No categorised changes found in this release.*')
    $out.Add('> Most commits were maintenance, dependency updates, or automated changes.')
    $out.Add('')
}

# --- Footer ---
$range = if ($FromTag) { "${FromTag}..HEAD" } else { 'all history' }
$keptPct = if ($totalRaw -gt 0) { [Math]::Round($filteredCount / $totalRaw * 100) } else { 0 }

$out.Add('---')

if ($totalRaw -gt 0) {
    $out.Add("*$filteredCount significant changes from $totalRaw total commits since ``$FromTag``.*")
} else {
    $out.Add("*Changelog generated from ``$range``.*")
}

Write-Output ($out -join "`n")
