<#
Create the age key that decrypts PacketProof's prod secrets, and hand it to GitHub Actions.

Run once, by the repository owner, on Windows PowerShell with the GitHub CLI signed in:

    powershell -ExecutionPolicy Bypass -File scripts\bootstrap-sops-key.ps1

What it does:
  1. checks that gh is signed in and can see the repository's "prod" environment
  2. downloads age v1.3.2 for Windows from its GitHub release and checks the SHA-256
  3. generates an age key pair in a temporary file
  4. stores the private key as the secret SOPS_AGE_KEY of the "prod" environment (piped straight
     into `gh secret set`: never printed, never pasted, never on a command line); the environment
     lets only jobs running from main read it
  5. stores the public key as the Actions variable SOPS_AGE_RECIPIENT
  6. checks that the secret and the variable are really there, and prints OK or FAILED
The temporary files, key included, are deleted at the end in every case.

Nobody else, including the assistant that wrote this script, ever sees the private key. If it is
ever lost or exposed, run this again and then the secrets-bootstrap workflow: prod gets new
identities, and the old ciphertext becomes useless (docs/secrets.md).

Native tools (age-keygen, gh) report progress on stderr. Some PowerShell hosts (ISE, the VS Code
console) turn any stderr line into a terminating error under $ErrorActionPreference = "Stop", so
this script checks exit codes itself instead.
#>
$ErrorActionPreference = "Continue"
$Repo = "aymen-nasri/packetproof"
$Version = "v1.3.2"
$Sha256 = "f48d8f8f9ebe903ab5027ed067652f2cc1db94bc206976430133b905dcd8e8c7"

function Fail([string]$Message) {
    throw "FAILED: $Message"
}

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$work = Join-Path $env:TEMP ("pp-age-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $work | Out-Null
try {
    Write-Host "1/6 checking the GitHub CLI"
    gh auth status 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { Fail "gh is not signed in: run 'gh auth login' first" }
    gh api "repos/$Repo/environments/prod" 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { Fail "this gh account cannot read the prod environment of $Repo" }

    Write-Host "2/6 downloading age $Version and checking its SHA-256"
    $zip = Join-Path $work "age.zip"
    try {
        Invoke-WebRequest -UseBasicParsing -OutFile $zip `
            "https://github.com/FiloSottile/age/releases/download/$Version/age-$Version-windows-amd64.zip"
    } catch { Fail "download failed: $($_.Exception.Message)" }
    $actual = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
    if ($actual -ne $Sha256) { Fail "age download checksum mismatch: $actual" }
    Expand-Archive $zip -DestinationPath $work -Force
    $keygen = Join-Path $work "age\age-keygen.exe"

    Write-Host "3/6 generating the key pair"
    $key = Join-Path $work "key.txt"
    & $keygen -o $key 2>&1 | Out-Null   # stderr: the public key and a file-permission warning
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $key)) { Fail "age-keygen did not create a key" }
    $public = ((& $keygen -y $key) | Out-String).Trim()
    if (-not $public.StartsWith("age1")) { Fail "could not read the public key" }

    Write-Host "4/6 storing the private key as the prod environment's secret SOPS_AGE_KEY"
    # Only the AGE-SECRET-KEY line, piped: it never appears on screen or in a process list.
    Get-Content $key | Where-Object { $_ -like "AGE-SECRET-KEY-*" } |
        gh secret set SOPS_AGE_KEY --env prod --repo $Repo 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { Fail "gh secret set failed" }

    Write-Host "5/6 storing the public key as the variable SOPS_AGE_RECIPIENT"
    gh variable set SOPS_AGE_RECIPIENT --repo $Repo --body $public 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { Fail "gh variable set failed" }

    Write-Host "6/6 checking that both are there"
    $names = @(gh secret list --env prod --repo $Repo --json name --jq ".[].name" 2>$null)
    if ($names -notcontains "SOPS_AGE_KEY") { Fail "SOPS_AGE_KEY is not listed in the prod environment" }
    $stored = ((gh variable get SOPS_AGE_RECIPIENT --repo $Repo 2>$null) | Out-String).Trim()
    if ($stored -ne $public) { Fail "SOPS_AGE_RECIPIENT does not hold the new public key" }

    Write-Host "OK: SOPS_AGE_KEY is stored as a secret of the prod environment." -ForegroundColor Green
    Write-Host "Public key (safe to share, now the SOPS_AGE_RECIPIENT variable): $public"
}
catch {
    Write-Host $_.Exception.Message -ForegroundColor Red
    $failed = $true
}
finally {
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
if ($failed) { exit 1 }
