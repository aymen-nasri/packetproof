<#
Create the age key that decrypts PacketProof's prod secrets, and hand it to GitHub Actions.

Run once, by the repository owner, on Windows PowerShell with the GitHub CLI signed in:

    powershell -ExecutionPolicy Bypass -File scripts\bootstrap-sops-key.ps1

What it does:
  1. downloads age v1.3.2 for Windows from its GitHub release and checks the SHA-256
  2. generates an age key pair in a temporary file
  3. stores the private key as the secret SOPS_AGE_KEY of the repository's "prod" environment
     (piped straight into `gh secret set`: never printed, never pasted, never on a command line);
     the environment lets only jobs running from main read it
  4. stores the public key as the Actions variable SOPS_AGE_RECIPIENT
  5. deletes the temporary key file

Nobody else, including the assistant that wrote this script, ever sees the private key. If it is
ever lost or exposed, run this again and then the secrets-bootstrap workflow: prod gets new
identities, and the old ciphertext becomes useless (docs/secrets.md).
#>
$ErrorActionPreference = "Stop"
$Repo = "aymen-nasri/packetproof"
$Version = "v1.3.2"
$Sha256 = "f48d8f8f9ebe903ab5027ed067652f2cc1db94bc206976430133b905dcd8e8c7"

$work = Join-Path $env:TEMP ("pp-age-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $work | Out-Null
try {
    $zip = Join-Path $work "age.zip"
    Invoke-WebRequest -UseBasicParsing -OutFile $zip `
        "https://github.com/FiloSottile/age/releases/download/$Version/age-$Version-windows-amd64.zip"
    $actual = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
    if ($actual -ne $Sha256) { throw "age download checksum mismatch: $actual" }
    Expand-Archive $zip -DestinationPath $work -Force
    $keygen = Join-Path $work "age\age-keygen.exe"

    $key = Join-Path $work "key.txt"
    # age-keygen prints the public key on stderr; it is not a secret.
    & $keygen -o $key
    if (-not (Test-Path $key)) { throw "age-keygen did not create a key" }
    $public = (& $keygen -y $key).Trim()

    # Only the AGE-SECRET-KEY line, piped: it never appears on screen or in a process list.
    Get-Content $key | Where-Object { $_ -like "AGE-SECRET-KEY-*" } | gh secret set SOPS_AGE_KEY --env prod --repo $Repo
    if ($LASTEXITCODE -ne 0) { throw "gh secret set failed" }
    gh variable set SOPS_AGE_RECIPIENT --repo $Repo --body $public
    if ($LASTEXITCODE -ne 0) { throw "gh variable set failed" }

    Write-Host "Done. SOPS_AGE_KEY is stored as a secret of the prod environment."
    Write-Host "Public key (safe to share, now the SOPS_AGE_RECIPIENT variable): $public"
}
finally {
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
