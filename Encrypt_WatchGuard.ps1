<#
.Synopsis
   Encrypts a string to a Watchguard encrypted parameter
.EXAMPLE
   Encrypt-WatchguardParameter -PlainText 'P455Ph74seG0£sH3R£'
   Encrypt-WatchguardParameter -PlainText 'P455Ph74seG0£sH3R£' -VerboseMode
   Encrypt-WatchguardParameter -PlainText '?1\o§??↓.Uw?/????,??'
   Encrypt-WatchguardParameter -PlainText 'P455w0rd1!'
   Encrypt-WatchguardParameter -PlainText 'Private123' -VerboseMode
#>
# Encrypt-WatchguardParameter function
function Encrypt-WatchguardParameter {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [string]$PlainText,
        [switch]$VerboseMode = $false
    )

    Process {
        if ($VerboseMode) { Write-Verbose "Starting encryption process..." }

        $KeyEncryptionKey = [byte[]]@(29, 3, 245, 130, 135, 152, 43, 199, 1, 34, 115, 148, 228, 152, 222, 35)

        # Convert plaintext to bytes
        $TextBytes = [System.Text.Encoding]::UTF8.GetBytes($PlainText)
        if ($VerboseMode) { Write-Verbose "Plaintext converted to bytes: $($TextBytes -join ',')" }

        # Calculate padding size
        $PaddingSize = 16 - ($TextBytes.Length % 16)
        if ($PaddingSize -ne 16) {
            $TextBytes += ,0 * $PaddingSize
            if ($VerboseMode) { Write-Verbose "Padding applied." }
        }

        # Initialize arrays for blocks
        $Blocks = @()
        $Blocks += ,$TextBytes[0..15]
        $Blocks += @($TextBytes[16..($TextBytes.Length - 1)])

        if ($VerboseMode) { Write-Verbose "Blocks initialized: Block 1: $($Blocks[0] -join ','), Block 2: $($Blocks[1] -join ',')" }

        # Intermediate values calculation
        for ($j = 0; $j -le 5; $j++) {
            for ($i = 1; $i -lt $Blocks.Count; $i++) {
                if ($VerboseMode) { Write-Verbose "Processing block $($i + 1) of round $($j + 1)..." }
                $t = 6 * $j + $i

                # Encrypt block
                $Alg = New-Object -Type System.Security.Cryptography.RijndaelManaged
                $Alg.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
                $Alg.Mode = [System.Security.Cryptography.CipherMode]::ECB
                $Alg.Key = $KeyEncryptionKey

                # Prepare data for encryption
                $currentBlock = $Blocks[$i]
                if ($VerboseMode) { Write-Verbose "Current block to encrypt: $($currentBlock -join ',')" }
                $ms = New-Object System.IO.MemoryStream
                $cs = New-Object System.Security.Cryptography.CryptoStream -ArgumentList @($ms, $Alg.CreateEncryptor(), [System.Security.Cryptography.CryptoStreamMode]::Write)

                # Encrypt data
                $cs.Write($currentBlock, 0, $currentBlock.Length)
                $cs.FlushFinalBlock()

                # Update block
                $encryptedData = $ms.ToArray()
                if ($VerboseMode) { Write-Verbose "Encrypted data: $($encryptedData -join ',')" }
                $Blocks[$i] = $encryptedData

                # Clean up streams
                $cs.Close()
                $ms.Close()
            }
        }

        # Combine encrypted blocks
        $CombinedBlocks = $Blocks[0] + ($Blocks[1..($Blocks.Count - 1)] -join '')
        if ($VerboseMode) { Write-Verbose "Combined encrypted blocks: $($CombinedBlocks -join ',')" }

        # Convert bytes to hexadecimal
        $EncryptedHex = $CombinedBlocks | ForEach-Object { '{0:X2}' -f $_ }
        if ($VerboseMode) { Write-Verbose "Encrypted hexadecimal string: $EncryptedHex" }

        Write-Output $EncryptedHex
    }
}

Encrypt-WatchguardParameter -PlainText 'Private123' -VerboseMode

Encrypt-WatchguardParameter -PlainText 'P455w0rd1!'

