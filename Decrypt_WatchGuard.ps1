<#
.Synopsis
   Decrypts a Watchguard encrypted BOVPN pre-shared-key
.EXAMPLE
    Decrypt-WatchguardParameter -EncryptedText '0E611DC31F2AEBB4A6E69F2641E1E83D762F514F3636E1EFA86B9BDECFEFADFB'
    Decrypt-WatchguardParameter -EncryptedText '0E611DC31F2AEBB4A6E69F2641E1E83D762F514F3636E1EFA86B9BDECFEFADFB' -VerboseMode $true
#>
function Decrypt-WatchguardParameter {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$EncryptedText,
        [switch]$VerboseMode=$false
    )

    if ($VerboseMode) { Write-Host "Starting decryption process..." }

    $HexBytes = $EncryptedText -split "(?<=\G\w{2})(?=\w{2})" | ForEach-Object { [Convert]::ToByte($_, 16) }

    if ($VerboseMode) { Write-Host "Input hexadecimal string: $EncryptedText" }

    if ($VerboseMode) { Write-Host "Hexadecimal pairs: $($HexBytes -join ',')" }

    $KeyEncryptionKey = [byte[]] @(29, 3, 245, 130, 135, 152, 43, 199, 1, 34, 115, 148, 228, 152, 222, 35)

    $DecryptedBytes = @()
    $BlockSize = 16  # Set the block size to 16 bytes

    $NumBlocks = [Math]::Ceiling($HexBytes.Count / $BlockSize)

    for ($i = 0; $i -lt $NumBlocks; $i++) {
        $start = $i * $BlockSize
        $end = [Math]::Min(($start + $BlockSize), $HexBytes.Count)
        $Block = [byte[]] ($HexBytes[$start..($end - 1)])

        $t = 6 * 0 + $i + 1
        $A = [byte[]] $Block

        if ($VerboseMode) { Write-Host "Processing block $($i + 1) of round 1..."; Write-Host "Current block to decrypt: $($Block -join ', ')" }

        $Alg = New-Object -Type System.Security.Cryptography.RijndaelManaged
        $Alg.Padding = [System.Security.Cryptography.PaddingMode]::None
        $Alg.Mode = [System.Security.Cryptography.CipherMode]::ECB
        $Alg.Key = $KeyEncryptionKey

        $ms = New-Object System.IO.MemoryStream
        $xf = $Alg.CreateDecryptor()
        $cs = New-Object System.Security.Cryptography.CryptoStream -ArgumentList @($ms, $xf, [System.Security.Cryptography.CryptoStreamMode]::Write)

        $cs.Write($A, 0, $A.Count)
        $cs.FlushFinalBlock()

        $DecryptedBlock = $ms.ToArray()

        if ($VerboseMode) { Write-Host "Decrypted block: $($DecryptedBlock -join ', ')" }

        $DecryptedBytes += $DecryptedBlock
        $cs.Close()
        $ms.Close()
    }

    if ($VerboseMode) { Write-Host "Combined decrypted blocks: $($DecryptedBytes -join ', ')" }

    $PaddingSize = $DecryptedBytes[-1]
    $PlainText = [System.Text.Encoding]::ASCII.GetString($DecryptedBytes[0..($DecryptedBytes.Length - $PaddingSize - 2)])

    if ($VerboseMode) { Write-Host "Padding size: $PaddingSize, Decrypted bytes without padding: $($DecryptedBytes[0..($DecryptedBytes.Length - $PaddingSize - 2)] -join ', ')" }

    if ($VerboseMode) { Write-Host "Decrypted plaintext: $PlainText" }

    Write-Output $PlainText

    if ($VerboseMode) { Write-Host "Decryption process complete." }
}