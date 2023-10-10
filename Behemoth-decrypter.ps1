[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$jsonfile,

    [Parameter(Mandatory=$true)]
    [string]$privatekey
)

# Get the current directory 
$currentDir = Get-Location

# List of files to search for using the provided filenames
$requiredFiles = @($jsonfile, $privatekey)

# If files were found, set this variable to trye
$filesFound = $true

# Loop over each file and check if it exists in the current directory
foreach ($file in $requiredFiles) {
    $filePath = Join-Path $currentDir $file
    if (-Not (Test-Path $filePath)) {
        Write-Host "[ - ] Error: $file not found in $currentDir" -ForegroundColor Red
        $filesFound = $false
    }
}

# If all files are found, load them to strings and print "Loaded"
if ($filesFound) {
    try {
        $jsonData = Get-Content (Join-Path $currentDir $jsonfile) -Raw
        $privateKeyXml = Get-Content (Join-Path $currentDir $privatekey) -Raw
        Write-Host "[ + ] JSON file and private key has been loaded." -ForegroundColor Green
        Write-Host ""
    } catch {
        Write-Host "[ - ] Error: Unable to load files. $_" -ForegroundColor Red
        exit
    }
} else {
    exit
}


try {
    $jsonObject = ConvertFrom-Json $jsonData
} catch {
    Write-Host "[ - ] Error: Unable to convert JSON data to PowerShell object. $_" -ForegroundColor Red
    exit
}



# Decrypt RSA Function
function Decrypt-RSA {
    param (
        [Parameter(Mandatory=$true)]
        [string]$data,

        [Parameter(Mandatory=$true)]
        [string]$privateKeyXml
    )

    $rsaProvider = [System.Security.Cryptography.RSACryptoServiceProvider]::new()
    try {
        $rsaProvider.FromXmlString($privateKeyXml)
    } catch {
        Write-Host "[ - ] Error: Unable to load private key XML to RSA provider. $_" -ForegroundColor Red
        exit
    }

    # Decrypt the data
    try {
        $bytesToDecrypt = [System.Convert]::FromBase64String($data)
        $decryptedBytes = $rsaProvider.Decrypt($bytesToDecrypt, $true)
        $rsaProvider.Clear()
    } catch {
        Write-Host "[ - ] Error: Unable to decrypt data. $_" -ForegroundColor Red
        exit
    }

    return [System.Text.Encoding]::UTF8.GetString($decryptedBytes)
}


function Decrypt {
    param (
        [string]$filePath,
        [string]$key,
        [string]$initialVector
    )

    # Check if file path is valid
    if ([string]::IsNullOrEmpty($filePath)) {
        Write-Host "[ - ] File path cannot be empty"
        return
    }

    if (-Not (Test-Path $filePath)) {
        Write-Host "[ - ] File not found: $filePath"
        return
    }

    # Convert key and iv from binary string to byte array
    $keyBytes = [System.Text.Encoding]::Default.GetBytes($key)
    $ivBytes = [System.Text.Encoding]::ASCII.GetBytes($initialVector)

    # Read the encrypted file
    $encryptedContent = [System.IO.File]::ReadAllBytes($filePath)

    # Extract the authentication tag from the end of the encrypted content
    $tagBytes = $encryptedContent[-16..-1]
    $encryptedContent = $encryptedContent[0..($encryptedContent.Length - 17)]

    # Initialize AES GCM object
    $aes = [System.Security.Cryptography.AesGcm]::new($keyBytes)

    # Decrypt the file content
    $decryptedContent = [byte[]]::new($encryptedContent.Length)
    $aes.Decrypt($ivBytes, $encryptedContent, $tagBytes, $decryptedContent)

    # Write the decrypted content to the file
    [System.IO.File]::WriteAllBytes($filePath, $decryptedContent)

    # Rename the file by removing the last extension
    $newFilePath = [System.IO.Path]::GetFileNameWithoutExtension($filePath)
    Rename-Item -Path $filePath -NewName $newFilePath

    Write-Host "[ + ] File decrypted and renamed successfully" -ForegroundColor Green
}



foreach ($item in $jsonObject.PSObject.Properties) {
    $filePath = $item.Name
    $key = $item.Value.key
    $iv = $item.Value.iv

    # Decrypt key and iv
    $decryptedKey = Decrypt-RSA -data $key -privateKeyXml $privateKeyXml
    $decryptedIv = Decrypt-RSA -data $iv -privateKeyXml $privateKeyXml

    # Print decrypted file path with key and iv
    Write-Host "File: $filePath"
    Write-Host "Decrypted Key: $decryptedKey"
    Write-Host "Decrypted IV: $decryptedIv"
    Write-Host ""
    $decryptedFilePath = Decrypt -FilePath $filePath -Key $decryptedKey -InitialVector $decryptedIv
    Write-Host ('*' * 100) -ForegroundColor Yellow
}
