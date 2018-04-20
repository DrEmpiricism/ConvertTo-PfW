#Requires -RunAsAdministrator
<#
	.SYNOPSIS
		Converts Windows 10 Home to Windows 10 Pro for Workstations.
	
	.DESCRIPTION
		Fully converts a Fall Creator's Update Windows 10 Home image to a Windows 10 Pro for Workstations image.
	
	.PARAMETER SourcePath
		The path to a Windows Installation ISO or an install.wim.
	
	.PARAMETER SavePath
		Specify an alternative save location for the converted image. The default save location is the Desktop.
	
	.PARAMETER ESD
		Compresses the final image to an ESD file instead of a WIM file.
		ESD compression can take quite a while to complete and is a system-intensive process.
	
	.EXAMPLE
		.\ConvertTo-PfW.ps1 -SourcePath "D:\install.wim"
		.\ConvertTo-PfW.ps1 -SourcePath "E:\Windows Images\Win10_1709_English_x64_ALL.iso" -SavePath "E:\Windows Images\Win10 PfW" -ESD
	
	.NOTES
		===========================================================================
		Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2018 v5.5.150
		Created on:   	11/30/2017
		Created by:     BenTheGreat
		Filename:     	ConvertTo-PfW.ps1
		Version:        2.4.7
		Last updated:	04/20/2018
		===========================================================================
#>

[CmdletBinding()]
[OutputType([System.Object])]
Param
(
	[Parameter(Mandatory = $true,
			   HelpMessage = 'The path to a Windows Installation ISO or an install.wim.')]
	[ValidateScript({
			If ((Test-Path $(Resolve-Path -Path $_) -PathType Leaf) -and ($_ -like "*.iso")) { $_ }
			ElseIf ((Test-Path $(Resolve-Path -Path $_) -PathType Leaf) -and ($_ -like "*.wim")) { $_ }
			Else { Throw "$_ is an invalid image type." }
		})]
	[Alias('ISO', 'WIM')]
	[string]$SourcePath,
	[Parameter(HelpMessage = 'Specify a different save location from default.')]
	[ValidateScript({
			If (Test-Path $(Resolve-Path -Path $_) -PathType Container) { $_ }
			Else { Throw "$_ is an invalid save path." }
		})]
	[Alias('Save')]
	[string]$SavePath,
	[Parameter(HelpMessage = 'Compresses the final image to an ESD file instead of a WIM file.')]
	[switch]$ESD
)

$Host.UI.RawUI.WindowTitle = "Converting image."
$Host.UI.RawUI.BackgroundColor = "Black"; Clear-Host
$ProgressPreference = "SilentlyContinue"
$Desktop = [Environment]::GetFolderPath("Desktop")

#region Helper Functions
Function Verify-Admin {
    [CmdletBinding()]
    Param ()
    $CurrentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
    $IsAdmin = $CurrentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    Write-Output "IsUserAdmin? $IsAdmin"
    Return $IsAdmin
}

Function Create-WorkDirectory {
    $WorkDir = [System.IO.Path]::GetTempPath()
    $WorkDir = [System.IO.Path]::Combine($WorkDir, [System.Guid]::NewGuid())
    [void][System.IO.Directory]::CreateDirectory($WorkDir)
    $WorkDir
}

Function Create-TempDirectory {
    $TempDir = [System.IO.Path]::GetTempPath()
    $TempDir = [System.IO.Path]::Combine($TempDir, [System.Guid]::NewGuid())
    [void][System.IO.Directory]::CreateDirectory($TempDir)
    $TempDir
}

Function Create-ImageDirectory {
    $ImageDir = [System.IO.Path]::GetTempPath()
    $ImageDir = [System.IO.Path]::Combine($ImageDir, [System.Guid]::NewGuid())
    [void][System.IO.Directory]::CreateDirectory($ImageDir)
    $ImageDir
}

Function Create-MountDirectory {
    $MountDir = [System.IO.Path]::GetTempPath()
    $MountDir = [System.IO.Path]::Combine($MountDir, [System.Guid]::NewGuid())
    [void][System.IO.Directory]::CreateDirectory($MountDir)
    $MountDir
}

Function Create-SaveDirectory {
    If (!($SavePath)) {
        New-Item -ItemType Directory -Path $Desktop\ConvertTo-PfW"-[$((Get-Date).ToString('MM.dd.yy hh.mm.ss'))]"
    }
    Else {
        New-Item -ItemType Directory -Path $SavePath\ConvertTo-PfW"-[$((Get-Date).ToString('MM.dd.yy hh.mm.ss'))]"
    }
}
#endregion Helper Functions

If (!(Verify-Admin)) {
    Throw "This script requires administrative permissions."
}

Try {
    If ((Test-Path -Path "$PSScriptRoot\Bin\wimlib-imagex.exe") -and (Test-Path -Path "$PSScriptRoot\Bin\libwim-15.dll")) {
        Copy-Item -Path "$PSScriptRoot\Bin\wimlib-imagex.exe" -Destination $Env:TEMP -Force
        Copy-Item -Path "$PSScriptRoot\Bin\libwim-15.dll" -Destination $Env:TEMP -Force
        $Error.Clear()
    }
    Else {
        If ((Test-Connection $Env:COMPUTERNAME -Quiet) -eq $true) {
            Write-Verbose "Wimlib not found. Requesting it from GitHub." -Verbose
            [Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"
            $paramWebRequestDll = @{
                Uri         = "https://github.com/DrEmpiricism/ConvertTo-PfW/blob/master/Bin/libwim-15.dll?raw=true"
                OutFile     = "$Env:TEMP\libwim-15.dll"
                TimeoutSec  = 15
                ErrorAction = "Stop"
            }
            [void](Invoke-WebRequest @paramWebRequestDll)
            $paramWebRequestExe = @{
                Uri         = "https://github.com/DrEmpiricism/ConvertTo-PfW/blob/master/Bin/wimlib-imagex.exe?raw=true"
                OutFile     = "$Env:TEMP\wimlib-imagex.exe"
                TimeoutSec  = 15
                ErrorAction = "Stop"
            }
            [void](Invoke-WebRequest @paramWebRequestExe)
            Write-Output ''
            $Error.Clear()
        }
        Else {
            Throw "Unable to retrieve required files. No active connection is available."
        }
    }
}
Catch {
    Write-Output ''
    Write-Warning "The GitHub web request has timed out."
    Break
}

If (([IO.FileInfo]$SourcePath).Extension -eq ".ISO") {
    $SourcePath = ([System.IO.Path]::ChangeExtension($SourcePath, ([System.IO.Path]::GetExtension($SourcePath)).ToString().ToLower()))
    $ResolveISO = (Resolve-Path -Path $SourcePath).Path
    $MountISO = Mount-DiskImage -ImagePath $ResolveISO -StorageType ISO -PassThru
    $DriveLetter = ($MountISO | Get-Volume).DriveLetter
    $InstallWIM = "$($DriveLetter):\sources\install.wim"
    If (Test-Path -Path $InstallWIM) {
        Write-Verbose "Copying the WIM from $(Split-Path $ResolveISO -Leaf)" -Verbose
        Copy-Item -Path $InstallWIM -Destination $Env:TEMP\install.wim -Force
        Dismount-DiskImage -ImagePath $SourcePath -StorageType ISO
        If (([IO.FileInfo]"$Env:TEMP\install.wim").IsReadOnly) {
            Set-ItemProperty -Path $Env:TEMP\install.wim -Name IsReadOnly -Value $false
        }
        $ImageIsCopied = $true
    }
    Else {
        Throw "$SourcePath does not contain valid installation media."
    }
}
ElseIf (([IO.FileInfo]$SourcePath).Extension -eq ".WIM") {
    $SourcePath = ([System.IO.Path]::ChangeExtension($SourcePath, ([System.IO.Path]::GetExtension($SourcePath)).ToString().ToLower()))
    $ResolveWIM = (Resolve-Path -Path $SourcePath).Path
    If (Test-Path -Path $ResolveWIM) {
        Write-Verbose "Copying the WIM from $(Split-Path $ResolveWIM -Parent)" -Verbose
        Copy-Item -Path $SourcePath -Destination $Env:TEMP\install.wim -Force
        If (([IO.FileInfo]"$Env:TEMP\install.wim").IsReadOnly) {
            Set-ItemProperty -Path $Env:TEMP\install.wim -Name IsReadOnly -Value $false
        }
        $ImageIsCopied = $true
    }
}

If ($ImageIsCopied.Equals($true)) {
    $CheckBuild = (Get-WindowsImage -ImagePath $Env:TEMP\install.wim -Index 1)
    If ($CheckBuild.Build -lt "16273") {
        Write-Output ''
        Throw "The image build [$($CheckBuild.Build.ToString())] is not supported."
    }
    Else {
        Write-Output ''
        Write-Output "The image build [$($CheckBuild.Build.ToString())] is supported."
        $BuildIsSupported = $true
    }
}

If (($BuildIsSupported.Equals($true)) -and (Test-Path -Path $Env:TEMP\libwim-15.dll) -and (Test-Path -Path $Env:TEMP\wimlib-imagex.exe)) {
    [void]($WorkFolder = Create-WorkDirectory)
    [void]($TempFolder = Create-TempDirectory)
    [void]($ImageFolder = Create-ImageDirectory)
    [void]($MountFolder = Create-MountDirectory)
    Move-Item -Path $Env:TEMP\install.wim -Destination $ImageFolder -Force
    Move-Item -Path $Env:TEMP\libwim-15.dll -Destination $ImageFolder -Force
    Move-Item -Path $Env:TEMP\wimlib-imagex.exe -Destination $ImageFolder -Force
    $ImageFile = "$ImageFolder\install.wim"
    $WimLib = "$ImageFolder\wimlib-imagex.exe"
    $IndexImages = @(
        "Windows 10 S"
        "Windows 10 S N"
        "Windows 10 Home N"
        "Windows 10 Home Single Language"
        "Windows 10 Education"
        "Windows 10 Education N"
        "Windows 10 Pro"
        "Windows 10 Pro N"
    )
    $HomeImage = "Windows 10 Home"
    $ImageInfo = (Get-WindowsImage -ImagePath $ImageFile)
}

If (!($ImageInfo.ImageName.Contains($HomeImage))) {
    Remove-Item $TempFolder -Recurse -Force
    Remove-Item $ImageFolder -Recurse -Force
    Remove-Item $MountFolder -Recurse -Force
    Remove-Item $WorkFolder -Recurse -Force
    Throw "$HomeImage not detected."
}

If ($ImageInfo.Count -gt '1' -and $ImageInfo.ImageName.Contains($HomeImage)) {
    Write-Output ''
    Write-Output "$HomeImage detected. Converting to a single-index image file."
    ForEach ($IndexImage In $IndexImages) {
        [void]($ImageInfo.Where{ $_.ImageName -contains $IndexImage } | Remove-WindowsImage -ImagePath $ImageFile -Name $IndexImage)
    }
    $Index = "1"
}
ElseIf ($ImageInfo.Count.Equals(1) -and $ImageInfo.ImageName.Contains($HomeImage)) {
    Write-Output ''
    Write-Output "$HomeImage detected."
    $Index = "1"
}

Try {
    Clear-Host
    Write-Verbose "Mounting Image." -Verbose
    [void](Mount-WindowsImage -ImagePath $ImageFile -Index $Index -Path $MountFolder -ScratchDirectory $TempFolder)
    Write-Output ''
    Write-Verbose "Verifying image health." -Verbose
    Start-Sleep 3
    $HealthCheck = (Repair-WindowsImage -Path $MountFolder -CheckHealth -ScratchDirectory $TempFolder)
    If ($HealthCheck.ImageHealthState -eq "Healthy") {
        Write-Output ''
        Write-Output "The image has returned as healthy."
        Start-Sleep 3
        Write-Output ''
        Write-Verbose "Changing Image Edition to Windows 10 Pro for Workstations." -Verbose
        [void](Set-WindowsEdition -Path $MountFolder -Edition "ProfessionalWorkstation" -ScratchDirectory $TempFolder -ErrorAction Stop)
        If (Test-Path -Path $MountFolder\Windows\Core.xml) {
            Remove-Item -Path $MountFolder\Windows\Core.xml -Force
        }
        Write-Output ''
        Write-Output "Image Edition successfully changed."
        Start-Sleep 3
        Write-Output ''
        Write-Verbose "Saving and Dismounting Image." -Verbose
        [void](Dismount-WindowsImage -Path $MountFolder -Save -CheckIntegrity -ScratchDirectory $TempFolder)
    }
    Else {
        Write-Output ''
        Write-Warning "The image has been flagged for corruption. Further servicing is required."
        Remove-Item $TempFolder -Recurse -Force
        Remove-Item $ImageFolder -Recurse -Force
        Remove-Item $MountFolder -Recurse -Force
        Remove-Item $WorkFolder -Recurse -Force
        Start-Sleep 3
        Break
    }
}
Catch {
    Write-Output ''
    Write-Warning "An error occured changing the Image Edition. Dismounting and Discarding Image."
    [void](Dismount-WindowsImage -Path $MountFolder -Discard -ScratchDirectory $TempFolder)
    Remove-Item $TempFolder -Recurse -Force
    Remove-Item $ImageFolder -Recurse -Force
    Remove-Item $MountFolder -Recurse -Force
    Remove-Item $WorkFolder -Recurse -Force
    Break
}
Finally {
    [void](Clear-WindowsCorruptMountPoint)
}

Try {
    Write-Output ''
    Write-Verbose "Converting $HomeImage to Windows 10 Pro for Workstations." -Verbose
    Start-Sleep 3
    $paramConvert = @{
        Command     = ('CMD.EXE /C $WimLib info $ImageFile $Index "Windows 10 Pro for Workstations" "Windows 10 Pro for Workstations" --image-property DISPLAYNAME="Windows 10 Pro for Workstations" --image-property DISPLAYDESCRIPTION="Windows 10 Pro for Workstations" --image-property FLAGS="ProfessionalWorkstation"')
        ErrorAction = "Stop"
    }
    [void](Invoke-Expression @paramConvert)
    Write-Output ''
    Write-Output "Conversion successful."
    $ConversionComplete = $true
    Start-Sleep 3
}
Catch {
    Write-Output ''
    Write-Warning "Unable to convert $HomeImage to Windows 10 Pro for Workstations."
    Remove-Item $TempFolder -Recurse -Force
    Remove-Item $ImageFolder -Recurse -Force
    Remove-Item $MountFolder -Recurse -Force
    Remove-Item $WorkFolder -Recurse -Force
    Break
}

If ($ConversionComplete.Equals($true)) {
    $EICFG_STR = @'
[EditionID]
ProfessionalWorkstation

[Channel]
Retail

[VL]
0
'@
    $EICFG_PATH = Join-Path -Path $WorkFolder -ChildPath "EI.cfg"
    Set-Content -Path $EICFG_PATH -Value $EICFG_STR -Force
}

Try {
    If ($ESD) {
        Write-Output ''
        Write-Verbose "Exporting Windows 10 Pro for Workstations to an ESD file. This will take some time to complete." -Verbose
        $paramExportESD = @{
            Command     = ('CMD.EXE /C $WimLib export $ImageFile $Index $WorkFolder\install.esd --solid --check')
            ErrorAction = "Stop"
        }
        [void](Invoke-Expression @paramExportESD)
    }
    Else {
        Write-Output ''
        Write-Verbose "Exporting Windows 10 Pro for Workstations." -Verbose
        $paramExportMaximum = @{
            Command     = ('CMD.EXE /C $WimLib export $ImageFile $Index $WorkFolder\install.wim --compress="LZX" --check')
            ErrorAction = "Stop"
        }
        [void](Invoke-Expression @paramExportMaximum)
    }
}
Catch {
    Write-Output ''
    Write-Warning "Unable to export Windows 10 Pro for Workstations."
    Break
}
Finally {
    $SaveFolder = Create-SaveDirectory
    Move-Item -Path $WorkFolder\install.wim -Destination $SaveFolder -Force
    Move-Item -Path $WorkFolder\*.cfg -Destination $SaveFolder -Force
    Remove-Item $TempFolder -Recurse -Force
    Remove-Item $ImageFolder -Recurse -Force
    Remove-Item $MountFolder -Recurse -Force
    Remove-Item $WorkFolder -Recurse -Force
    Write-Output ''
    Write-Output "Windows 10 Pro for Workstations saved to: $($SaveFolder.Name)"
    Start-Sleep 3
    Write-Output ''
    Write-Verbose "Full image conversion has completed with [$($Error.Count)] errors." -Verbose
    Write-Output ''
}

# SIG # Begin signature block
# MIIMBQYJKoZIhvcNAQcCoIIL9jCCC/ICAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUT6QDA38QezE3H8rH1cl35CNy
# JO6gggj8MIIDfTCCAmWgAwIBAgIQfY66zkudTZ9EnV2nSZm8oDANBgkqhkiG9w0B
# AQsFADBFMRQwEgYKCZImiZPyLGQBGRYEVEVDSDEVMBMGCgmSJomT8ixkARkWBU9N
# TklDMRYwFAYDVQQDEw1PTU5JQy5URUNILUNBMB4XDTE4MDMxMzIxNTY1OFoXDTIz
# MDMxMzIyMDY1OFowRTEUMBIGCgmSJomT8ixkARkWBFRFQ0gxFTATBgoJkiaJk/Is
# ZAEZFgVPTU5JQzEWMBQGA1UEAxMNT01OSUMuVEVDSC1DQTCCASIwDQYJKoZIhvcN
# AQEBBQADggEPADCCAQoCggEBAO6V7MmlK+QuOqWIzrLbmhv9acRXB46vi4RV2xla
# MTDUimrSyGtpoDQTYK2QZ3idDq1nxrnfAR2XytTwVCcCFoWLpFFRack5k/q3QFFV
# WP2DbSqoWfNG/EFd0qx8p81X5mH09t1mnN/K+BX1jiBS60rQYTsSGMkSSn/IUxDs
# sLvatjToctZnCDiqG8SgPdWtVfHRLLMmT0l8paOamO0bpaSSsTpBaan+qiYidnxa
# eIR23Yvv26Px1kMFYNp5YrWfWJEw5udB4W8DASO8TriypXXpca2jCEkVswNwNW/n
# Ng7QQqECDVwVm3BVSClNcf1J52uU+Nvx36gKRl5xcogW4h0CAwEAAaNpMGcwEwYJ
# KwYBBAGCNxQCBAYeBABDAEEwDgYDVR0PAQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMB
# Af8wHQYDVR0OBBYEFH/3cqyAb+6RpNGa2+j3ldMI8axTMBAGCSsGAQQBgjcVAQQD
# AgEAMA0GCSqGSIb3DQEBCwUAA4IBAQBYMivmEQPQpT1OfiPLVFaGFbnKmWo0dTWo
# vkCQMq54NdUqvnCkOIC9O3nrsBqdQhTPAtDow1C1qWQipGf/JyMCTh9ZIEoz3u4z
# RsiKMjIlPJkar1OsTsvKcAaya+a10LTcBMfF4DyOFaGqvKNrTaD3MmFQIBblQ8TS
# QOzQPOXUwY/2IgI9w1AA8VO0N2coYzvj4i79RSQ77eg1iefjBRqs347o4/b7pWtS
# 95+FBGr7JhhV3i9EI95172O4jmEkmoJQgr2mzvThjp9WiyeyjpnBAikV14YmEIyu
# DmKue5ZuxG+D3W3ZwFyGytUCHYWwMshTRwI0z236dZG9OhYDSfibMIIFdzCCBF+g
# AwIBAgITIQAAAAV87PzZFzK4xAAAAAAABTANBgkqhkiG9w0BAQsFADBFMRQwEgYK
# CZImiZPyLGQBGRYEVEVDSDEVMBMGCgmSJomT8ixkARkWBU9NTklDMRYwFAYDVQQD
# Ew1PTU5JQy5URUNILUNBMB4XDTE4MDQxODEyMjAzNloXDTE5MDQxODEyMjAzNlow
# UzEUMBIGCgmSJomT8ixkARkWBFRFQ0gxFTATBgoJkiaJk/IsZAEZFgVPTU5JQzEO
# MAwGA1UEAxMFVXNlcnMxFDASBgNVBAMTC0JlblRoZUdyZWF0MIIBIjANBgkqhkiG
# 9w0BAQEFAAOCAQ8AMIIBCgKCAQEA9xWMMTEOCpdnZu3eDTVbytEzoTnHQYeS/2jg
# wGLYU3+43C3viMoNVj+nLANJydTIRW5Dca+6JfO8UH25kf0XQ+AiXirQfjb9ec9u
# I+au+krmlL1fSR076lPgYzqnqPMQzOER8U2J2+uF18UtxEVO3rq7Cnxlich4jXzy
# gTy8XiNSAfUGR1nfq7HjahJ/CKopwl/7NcfmV5ZDzogRob1eErOPJXGAkewJuKqp
# /qItYzGH+9XADCyO0GYVIOsXNIE0Ho0bdBPZ3eDdamL1vocTlEkTe0/drs3o2AkS
# qcgg2I0uBco/p8CxCR7Tfq2zX1DFW9B7+KGNobxq+l+V15rTMwIDAQABo4ICUDCC
# AkwwJQYJKwYBBAGCNxQCBBgeFgBDAG8AZABlAFMAaQBnAG4AaQBuAGcwEwYDVR0l
# BAwwCgYIKwYBBQUHAwMwDgYDVR0PAQH/BAQDAgeAMB0GA1UdDgQWBBSIikO7ZjAP
# GlMAUcP2kulHiqpJnDAfBgNVHSMEGDAWgBR/93KsgG/ukaTRmtvo95XTCPGsUzCB
# yQYDVR0fBIHBMIG+MIG7oIG4oIG1hoGybGRhcDovLy9DTj1PTU5JQy5URUNILUNB
# LENOPURPUkFETyxDTj1DRFAsQ049UHVibGljJTIwS2V5JTIwU2VydmljZXMsQ049
# U2VydmljZXMsQ049Q29uZmlndXJhdGlvbixEQz1PTU5JQyxEQz1URUNIP2NlcnRp
# ZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFzZT9vYmplY3RDbGFzcz1jUkxEaXN0cmli
# dXRpb25Qb2ludDCBvgYIKwYBBQUHAQEEgbEwga4wgasGCCsGAQUFBzAChoGebGRh
# cDovLy9DTj1PTU5JQy5URUNILUNBLENOPUFJQSxDTj1QdWJsaWMlMjBLZXklMjBT
# ZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPU9NTklDLERD
# PVRFQ0g/Y0FDZXJ0aWZpY2F0ZT9iYXNlP29iamVjdENsYXNzPWNlcnRpZmljYXRp
# b25BdXRob3JpdHkwMQYDVR0RBCowKKAmBgorBgEEAYI3FAIDoBgMFkJlblRoZUdy
# ZWF0QE9NTklDLlRFQ0gwDQYJKoZIhvcNAQELBQADggEBAD1ZkdqIaFcqxTK1YcVi
# QENxxkixwVHJW8ZATwpQa8zQBh3B1cMromiR6gFvPmphMI1ObRtuTohvuZ+4tK7/
# IohAt6TwzyDFqY+/HzoNCat07Vb7DrA2fa+QMOl421kVUnZyYLI+gEod/zJqyuk8
# ULBmUxCXxxH26XVC016AuoOedKwzBgAFyIDlIAivZcSOtaSyALJSZ2Pk29R69dp5
# ICb+zCXCWPQJkbsU6eTlZAwaMmR2Vx4TQeDl49YIIwoDXDT4zBTcJ6n2k6vHQDWR
# K9zaF4qAD9pwlQICbLgTeZBz5Bz2sXzhkPsmY6LNKTAOnuk0QbjsKXSKoB/QRAip
# FiUxggJzMIICbwIBATBcMEUxFDASBgoJkiaJk/IsZAEZFgRURUNIMRUwEwYKCZIm
# iZPyLGQBGRYFT01OSUMxFjAUBgNVBAMTDU9NTklDLlRFQ0gtQ0ECEyEAAAAFfOz8
# 2RcyuMQAAAAAAAUwCQYFKw4DAhoFAKCB7TAZBgkqhkiG9w0BCQMxDAYKKwYBBAGC
# NwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQx
# FgQUkqiNswGFL7EbnQJkspyEeyK+kWIwgYwGCisGAQQBgjcCAQwxfjB8oHqAeABD
# AG8AbgB2AGUAcgB0AHMAIABXAGkAbgBkAG8AdwBzACAAMQAwACAASABvAG0AZQAg
# AHQAbwAgAFcAaQBuAGQAbwB3AHMAIAAxADAAIABQAHIAbwAgAGYAbwByACAAVwBv
# AHIAawBzAHQAYQB0AGkAbwBuAHMALjANBgkqhkiG9w0BAQEFAASCAQA3w8ROswZr
# wW0YZdl8+ugKalshQf1kvWqQS082mK5uH9h4xYDAEmWQOpWnt675bQ1LPQ1ZM0+n
# LD2nIISmNPbkDZazSO1EBC+bek28i3HnWxKe5fhXIXCpmvvNsyJ+ljqyL6/WloQA
# LpF2epYKzUlRFCzVg3u5Vs+Ov7MxWyXh181UCsoinp9st7PGTGEkLmdV32bKzeVt
# FIEi9Xw1DtaecHWAo6Me+K6j28ao65wFZwwL965yeRgz0/qBxDkOVGa+MyrX8Fo5
# ma6NjnaDeUu7j42BKCcynQ0KoVE5FQoL+6ZCYsJWqGcSWDHQKSEbhPx2newA0AmU
# 5Q6R6fD5fWPw
# SIG # End signature block
