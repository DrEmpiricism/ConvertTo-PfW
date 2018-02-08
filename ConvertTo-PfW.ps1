<#
	.SYNOPSIS
		Converts Windows 10 Home to Windows 10 Pro for Workstations
	
	.DESCRIPTION
		Fully converts a Fall Creator's Update Windows 10 Home image to a Windows 10 Pro for Workstations image.
	
	.PARAMETER SourcePath
		The path to a Windows Installation ISO or an Install.WIM.
	
	.PARAMETER SavePath
		Specify an alternative save location for the converted image. The default save location is the Desktop.
	
	.PARAMETER ESD
		Compresses the final image to an ESD file instead of a WIM file.
	
	.EXAMPLE
		.\ConvertTo-PfW.ps1 -SourcePath "D:\install.wim"
		.\ConvertTo-PfW.ps1 -SourcePath "E:\Windows Images\Win10_1709_English_x64_ALL.iso" -SavePath "E:\Windows Images\Win10 PfW" -ESD
	
	.NOTES
		It does not matter if the source image contains multiple indexes or a single Home index.
		Be aware that ESD compression can take quite a while to complete and is a system-intensive process.
	
	.NOTES
		===========================================================================
		Created on:   	11/30/2017
		Created by:     DrEmpiricism
		Contact:        Ben@Omnic.Tech
		Filename:     	ConvertTo-PfW.ps1
		Version:        2.4
		Last updated:	02/08/2018
		===========================================================================
#>
[CmdletBinding()]
Param
(
	[Parameter(Mandatory = $true,
			   HelpMessage = 'The path to a Windows Installation ISO or an Install.WIM.')][ValidateScript({ Test-Path $(Resolve-Path $_) })][Alias('ISO', 'WIM')][string]$SourcePath,
	[Parameter(HelpMessage = 'Specify a different save location from default.')][ValidateScript({ Test-Path $(Resolve-Path $_) })][Alias('Save')][string]$SavePath,
	[Parameter(HelpMessage = 'Compresses the final image to an ESD file instead of a WIM file.')][switch]$ESD
)

$Host.UI.RawUI.WindowTitle = "Converting image."
$Host.UI.RawUI.BackgroundColor = "Black"; Clear-Host
$ProgressPreference = "SilentlyContinue"
$Desktop = [Environment]::GetFolderPath("Desktop")

#region Helper Functions
Function Verify-Admin
{
	[CmdletBinding()]
	Param ()
	$CurrentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
	$IsAdmin = $CurrentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
	Write-Output "IsUserAdmin? $IsAdmin"
	Return $IsAdmin
}

Function Create-WorkDirectory
{
	$WorkDir = [System.IO.Path]::GetTempPath()
	$WorkDir = [System.IO.Path]::Combine($WorkDir, [System.Guid]::NewGuid())
	[void][System.IO.Directory]::CreateDirectory($WorkDir)
	$WorkDir
}

Function Create-TempDirectory
{
	$TempDir = [System.IO.Path]::GetTempPath()
	$TempDir = [System.IO.Path]::Combine($TempDir, [System.Guid]::NewGuid())
	[void][System.IO.Directory]::CreateDirectory($TempDir)
	$TempDir
}

Function Create-ImageDirectory
{
	$ImageDir = [System.IO.Path]::GetTempPath()
	$ImageDir = [System.IO.Path]::Combine($ImageDir, [System.Guid]::NewGuid())
	[void][System.IO.Directory]::CreateDirectory($ImageDir)
	$ImageDir
}

Function Create-MountDirectory
{
	$MountDir = [System.IO.Path]::GetTempPath()
	$MountDir = [System.IO.Path]::Combine($MountDir, [System.Guid]::NewGuid())
	[void][System.IO.Directory]::CreateDirectory($MountDir)
	$MountDir
}

Function Create-SaveDirectory
{
	[CmdletBinding()]
	Param ()
	
	If (!($SavePath))
	{
		New-Item -ItemType Directory -Path $Desktop\ConvertTo-PfW"-[$((Get-Date).ToString('MM.dd.yy hh.mm.ss'))]"
	}
	ElseIf (Test-Path -Path $SavePath -PathType Container)
	{
		New-Item -ItemType Directory -Path $SavePath\ConvertTo-PfW"-[$((Get-Date).ToString('MM.dd.yy hh.mm.ss'))]"
	}
	Else
	{
		New-Item -ItemType Directory -Path $Desktop\ConvertTo-PfW"-[$((Get-Date).ToString('MM.dd.yy hh.mm.ss'))]"
	}
}
#endregion Helper Functions

If (!(Verify-Admin))
{
	Throw "This script requires administrative permissions."
}

If ((Test-Path -Path "$PSScriptRoot\Bin\wimlib-imagex.exe") -and (Test-Path -Path "$PSScriptRoot\Bin\libwim-15.dll"))
{
	Copy-Item -Path "$PSScriptRoot\Bin\wimlib-imagex.exe" -Destination $env:TEMP -Force
	Copy-Item -Path "$PSScriptRoot\Bin\libwim-15.dll" -Destination $env:TEMP -Force
	$Error.Clear()
	Clear-Host
}
Else
{
	If ((Test-Connection $env:COMPUTERNAME -Quiet) -eq $true)
	{
		[void](Invoke-WebRequest -Uri "https://github.com/DrEmpiricism/ConvertTo-PfW/blob/master/Bin/libwim-15.dll?raw=true" -OutFile $env:TEMP\libwim-15.dll)
		[void](Invoke-WebRequest -Uri "https://github.com/DrEmpiricism/ConvertTo-PfW/blob/master/Bin/wimlib-imagex.exe?raw=true" -OutFile $env:TEMP\wimlib-imagex.exe)
		$Error.Clear()
		Clear-Host
	}
	Else
	{
		Throw "Unable to retrieve WimLib; no active connection is available."
	}
}

If (([IO.FileInfo]$SourcePath).Extension -like ".ISO")
{
	$ISOPath = (Resolve-Path $SourcePath).Path
	$MountISO = Mount-DiskImage -ImagePath $ISOPath -StorageType ISO -PassThru
	$DriveLetter = ($MountISO | Get-Volume).DriveLetter
	$InstallWIM = "$($DriveLetter):\sources\install.wim"
	If (Test-Path -Path $InstallWIM)
	{
		Write-Verbose "Copying WIM from the ISO to a temporary directory." -Verbose
		Copy-Item -Path $InstallWIM -Destination $env:TEMP -Force
		Dismount-DiskImage -ImagePath $ISOPath -StorageType ISO
		If (([IO.FileInfo]"$env:TEMP\install.wim").IsReadOnly) { ATTRIB -R $env:TEMP\install.wim }
	}
	Else
	{
		Dismount-DiskImage -ImagePath $ISOPath -StorageType ISO
		Throw "$ISOPath does not contain valid Windows Installation media."
	}
}
ElseIf (([IO.FileInfo]$SourcePath).Extension -like ".WIM")
{
	$WIMPath = (Resolve-Path $SourcePath).Path
	If (Test-Path -Path $WIMPath)
	{
		Write-Verbose "Copying WIM to a temporary directory." -Verbose
		Copy-Item -Path $SourcePath -Destination $env:TEMP\install.wim -Force
		If (([IO.FileInfo]"$env:TEMP\install.wim").IsReadOnly) { ATTRIB -R $env:TEMP\install.wim }
	}
	Else
	{
		Throw "$WIMPath is not a resolvable path."
	}
}

If ((Test-Path -Path $env:TEMP\install.wim) -and (Test-Path -Path $env:TEMP\libwim-15.dll) -and (Test-Path -Path $env:TEMP\wimlib-imagex.exe))
{
	[void]($WorkFolder = Create-WorkDirectory)
	[void]($TempFolder = Create-TempDirectory)
	[void]($ImageFolder = Create-ImageDirectory)
	[void]($MountFolder = Create-MountDirectory)
	Move-Item -Path $env:TEMP\install.wim -Destination $ImageFolder -Force
	Move-Item -Path $env:TEMP\libwim-15.dll -Destination $ImageFolder -Force
	Move-Item -Path $env:TEMP\wimlib-imagex.exe -Destination $ImageFolder -Force
	$ImageFile = "$ImageFolder\install.wim"
	$WimLib = "$ImageFolder\wimlib-imagex.exe"
	[string[]]$IndexImages = @(
		"Windows 10 S", "Windows 10 S N", "Windows 10 Home N", "Windows 10 Home Single Language", "Windows 10 Education", "Windows 10 Education N", "Windows 10 Pro", "Windows 10 Pro N"
	)
	$HomeImage = "Windows 10 Home"
	$ImageInfo = Get-WindowsImage -ImagePath $ImageFile
}

If ($ImageInfo.Count -gt "1" -and $ImageInfo.ImageName.Contains($HomeImage))
{
	Write-Output ''
	Write-Output "$HomeImage detected. Converting to a single-index image file."
	ForEach ($IndexImage in $IndexImages)
	{
		[void]($ImageInfo.Where{ $_.ImageName -contains $IndexImage } | Remove-WindowsImage -ImagePath $ImageFile -Name $IndexImage)
	}
	$Index = "1"
}
ElseIf ($ImageInfo.Count -eq "1" -and $ImageInfo.ImageName.Contains($HomeImage))
{
	Write-Output ''
	Write-Output "$HomeImage detected."
	$Index = "1"
}
Else
{
	Write-Error -Message "$HomeImage not detected."
	Remove-Item $TempFolder -Recurse -Force
	Remove-Item $ImageFolder -Recurse -Force
	Remove-Item $MountFolder -Recurse -Force
	Remove-Item $WorkFolder -Recurse -Force
	Break
}

Try
{
	Write-Output ''
	Write-Verbose "Mounting Image." -Verbose
	[void](Mount-WindowsImage -ImagePath $ImageFile -Index $Index -Path $MountFolder -ScratchDirectory $TempFolder)
	Write-Output ''
	Write-Verbose "Changing Image Edition to Windows 10 Pro for Workstations." -Verbose
	[void](Set-WindowsEdition -Path $MountFolder -Edition "ProfessionalWorkstation" -ScratchDirectory $TempFolder)
	If (Test-Path -Path $MountFolder\Windows\Core.xml)
	{
		Remove-Item -Path $MountFolder\Windows\Core.xml -Force
	}
	Write-Output ''
	Write-Output "Image Edition successfully changed."
	Start-Sleep 3
	Write-Output ''
	Write-Verbose "Saving and Dismounting Image." -Verbose
	[void](Dismount-WindowsImage -Path $MountFolder -Save -CheckIntegrity -ScratchDirectory $TempFolder)
	$IndexChangeComplete = $true
}
Catch [System.Exception]
{
	Write-Output ''
	Write-Error -Message "Unable to change Image Edition to Windows 10 Pro for Workstations." -Category WriteError
	If (Get-WindowsImage -Mounted)
	{
		[void](Dismount-WindowsImage -Path $MountFolder -Discard)
	}
	Remove-Item $TempFolder -Recurse -Force
	Remove-Item $ImageFolder -Recurse -Force
	Remove-Item $MountFolder -Recurse -Force
	Remove-Item $WorkFolder -Recurse -Force
	Break
}

Try
{
	Write-Output ''
	Write-Verbose "Converting $HomeImage to Windows 10 Pro for Workstations." -Verbose
	[void](Invoke-Expression -Command ('CMD.exe /C $WimLib info $ImageFile $Index "Windows 10 Pro for Workstations" "Windows 10 Pro for Workstations" --image-property DISPLAYNAME="Windows 10 Pro for Workstations" --image-property DISPLAYDESCRIPTION="Windows 10 Pro for Workstations" --image-property FLAGS="ProfessionalWorkstation"'))
	Write-Output ''
	Write-Output "Conversion successful."
	$ConversionComplete = $true
	Start-Sleep 3
}
Catch [System.Exception]
{
	Write-Output ''
	Write-Error -Message "Unable to convert $HomeImage to Windows 10 Pro for Workstations." -Category InvalidArgument
	Remove-Item $TempFolder -Recurse -Force
	Remove-Item $ImageFolder -Recurse -Force
	Remove-Item $MountFolder -Recurse -Force
	Remove-Item $WorkFolder -Recurse -Force
	Break
}

If ($ConversionComplete -eq $true)
{
	$AddEICFG = {
		$EICFGStr = @"
[EditionID]
ProfessionalWorkstation

[Channel]
Retail

[VL]
0
"@
		$CreateEICFG = Join-Path -Path $WorkFolder -ChildPath "EI.CFG"
		Set-Content -Path $CreateEICFG -Value $EICFGStr -Force
	}
	Write-Output ''
	Write-Verbose "Creating a Pro for Workstations EI.CFG." -Verbose
	& $AddEICFG
	Start-Sleep 3
}

Try
{
	If ($ESD)
	{
		Write-Output ''
		Write-Verbose "Exporting Windows 10 Pro for Workstations into an ESD file. This will take some time to complete." -Verbose
		[void](Invoke-Expression -Command ('CMD.exe /C $WimLib export $ImageFile $Index $WorkFolder\install.esd --solid --check'))
		[void](Clear-WindowsCorruptMountPoint)
		$SaveFolder = Create-SaveDirectory
		Move-Item -Path $WorkFolder\install.esd -Destination $SaveFolder -Force
	}
	Else
	{
		Write-Output ''
		Write-Verbose "Exporting Windows 10 Pro for Workstations." -Verbose
		[void](Invoke-Expression -Command ('CMD.exe /C $WimLib export $ImageFile $Index $WorkFolder\install.wim --compress="LZX" --check'))
		[void](Clear-WindowsCorruptMountPoint)
		$SaveFolder = Create-SaveDirectory
		Move-Item -Path $WorkFolder\install.wim -Destination $SaveFolder -Force
	}
}
Finally
{
	Move-Item -Path $WorkFolder\*.CFG -Destination $SaveFolder -Force
	Remove-Item $TempFolder -Recurse -Force
	Remove-Item $ImageFolder -Recurse -Force
	Remove-Item $MountFolder -Recurse -Force
	Remove-Item $WorkFolder -Recurse -Force
	Write-Output ''
	Write-Output "Windows 10 Pro for Workstations saved to $SaveFolder"
	Start-Sleep 3
	Write-Output ''
}
# SIG # Begin signature block
# MIIJnAYJKoZIhvcNAQcCoIIJjTCCCYkCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUprVSb4Qhz9fyQBLipwd+BBwE
# pWGgggaRMIIDQjCCAi6gAwIBAgIQdLtQndqbgJJBvqGYnOa7JjAJBgUrDgMCHQUA
# MCkxJzAlBgNVBAMTHk9NTklDLlRFQ0gtQ0EgQ2VydGlmaWNhdGUgUm9vdDAeFw0x
# NzExMDcwMzM4MjBaFw0zOTEyMzEyMzU5NTlaMCQxIjAgBgNVBAMTGU9NTklDLlRF
# Q0ggUG93ZXJTaGVsbCBDU0MwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQC61XYWFHD6Mf5tjbApbKSOWTlKYm9zYpVcHJ4bCXuRwUHaZEqd13GuvxA58oxL
# sj2PjV2lzV00zFk0RyswA20H2bjQtRJ45WZWUZMpgcf6hIiFGtQCuEQnytjD0AQu
# OTGBfwngyRsKLbaEDWk7B0dlWoYCvxt1zvXSIH2YcqpfP6QLejA+nyhvuLZm0O9E
# aFvBCPc+7G68VfQCQyn+aBTQpJpH34O9Qv06B2FGSiDk+lwrKQW4juEDmrabgpYF
# TACsxVUHK/1loejOvCZFyBXiyRoNaf8tJaSqmqzeB5zZz4rFAJesWEs+iAZutvfa
# x6TzMGFtjjevzl6ZrnF7Fv/9AgMBAAGjczBxMBMGA1UdJQQMMAoGCCsGAQUFBwMD
# MFoGA1UdAQRTMFGAEApGKFjm6hqPE+12gARxOhGhKzApMScwJQYDVQQDEx5PTU5J
# Qy5URUNILUNBIENlcnRpZmljYXRlIFJvb3SCEIgU76EmbFSeTMjPeYe5TN0wCQYF
# Kw4DAh0FAAOCAQEAte3lbQnd4Wnqf6qqmemtPLIHDna+382IRzBr4+ZaK4TXqXgl
# /sPzVkwkoqroJV9mMrQPvVXjgCaHie5h5W0HeGRVdQv7biG4zRNzbheVck2LPaOo
# MDNsNCc12ab9lvK/Y7eaj19iP1Yii/VBrnY3YsNt200icymp60R1QjgvXncPxZqK
# viMg7VQWBTfQ3n7LucBhuSZaMJItbVRTlJsbXzkmCQzvG88/TDRbFqukbmDVgiZL
# RONR2KTv0PRxopIews59WGMrJseuihET4z5a3L7xeUdwXCVPn87xgqIQGaCB5jui
# 0DHgpniWmxbBuAQMPMeuwSEQV0jb5KqVUegFGDCCA0cwggIzoAMCAQICEIgU76Em
# bFSeTMjPeYe5TN0wCQYFKw4DAh0FADApMScwJQYDVQQDEx5PTU5JQy5URUNILUNB
# IENlcnRpZmljYXRlIFJvb3QwHhcNMTcxMTA3MDMzMjIyWhcNMzkxMjMxMjM1OTU5
# WjApMScwJQYDVQQDEx5PTU5JQy5URUNILUNBIENlcnRpZmljYXRlIFJvb3QwggEi
# MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDMH3EMA2t/V0+BbvaWhgoezpQZ
# hY5NZcC/Yfs6YzAbCEBagmfT22NpAGKAd/fmsqL0DlZeBPDC8z5ga9BvxxWtvZQl
# QzCHx3wbmgrpc9AA99xEGms3lhcKea+wqEPCebK/OnSPVqqxEoGykoLQiR2BSO/m
# QL2hQPkM8kFGbX3ncUCMSdMWJR0XTcZL6zVPIpaLj0qJVEL6YoAFdlrd+6N2STex
# 9LKZhJ88dtfEiM0e81KyAkHHjPX03abSKppVTgOxG4+WZtMDZnvlpolEi5tgVy0e
# d04BBQmztKilRZILPkAgcmx89pf6Fa5Vss3Fp3Z7D+4e9nQ+4DZ/Vb1NIKZRAgMB
# AAGjczBxMBMGA1UdJQQMMAoGCCsGAQUFBwMDMFoGA1UdAQRTMFGAEApGKFjm6hqP
# E+12gARxOhGhKzApMScwJQYDVQQDEx5PTU5JQy5URUNILUNBIENlcnRpZmljYXRl
# IFJvb3SCEIgU76EmbFSeTMjPeYe5TN0wCQYFKw4DAh0FAAOCAQEAtj1/SaELGLyj
# DP2aRLpfMq1KIBoMjJvQhYfPWugzc6GJM/v+3LomDW8yylMhQRqy6749HMfDVXtJ
# oc4KU00H2q7M5xXGX7HJlh4tFEMrT4k1WDVdxF/TgXxTlMWBfRXV/rNzSFHtHVf6
# F+dY7INqxKlbMGpg3buF/Oh8ZtPk9xhyWtwraUTsyVBlmQlMeFeKwksbaSEy72mJ
# 5DhQfVmEv1PTv/wIJ/ff8OOZ63AeJqpLcmFARbTUmQVboFEG5mU30BHHntABspLj
# kdk4PCQjdVgG8Bd7uOC3XNbmrhTehi7Uu8uOBm7RQawF1wh65SlQm5HY2tntNPzD
# qHcndUPZwjGCAnUwggJxAgEBMD0wKTEnMCUGA1UEAxMeT01OSUMuVEVDSC1DQSBD
# ZXJ0aWZpY2F0ZSBSb290AhB0u1Cd2puAkkG+oZic5rsmMAkGBSsOAwIaBQCgggEN
# MBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgor
# BgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBT1jsfNVSr4jbUxJTi2ZKTtT1IvVzCB
# rAYKKwYBBAGCNwIBDDGBnTCBmqCBl4CBlABXAGkAbgBkAG8AdwBzACAAMQAwACAA
# SABvAG0AZQAgAHQAbwAgAFcAaQBuAGQAbwB3AHMAIAAxADAAIABQAHIAbwAgAGYA
# bwByACAAVwBvAHIAawBzAHQAYQB0AGkAbwBuAHMAIABmAHUAbABsACAAYwBvAG4A
# dgBlAHIAcwBpAG8AbgAgAHMAYwByAGkAcAB0AC4wDQYJKoZIhvcNAQEBBQAEggEA
# uRd339WydSydOhLq4CEkflYoMSF1OBBPgNqq+Cz6bLAMF+hXwwtaOOvXJfh0maG/
# 2fInGKT9UhT13kUd8TEx+ZpJtZoV1gpZYfVbcvN703I1kxSA13JKWlvArxQUo2GC
# PBjyMRTYu3VrKJosyVopN2e/bUMEpAGaa/e+g0JdedsyCmW3UlaF7RYP6f09sqWf
# /V/RDM0MORKw6zWmsiJU7rP2NhDqLM5+VJAiYsMLr4MFyDRGLw1JjpifnCoYLCkQ
# MEHI+bbvWb/tCB9o90Rge3YKm5xClqkQhb98jwIezTF5/YNIvUZBJjAB7TCryTCL
# hDsgJ9jNyHiyS9e5MLRxYQ==
# SIG # End signature block
