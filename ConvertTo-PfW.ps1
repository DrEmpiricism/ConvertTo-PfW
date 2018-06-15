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
		Version:        2.4.9
		Last updated:	06/13/2018
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
$TempPath = [System.IO.Path]::GetTempPath()

#region Helper Functions
Function Test-Admin
{
	$CurrentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
	$IsAdmin = $CurrentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
	Write-Output "IsUserAdmin? $IsAdmin"
	Return $IsAdmin
}

Function New-WorkDirectory
{
	$WorkDir = [System.IO.Directory]::CreateDirectory((Join-Path -Path $Env:TEMP -ChildPath "WorkTemp_$(Get-Random)"))
	$WorkDir = Get-Item -LiteralPath "$Env:TEMP\$WorkDir" -Force
	$WorkDir
}

Function New-ScratchDirectory
{
	$ScratchDir = [System.IO.Directory]::CreateDirectory((Join-Path -Path $Env:TEMP -ChildPath "ScratchTemp_$(Get-Random)"))
	$ScratchDir = Get-Item -LiteralPath "$Env:TEMP\$ScratchDir" -Force
	$ScratchDir
}

Function New-ImageDirectory
{
	$ImageDir = [System.IO.Directory]::CreateDirectory((Join-Path -Path $Env:TEMP -ChildPath "ImageTemp_$(Get-Random)"))
	$ImageDir = Get-Item -LiteralPath "$Env:TEMP\$ImageDir" -Force
	$ImageDir
}

Function New-MountDirectory
{
	$MountDir = [System.IO.Directory]::CreateDirectory((Join-Path -Path $Env:TEMP -ChildPath "MountTemp_$(Get-Random)"))
	$MountDir = Get-Item -LiteralPath "$Env:TEMP\$MountDir" -Force
	$MountDir
}

Function New-SaveDirectory
{
	If (!$SavePath)
	{
		$SaveDir = [System.IO.Directory]::CreateDirectory((Join-Path -Path $Desktop -ChildPath ConvertTo-PfW"-[$((Get-Date).ToString('MM.dd.yy hh.mm.ss'))]"))
		$SaveDir = Get-Item -LiteralPath "$Desktop\$SaveDir"
		$SaveDir
	}
	Else
	{
		$SaveDir = [System.IO.Directory]::CreateDirectory((Join-Path -Path $SavePath -ChildPath ConvertTo-PfW"-[$((Get-Date).ToString('MM.dd.yy hh.mm.ss'))]"))
		$SaveDir = Get-Item -LiteralPath "$SavePath\$SaveDir"
		$SaveDir
	}
}
#endregion Helper Functions

If (!(Test-Admin)) { Write-Error "This script requires administrative permissions."; Break }

Try
{
	If ((Test-Path -Path "$PSScriptRoot\Bin\wimlib-imagex.exe") -and (Test-Path -Path "$PSScriptRoot\Bin\libwim-15.dll"))
	{
		Copy-Item -Path "$PSScriptRoot\Bin\wimlib-imagex.exe" -Destination $TempPath -Force
		Copy-Item -Path "$PSScriptRoot\Bin\libwim-15.dll" -Destination $TempPath -Force
		$Error.Clear()
	}
	Else
	{
		If ((Test-Connection $Env:COMPUTERNAME -Quiet) -eq $true)
		{
			Write-Verbose "Wimlib not found. Requesting it from GitHub." -Verbose
			[Net.ServicePointManager]::SecurityProtocol = "TLS12, TLS11, TLS"
			[void](Invoke-WebRequest -Uri "https://github.com/DrEmpiricism/ConvertTo-PfW/blob/master/Bin/libwim-15.dll?raw=true" -OutFile "$TempPath\libwim-15.dll" -TimeoutSec 15 -ErrorAction Stop)
			[void](Invoke-WebRequest -Uri "https://github.com/DrEmpiricism/ConvertTo-PfW/blob/master/Bin/wimlib-imagex.exe?raw=true" -OutFile "$TempPath\wimlib-imagex.exe" -TimeoutSec 15 -ErrorAction Stop)
			$Error.Clear()
			Write-Output ''
		}
		Else
		{
			Write-Output ''
			Write-Error "Unable to retrieve required files. No active connection is available."
			Break
		}
	}
}
Catch
{
	Write-Output ''
	Write-Error "The GitHub web request has timed out."
	Break
}

If (([IO.FileInfo]$SourcePath).Extension -eq ".ISO")
{
	$SourcePath = ([System.IO.Path]::ChangeExtension($SourcePath, ([System.IO.Path]::GetExtension($SourcePath)).ToString().ToLower()))
	$ResolveISO = (Resolve-Path -Path $SourcePath).ProviderPath
	$MountISO = Mount-DiskImage -ImagePath $ResolveISO -StorageType ISO -PassThru
	$DriveLetter = ($MountISO | Get-Volume).DriveLetter
	$WIMFile = "$($DriveLetter):\sources\install.wim"
	If (Test-Path -Path $WIMFile)
	{
		Write-Verbose "Copying the WIM from $(Split-Path -Path $ResolveISO -Leaf)" -Verbose
		Copy-Item -Path $WIMFile -Destination "$TempPath\install.wim" -Force
		Dismount-DiskImage -ImagePath $SourcePath -StorageType ISO
		$WIMFile = Get-Item -Path "$TempPath\install.wim" -Force
		Set-ItemProperty -Path $WIMFile -Name IsReadOnly -Value $false
		$ImageIsCopied = $true
	}
	Else
	{
		Write-Error "$SourcePath does not contain valid installation media."
		Break
	}
}
ElseIf (([IO.FileInfo]$SourcePath).Extension -eq ".WIM")
{
	$SourcePath = ([System.IO.Path]::ChangeExtension($SourcePath, ([System.IO.Path]::GetExtension($SourcePath)).ToString().ToLower()))
	$ResolveWIM = (Resolve-Path -Path $SourcePath).ProviderPath
	If (Test-Path -Path $ResolveWIM)
	{
		Write-Verbose "Copying the WIM from $(Split-Path -Path $ResolveWIM -Parent)" -Verbose
		Copy-Item -Path $SourcePath -Destination "$TempPath\install.wim" -Force
		$WIMFile = Get-Item -Path "$TempPath\install.wim" -Force
		If ($WIMFile.IsReadOnly) { Set-ItemProperty -Path $WIMFile -Name IsReadOnly -Value $false }
		$ImageIsCopied = $true
	}
}

If ($ImageIsCopied.Equals($true))
{
	$CheckBuild = (Get-WindowsImage -ImagePath $WIMFile -Index 1).Build
	If ($CheckBuild -lt '16273')
	{
		Write-Output ''
		Write-Error "The image build [$($CheckBuild.ToString())] is not supported."
		Break
	}
	Else
	{
		Write-Output ''
		Write-Output "The image build [$($CheckBuild.ToString())] is supported."
		Start-Sleep 3
		$BuildIsSupported = $true
	}
}

If (($BuildIsSupported.Equals($true)) -and (Test-Path -Path "$TempPath\libwim-15.dll") -and (Test-Path -Path "$TempPath\wimlib-imagex.exe"))
{
	[void]($WorkFolder = New-WorkDirectory)
	[void]($ScratchFolder = New-ScratchDirectory)
	[void]($ImageFolder = New-ImageDirectory)
	[void]($MountFolder = New-MountDirectory)
	Move-Item -Path "$TempPath\install.wim" -Destination $ImageFolder
	Move-Item -Path "$TempPath\libwim-15.dll" -Destination $ImageFolder
	Move-Item -Path "$TempPath\wimlib-imagex.exe" -Destination $ImageFolder
	$ImageFile = "$ImageFolder\install.wim"
	$ImageX = "$ImageFolder\wimlib-imagex.exe"
	$IndexImages = @("Windows 10 S", "Windows 10 S N", "Windows 10 Home N", "Windows 10 Home Single Language", "Windows 10 Education", "Windows 10 Education N", "Windows 10 Pro", "Windows 10 Pro N")
	$HomeImage = "Windows 10 Home"
	$ImageInfo = Get-WindowsImage -ImagePath $ImageFile
}

If (!$ImageInfo.ImageName.Contains($HomeImage))
{
	Write-Output ''
	Write-Error "$HomeImage not detected."
	Remove-Item $ScratchFolder -Recurse -Force
	Remove-Item $ImageFolder -Recurse -Force
	Remove-Item $MountFolder -Recurse -Force
	Remove-Item $WorkFolder -Recurse -Force
	Break
}
ElseIf ($ImageInfo.ImageName.Contains($HomeImage) -and $ImageInfo.Count -gt 1)
{
	Write-Output ''
	Write-Verbose "$HomeImage detected. Converting to a single-index image file." -Verbose
	ForEach ($IndexImage In $IndexImages)
	{
		[void]($ImageInfo.Where{ $_.ImageName -contains $IndexImage } | Remove-WindowsImage -ImagePath $ImageFile -Name $IndexImage -ScratchDirectory $ScratchFolder)
	}
	$Index = 1
}
ElseIf ($ImageInfo.ImageName.Contains($HomeImage) -and $ImageInfo.Count.Equals(1))
{
	Write-Output ''
	Write-Verbose "$HomeImage detected." -Verbose
	$Index = 1
}

Try
{
	Write-Output ''
	Write-Verbose "Mounting Image." -Verbose
	[void](Mount-WindowsImage -ImagePath $ImageFile -Index $Index -Path $MountFolder -ScratchDirectory $ScratchFolder)
	$HealthCheck = (Repair-WindowsImage -Path $MountFolder -CheckHealth -ScratchDirectory $ScratchFolder).ImageHealthState
	If ($HealthCheck -eq "Healthy")
	{
		Write-Output ''
		Write-Verbose "Changing Image Edition to Windows 10 Pro for Workstations." -Verbose
		[void](Set-WindowsEdition -Path $MountFolder -Edition "ProfessionalWorkstation" -ScratchDirectory $ScratchFolder -ErrorAction Stop)
		If (Test-Path -Path "$MountFolder\Windows\Core.xml") { Remove-Item -Path "$MountFolder\Windows\Core.xml" -Force -ErrorAction SilentlyContinue }
		Write-Output ''
		Write-Verbose "Saving and Dismounting Image." -Verbose
		$RecycleBin = "$MountFolder\" + '$Recycle.Bin'
		If (Test-Path -Path $RecycleBin) { Remove-Item -Path $RecycleBin -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue }
		If (Test-Path -Path "$MountFolder\PerfLogs") { Remove-Item -Path "$MountFolder\PerfLogs" -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue }
		[void](Dismount-WindowsImage -Path $MountFolder -Save -CheckIntegrity -ScratchDirectory $ScratchFolder)
	}
	Else
	{
		Write-Output ''
		Write-Error "The image has been flagged for corruption. Further servicing is required."
		Remove-Item $ScratchFolder -Recurse -Force -ErrorAction SilentlyContinue
		Remove-Item $ImageFolder -Recurse -Force -ErrorAction SilentlyContinue
		Remove-Item $MountFolder -Recurse -Force -ErrorAction SilentlyContinue
		Remove-Item $WorkFolder -Recurse -Force -ErrorAction SilentlyContinue
		Break
	}
}
Catch
{
	Write-Output ''
	Write-Error "An error occured changing the Image Edition. Dismounting and Discarding Image."
	[void](Dismount-WindowsImage -Path $MountFolder -Discard -ScratchDirectory $ScratchFolder)
	Remove-Item $ScratchFolder -Recurse -Force -ErrorAction SilentlyContinue
	Remove-Item $ImageFolder -Recurse -Force -ErrorAction SilentlyContinue
	Remove-Item $MountFolder -Recurse -Force -ErrorAction SilentlyContinue
	Remove-Item $WorkFolder -Recurse -Force -ErrorAction SilentlyContinue
	Break
}
Finally
{
	[void](Clear-WindowsCorruptMountPoint)
}

Try
{
	Write-Output ''
	Write-Verbose "Converting $HomeImage to Windows 10 Pro for Workstations." -Verbose
	Start-Sleep 3
	[void](Invoke-Expression -Command ('CMD.EXE /C $ImageX info $ImageFile $Index "Windows 10 Pro for Workstations" "Windows 10 Pro for Workstations" --image-property DISPLAYNAME="Windows 10 Pro for Workstations" --image-property DISPLAYDESCRIPTION="Windows 10 Pro for Workstations" --image-property FLAGS="ProfessionalWorkstation"') -ErrorAction Stop)
	$ConversionComplete = $true
	Start-Sleep 3
}
Catch
{
	Write-Output ''
	Write-Error "Unable to convert $HomeImage to Windows 10 Pro for Workstations."
	Remove-Item $ScratchFolder -Recurse -Force -ErrorAction SilentlyContinue
	Remove-Item $ImageFolder -Recurse -Force -ErrorAction SilentlyContinue
	Remove-Item $MountFolder -Recurse -Force -ErrorAction SilentlyContinue
	Remove-Item $WorkFolder -Recurse -Force -ErrorAction SilentlyContinue
	Break
}

If ($ConversionComplete.Equals($true))
{
	$null = @'
[EditionID]
ProfessionalWorkstation

[Channel]
Retail

[VL]
0
'@ | Out-File -FilePath "$WorkFolder\EI.cfg" -Force -ErrorAction SilentlyContinue
}

Try
{
	If ($ESD)
	{
		Write-Output ''
		Write-Verbose "Exporting Windows 10 Pro for Workstations to an ESD file. This will take some time to complete." -Verbose
		[void](Invoke-Expression -Command ('CMD.EXE /C $ImageX export $ImageFile $Index "$WorkFolder\install.esd" --solid --check') -ErrorAction Stop)
		Remove-Item -Path $ImageFile -Force
	}
	Else
	{
		Write-Output ''
		Write-Verbose "Exporting Windows 10 Pro for Workstations." -Verbose
		[void](Invoke-Expression -Command ('CMD.EXE /C $ImageX export $ImageFile $Index "$WorkFolder\install.wim" --compress="LZX" --check') -ErrorAction Stop)
	}
}
Catch
{
	Write-Output ''
	Write-Error "Unable to export Windows 10 Pro for Workstations."
	Break
}
Finally
{
	[void]($SaveFolder = New-SaveDirectory)
	If (Test-Path -Path "$WorkFolder\install.wim") { Move-Item -Path "$WorkFolder\install.wim" -Destination $SaveFolder -Force }
	If (Test-Path -Path "$WorkFolder\install.esd") { Move-Item -Path "$WorkFolder\install.esd" -Destination $SaveFolder -Force }
	Move-Item -Path "$WorkFolder\*.cfg" -Destination $SaveFolder -Force -ErrorAction SilentlyContinue
	Remove-Item $ScratchFolder -Recurse -Force -ErrorAction SilentlyContinue
	Remove-Item $ImageFolder -Recurse -Force -ErrorAction SilentlyContinue
	Remove-Item $MountFolder -Recurse -Force -ErrorAction SilentlyContinue
	Remove-Item $WorkFolder -Recurse -Force -ErrorAction SilentlyContinue
	Write-Output ''
	Write-Output "Windows 10 Pro for Workstations saved to: $($SaveFolder.Name)"
	Write-Verbose "Full image conversion has completed with [$($Error.Count)] errors." -Verbose
	Write-Output ''
	Start-Sleep 3
}
# SIG # Begin signature block
# MIIMJgYJKoZIhvcNAQcCoIIMFzCCDBMCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUw9MWNBhC6mR704ryqQ/CQQnv
# CDqgggj8MIIDfTCCAmWgAwIBAgIQfY66zkudTZ9EnV2nSZm8oDANBgkqhkiG9w0B
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
# FiUxggKUMIICkAIBATBcMEUxFDASBgoJkiaJk/IsZAEZFgRURUNIMRUwEwYKCZIm
# iZPyLGQBGRYFT01OSUMxFjAUBgNVBAMTDU9NTklDLlRFQ0gtQ0ECEyEAAAAFfOz8
# 2RcyuMQAAAAAAAUwCQYFKw4DAhoFAKCCAQ0wGQYJKoZIhvcNAQkDMQwGCisGAQQB
# gjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkE
# MRYEFLozVNXKH+qQU3cJXZib+CRwhaE3MIGsBgorBgEEAYI3AgEMMYGdMIGaoIGX
# gIGUAFcAaQBuAGQAbwB3AHMAIAAxADAAIABIAG8AbQBlACAAdABvACAAVwBpAG4A
# ZABvAHcAcwAgADEAMAAgAFAAcgBvACAAZgBvAHIAIABXAG8AcgBrAHMAdABhAHQA
# aQBvAG4AcwAgAGYAdQBsAGwAIABjAG8AbgB2AGUAcgBzAGkAbwBuACAAcwBjAHIA
# aQBwAHQALjANBgkqhkiG9w0BAQEFAASCAQB1F2eawZAp8NE8TsSIZdSv89oCvIaV
# 3MRboXC6ZRnjMe/4p5CiT57QBp4O2M8T+IMHru1MfXhiijkebIGgKRKxfq5m8D8f
# 0na3JRVyksR6xzRNJYj6DSyav+ZgUpVC/08VEWaxUo4O9WWcwTR0Pqb5ELB9PPFe
# USyVcD5uJfWKkUFxLdjKem2SGHjrh+uruIUk1tNbqyyxMorpZ5tsxj4BG0IW+llm
# jbfF21P4ByQvOuAlu7D7U4CloCfiVRsHIrg4aP8hRAOOZlaE3Il9ZWO/iZcTbZhl
# RWwujn7Uv7uK/fB3LIrsCqRntCT3xhz727JGnenf5EOg+jytqIHD6kAf
# SIG # End signature block
