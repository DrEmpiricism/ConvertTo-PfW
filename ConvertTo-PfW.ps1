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
		Version:        2.4.1
		Last updated:	02/10/2018
		===========================================================================
#>
[CmdletBinding()]
Param
(
	[Parameter(Mandatory = $true,
			   HelpMessage = 'The path to a Windows Installation ISO or an Install.WIM.')][ValidateScript({
			If ((Test-Path $(Resolve-Path $_) -PathType Leaf) -and ($_ -like "*.iso")) { $_ }
			ElseIf ((Test-Path $(Resolve-Path $_) -PathType Leaf) -and ($_ -like "*.wim")) { $_ }
			Else { Throw "$_ is an invalid image type." }
		})][Alias('ISO', 'WIM')][string]$SourcePath,
	[Parameter(HelpMessage = 'Specify a different save location from default.')][ValidateScript({
			If (Test-Path $(Resolve-Path $_) -PathType Container) { $_ }
			Else { Throw "$_ is an invalid save path." }
		})][Alias('Save')][string]$SavePath,
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

Function Load-SoftwareHive
{
	[void](REG LOAD HKLM\WIM_HKLM_SOFTWARE "$MountFolder\windows\system32\config\software")
}

Function Unload-SoftwareHive
{
	Start-Sleep 3
	[System.GC]::Collect()
	[void](REG UNLOAD HKLM\WIM_HKLM_SOFTWARE)
}

Function Verify-SoftwareHive
{
	[CmdletBinding()]
	Param ()
	
	$HivePath = @(
		"HKLM:\WIM_HKLM_SOFTWARE"
	) | % { $SoftwareHiveLoaded = ((Test-Path -Path $_) -eq $true) }; Return $SoftwareHiveLoaded
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
		Write-Verbose "Wimlib not found. Grabbing it from GitHub." -Verbose
		[void](Invoke-WebRequest -Uri "https://github.com/DrEmpiricism/ConvertTo-PfW/blob/master/Bin/libwim-15.dll?raw=true" -OutFile $env:TEMP\libwim-15.dll)
		[void](Invoke-WebRequest -Uri "https://github.com/DrEmpiricism/ConvertTo-PfW/blob/master/Bin/wimlib-imagex.exe?raw=true" -OutFile $env:TEMP\wimlib-imagex.exe)
		$Error.Clear()
		Clear-Host
	}
	Else
	{
		Throw "Unable to retrieve required files. No active connection is available."
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

If (!($ImageInfo.ImageName.Contains($HomeImage)))
{
	Remove-Item $TempFolder -Recurse -Force
	Remove-Item $ImageFolder -Recurse -Force
	Remove-Item $MountFolder -Recurse -Force
	Remove-Item $WorkFolder -Recurse -Force
	Throw "$HomeImage not detected."
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
	Write-Output ''
	Write-Verbose "Mounting Image." -Verbose
	[void](Mount-WindowsImage -ImagePath $ImageFile -Index $Index -Path $MountFolder -ScratchDirectory $TempFolder)
}
ElseIf ($ImageInfo.Count -eq "1" -and $ImageInfo.ImageName.Contains($HomeImage))
{
	Write-Output ''
	Write-Output "$HomeImage detected."
	$Index = "1"
	Write-Output ''
	Write-Verbose "Mounting Image." -Verbose
	[void](Mount-WindowsImage -ImagePath $ImageFile -Index $Index -Path $MountFolder -ScratchDirectory $TempFolder)
}

Try
{
	[void](Load-SoftwareHive)
	$WIMProperties = Get-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows NT\CurrentVersion"
	Write-Output ''
	Write-Verbose "Verifying image build." -Verbose
	Start-Sleep 3
	If ($WIMProperties.CurrentBuildNumber -ge "16273")
	{
		Write-Output ''
		Write-Output "The image build [$($WIMProperties.CurrentBuildNumber)] is supported."
		Start-Sleep 3
		[void](Unload-SoftwareHive)
	}
	Else
	{
		Write-Warning "The image build [$($WIMProperties.CurrentBuildNumber)] is not supported."
		Break
	}
}
Catch
{
	If (Verify-SoftwareHive)
	{
		[void](Unload-SoftwareHive)
	}
	Write-Output ''
	Write-Output "Dismounting and discarding image."
	[void](Dismount-WindowsImage -Path $MountFolder -Discard -ScratchDirectory $TempFolder)
	[void](Clear-WindowsCorruptMountPoint)
	Remove-Item $TempFolder -Recurse -Force
	Remove-Item $ImageFolder -Recurse -Force
	Remove-Item $MountFolder -Recurse -Force
	Remove-Item $WorkFolder -Recurse -Force
	Break; Exit
}

Try
{
	Write-Output ''
	Write-Verbose "Verifying image health." -Verbose
	Start-Sleep 3
	$ScriptStartHealthCheck = Repair-WindowsImage -Path $MountFolder -CheckHealth
	If ($ScriptStartHealthCheck.ImageHealthState -eq "Healthy")
	{
		Write-Output ''
		Write-Output "The image has returned as healthy."
		Start-Sleep 3
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
	}
	Else
	{
		Write-Output ''
		Write-Warning "The image has been flagged for corruption. Further servicing is required."
		Start-Sleep 3
		Write-Output ''
		Write-Output "Dismounting and discarding image."
		[void](Dismount-WindowsImage -Path $MountFolder -Discard -ScratchDirectory $TempFolder)
		[void](Clear-WindowsCorruptMountPoint)
		Remove-Item $TempFolder -Recurse -Force
		Remove-Item $ImageFolder -Recurse -Force
		Remove-Item $MountFolder -Recurse -Force
		Remove-Item $WorkFolder -Recurse -Force
		Break
	}
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
	Break; Exit
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
	Break; Exit
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
	$DefaultSavePath = $Desktop.Split("\")[-1] + "\" + $SaveFolder.Name
	$CustomSavePath = $SaveFolder.Parent.Name + "\" + $SaveFolder.Name
	Move-Item -Path $WorkFolder\*.CFG -Destination $SaveFolder -Force
	Remove-Item $TempFolder -Recurse -Force
	Remove-Item $ImageFolder -Recurse -Force
	Remove-Item $MountFolder -Recurse -Force
	Remove-Item $WorkFolder -Recurse -Force
	Write-Output ''
	If ($DefaultSavePath.Equals($CustomSavePath))
	{
		Write-Output "Windows 10 Pro for Workstations saved to: $($DefaultSavePath)"
	}
	Else
	{
		Write-Output "Windows 10 Pro for Workstations saved to: $($CustomSavePath)"
	}
	Start-Sleep 3
	Write-Output ''
}
# SIG # Begin signature block
# MIIMEgYJKoZIhvcNAQcCoIIMAzCCC/8CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQURGe/EgoCfLYndh+z9Z5pkXRk
# XESgggjmMIIDaTCCAlGgAwIBAgIQb3wGgV/z161BGZ7IsR60pjANBgkqhkiG9w0B
# AQsFADBHMRQwEgYKCZImiZPyLGQBGRYEVEVDSDEVMBMGCgmSJomT8ixkARkWBU9N
# TklDMRgwFgYDVQQDEw9PTU5JQy1ET1JBRE8tQ0EwHhcNMTgwMjA4MTY0MDU3WhcN
# MjMwMjA4MTY1MDU3WjBHMRQwEgYKCZImiZPyLGQBGRYEVEVDSDEVMBMGCgmSJomT
# 8ixkARkWBU9NTklDMRgwFgYDVQQDEw9PTU5JQy1ET1JBRE8tQ0EwggEiMA0GCSqG
# SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDDsQ+hzIyZ6FHC6IUCOhXEgjt5TrxUFn0w
# nC9f1nw5MyVpI8wK7J3SoCbjPsgBUnfK/i50o/NhPXfR+ekOE7XR+yO3PIWIWTvv
# 9EFtCM4u94tw7jxGpSU9pQweAWzkP8QBjbttWu51TIER6clMyyxojTj8SQZgxNqz
# 4jIdDJiC7j+MS6HrH4ql/C3GIdHZhHIdStPGRvPHgfp8pm9Hyr5UWepGV2onn8Eb
# 1eQawDyhLTIA842gdMO4gF+jQE7+zGg5IVq5BL2aReEKkqnby+HjlqW+a9AOS6Jw
# idAUwF7OrrhtoWUUOdzYUs1WPxRQAtilyU3gdoqyGfUfcE1l4rl1AgMBAAGjUTBP
# MAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRbtzbutgPm
# KPNKNYQYqIkQkCaJ6zAQBgkrBgEEAYI3FQEEAwIBADANBgkqhkiG9w0BAQsFAAOC
# AQEAmO3Nw5TEi+sgkMqBtEw6kur2kED8S6lOvaOWXB3Kp5mVMsD8Fo9MQYMM9SxE
# JsYvGJryRye4nu0OIwv95ojs/ieOVsKwg11/spo7elByto1K0Z6iDXXHOMTme/M0
# Ye3V5DWJoQnRksRMjPeW1tpz3E/FH9qYzvQQv7bb6lU5Q7LqYt7n2jRcM6sDaVXc
# cOVsgdb8Aih0ye7awgmhJHKzOQ9aUMlI8W6RtHvapK3rGTRNdZZCVifKjKvmPks9
# 5iZnRbuqc7QiQF0H3hIWNKATVLLjjkotZrWW4LzC87072nFwg0g13+ooan18418I
# eMVVOeAbkcNcCK1C3GcEDo8rsDCCBXUwggRdoAMCAQICE1kAAAACZ/v40yjR9ngA
# AAAAAAIwDQYJKoZIhvcNAQELBQAwRzEUMBIGCgmSJomT8ixkARkWBFRFQ0gxFTAT
# BgoJkiaJk/IsZAEZFgVPTU5JQzEYMBYGA1UEAxMPT01OSUMtRE9SQURPLUNBMB4X
# DTE4MDIwODE2NDgxM1oXDTE5MDIwODE2NDgxM1owTzEUMBIGCgmSJomT8ixkARkW
# BFRFQ0gxFTATBgoJkiaJk/IsZAEZFgVPTU5JQzEOMAwGA1UEAxMFVXNlcnMxEDAO
# BgNVBAMTB0dvZEhhbmQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCh
# 7439JFXgYkodIc/cHohJWJp+k2Rg/015cl9qWI5+2kuV/W3txB05uaHiQIFJKmr5
# nsOPo/zG8RYgTRq6lXqLg6LGPVIE7DcCJwjDGB4Fr4KPTD6iU/bss2uFmewdc28a
# qO9pvKPQTrqqoqc1e7ASuJRiKpIwJ7ojGmFfdatsWMiak46RBtKLM++WgoohvF0y
# OlxwFTAo4bKIYW6yF4vUdLOSUs//FHlRN8ONkpJIDGvez+pvntCdypt8SFxokGiW
# w6DBnnmI2q10NZK2zuINfxYXHG9M2hylXHLSbCQEsrUfeOTC90gFw5Wmxbp3p+F4
# HpkpkG6i0FiuwwYN2gHTAgMBAAGjggJQMIICTDAlBgkrBgEEAYI3FAIEGB4WAEMA
# bwBkAGUAUwBpAGcAbgBpAG4AZzATBgNVHSUEDDAKBggrBgEFBQcDAzAOBgNVHQ8B
# Af8EBAMCB4AwHQYDVR0OBBYEFNs11f6VTYfS2x4exRBfPD5g38OcMB8GA1UdIwQY
# MBaAFFu3Nu62A+Yo80o1hBioiRCQJonrMIHLBgNVHR8EgcMwgcAwgb2ggbqggbeG
# gbRsZGFwOi8vL0NOPU9NTklDLURPUkFETy1DQSxDTj1ET1JBRE8sQ049Q0RQLENO
# PVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3Vy
# YXRpb24sREM9T01OSUMsREM9VEVDSD9jZXJ0aWZpY2F0ZVJldm9jYXRpb25MaXN0
# P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JMRGlzdHJpYnV0aW9uUG9pbnQwgcAGCCsGAQUF
# BwEBBIGzMIGwMIGtBggrBgEFBQcwAoaBoGxkYXA6Ly8vQ049T01OSUMtRE9SQURP
# LUNBLENOPUFJQSxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNl
# cyxDTj1Db25maWd1cmF0aW9uLERDPU9NTklDLERDPVRFQ0g/Y0FDZXJ0aWZpY2F0
# ZT9iYXNlP29iamVjdENsYXNzPWNlcnRpZmljYXRpb25BdXRob3JpdHkwLQYDVR0R
# BCYwJKAiBgorBgEEAYI3FAIDoBQMEkdvZEhhbmRAT01OSUMuVEVDSDANBgkqhkiG
# 9w0BAQsFAAOCAQEAhcC7Tr1GtakUzANpsAY9wTnuiCDkPx/fYQSi5bcSOda+0dDp
# IMs+8ZPopwwZd6ieRueB78BZiKPSghdGi2P/8eQdsJ1rbbb12iOzuaGdk61uTP6X
# /LVPEpa/BTs12GH4B5Bo/A9MA2b1Q0adgit0bFC32/5/6azpxpDPqi9ItVpOfXgD
# NMfuUzENYw7reZMGdRasF7Hb9E786CNfQQTDFysOBIVD5Tg2yMASu4vE/ppS/ufO
# Wc4jOR6xcGXSMurr4UzN+jhcQBpXRZhvF1fOxkGMYuJLKqJmGEonrrhubHKsAZvM
# wRKGMCf0QeLfj6cOKPGi0m9yI0JfyqUzVkyJEzGCApYwggKSAgEBMF4wRzEUMBIG
# CgmSJomT8ixkARkWBFRFQ0gxFTATBgoJkiaJk/IsZAEZFgVPTU5JQzEYMBYGA1UE
# AxMPT01OSUMtRE9SQURPLUNBAhNZAAAAAmf7+NMo0fZ4AAAAAAACMAkGBSsOAwIa
# BQCgggENMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsx
# DjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBRt48qt4MDl/2mHFIObQr5k
# TFh3WjCBrAYKKwYBBAGCNwIBDDGBnTCBmqCBl4CBlABXAGkAbgBkAG8AdwBzACAA
# MQAwACAASABvAG0AZQAgAHQAbwAgAFcAaQBuAGQAbwB3AHMAIAAxADAAIABQAHIA
# bwAgAGYAbwByACAAVwBvAHIAawBzAHQAYQB0AGkAbwBuAHMAIABmAHUAbABsACAA
# YwBvAG4AdgBlAHIAcwBpAG8AbgAgAHMAYwByAGkAcAB0AC4wDQYJKoZIhvcNAQEB
# BQAEggEAaxcyq1ZigJ04n+75ta76LlTna3s75fOj5ZRYp7T4Q8tMxBt9dUAr75bH
# 3F40GsGieaETwBhcEtc+lj/P96fTsKpxqjPtkurSVGxb8q0PSS9neat6hTz4Q3NF
# Kp+kg6gVlH16ypJbVxxtLW5Lt9FSnC5iU7VR60PjmnGUUMorTGQDo9AjRTCE754j
# utbgmv4BMYxLcCy6996MqKHY7DQWjsSeZgy6W5oQvOMm8rr/wvEjOKZk0E8LF8eS
# IqjKB3HD7/PjEYk+bHl1OAUxz6msXp474Hu2sfkfBOo1nOnNVfuxrc6OrVc4kFT4
# UD0ZPR+TzPXFOzFV4PYHTeDsVt0UyA==
# SIG # End signature block
