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
		Version:        2.4.6
		Last updated:	04/02/2018
		===========================================================================
#>
[CmdletBinding()]
Param
(
	[Parameter(Mandatory = $true,
			   HelpMessage = 'The path to a Windows Installation ISO or an Install.WIM.')]
	[ValidateScript({
			If ((Test-Path $(Resolve-Path $_) -PathType Leaf) -and ($_ -like "*.iso")) { $_ }
			ElseIf ((Test-Path $(Resolve-Path $_) -PathType Leaf) -and ($_ -like "*.wim")) { $_ }
			Else { Throw "$_ is an invalid image type." }
		})]
	[Alias('ISO', 'WIM')]
	[string]$SourcePath,
	[Parameter(HelpMessage = 'Specify a different save location from default.')]
	[ValidateScript({
			If (Test-Path $(Resolve-Path $_) -PathType Container) { $_ }
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
	If (!($SavePath))
	{
		New-Item -ItemType Directory -Path $Desktop\ConvertTo-PfW"-[$((Get-Date).ToString('MM.dd.yy hh.mm.ss'))]"
	}
	Else
	{
		New-Item -ItemType Directory -Path $SavePath\ConvertTo-PfW"-[$((Get-Date).ToString('MM.dd.yy hh.mm.ss'))]"
	}
}
#endregion Helper Functions

If (!(Verify-Admin))
{
	Throw "This script requires administrative permissions."
}

Try
{
	If ((Test-Path -Path "$PSScriptRoot\Bin\wimlib-imagex.exe") -and (Test-Path -Path "$PSScriptRoot\Bin\libwim-15.dll"))
	{
		Copy-Item -Path "$PSScriptRoot\Bin\wimlib-imagex.exe" -Destination $env:TEMP -Force
		Copy-Item -Path "$PSScriptRoot\Bin\libwim-15.dll" -Destination $env:TEMP -Force
		$Error.Clear()
	}
	Else
	{
		If ((Test-Connection $env:COMPUTERNAME -Quiet) -eq $true)
		{
			Write-Verbose "Wimlib not found. Requesting it from GitHub." -Verbose
			[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"
			$paramWebRequestDll = @{
				Uri	       = "https://github.com/DrEmpiricism/ConvertTo-PfW/blob/master/Bin/libwim-15.dll?raw=true"
				OutFile    = "$env:TEMP\libwim-15.dll"
				TimeoutSec = 15
				ErrorAction = "Stop"
			}
			[void](Invoke-WebRequest @paramWebRequestDll)
			$paramWebRequestExe = @{
				Uri	       = "https://github.com/DrEmpiricism/ConvertTo-PfW/blob/master/Bin/wimlib-imagex.exe?raw=true"
				OutFile    = "$env:TEMP\wimlib-imagex.exe"
				TimeoutSec = 15
				ErrorAction = "Stop"
			}
			[void](Invoke-WebRequest @paramWebRequestExe)
			Write-Output ''
			$Error.Clear()
		}
		Else
		{
			Throw "Unable to retrieve required files. No active connection is available."
		}
	}
}
Catch
{
	Write-Output ''
	Write-Warning "The GitHub web request has timed out."
	Break
}

If (([IO.FileInfo]$SourcePath).Extension -eq ".ISO")
{
	$ResolveISO = (Resolve-Path -Path $SourcePath).Path
	$MountISO = Mount-DiskImage -ImagePath $ResolveISO -StorageType ISO -PassThru
	$DriveLetter = ($MountISO | Get-Volume).DriveLetter
	$InstallWIM = "$($DriveLetter):\sources\install.wim"
	If (Test-Path -Path $InstallWIM)
	{
		Write-Verbose "Copying the WIM from $(Split-Path $ResolveISO -Leaf)." -Verbose
		Copy-Item -Path $InstallWIM -Destination $env:TEMP\install.wim -Force
		Dismount-DiskImage -ImagePath $SourcePath -StorageType ISO
		If (([IO.FileInfo]"$env:TEMP\install.wim").IsReadOnly)
		{
			Set-ItemProperty -Path $env:TEMP\install.wim -Name IsReadOnly -Value $false
		}
		$ImageIsCopied = $true
	}
	Else
	{
		Throw "$SourcePath does not contain valid installation media."
	}
}
ElseIf (([IO.FileInfo]$SourcePath).Extension -eq ".WIM")
{
	$ResolveWIM = (Resolve-Path -Path $SourcePath).Path
	If (Test-Path -Path $ResolveWIM)
	{
		Write-Verbose "Copying the WIM from $(Split-Path $ResolveWIM -Parent)." -Verbose
		Copy-Item -Path $SourcePath -Destination $env:TEMP\install.wim -Force
		If (([IO.FileInfo]"$env:TEMP\install.wim").IsReadOnly)
		{
			Set-ItemProperty -Path $env:TEMP\install.wim -Name IsReadOnly -Value $false
		}
		$ImageIsCopied = $true
	}
}

If ($ImageIsCopied.Equals($true))
{
	$CheckBuild = (Get-WindowsImage -ImagePath $env:TEMP\install.wim -Index 1)
	If ($CheckBuild.Build -lt "16273")
	{
		Write-Output ''
		Throw "The image build [$($CheckBuild.Build.ToString())] is not supported."
	}
	Else
	{
		Write-Output ''
		Write-Output "The image build [$($CheckBuild.Build.ToString())] is supported."
		$BuildIsSupported = $true
	}
}

If (($BuildIsSupported.Equals($true)) -and (Test-Path -Path $env:TEMP\libwim-15.dll) -and (Test-Path -Path $env:TEMP\wimlib-imagex.exe))
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
	$IndexImages = @(
		"Windows 10 S",
		"Windows 10 S N",
		"Windows 10 Home N",
		"Windows 10 Home Single Language",
		"Windows 10 Education",
		"Windows 10 Education N",
		"Windows 10 Pro",
		"Windows 10 Pro N"
	)
	$HomeImage = "Windows 10 Home"
	$ImageInfo = (Get-WindowsImage -ImagePath $ImageFile)
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
}
ElseIf ($ImageInfo.Count.Equals(1) -and $ImageInfo.ImageName.Contains($HomeImage))
{
	Write-Output ''
	Write-Output "$HomeImage detected."
	$Index = "1"
}

Try
{
	Clear-Host
	Write-Verbose "Mounting Image." -Verbose
	[void](Mount-WindowsImage -ImagePath $ImageFile -Index $Index -Path $MountFolder -ScratchDirectory $TempFolder)
	Write-Output ''
	Write-Verbose "Verifying image health." -Verbose
	Start-Sleep 3
	$HealthCheck = (Repair-WindowsImage -Path $MountFolder -CheckHealth -ScratchDirectory $TempFolder)
	If ($HealthCheck.ImageHealthState -eq "Healthy")
	{
		Write-Output ''
		Write-Output "The image has returned as healthy."
		Start-Sleep 3
		Write-Output ''
		Write-Verbose "Changing Image Edition to Windows 10 Pro for Workstations." -Verbose
		[void](Set-WindowsEdition -Path $MountFolder -Edition "ProfessionalWorkstation" -ScratchDirectory $TempFolder -ErrorAction Stop)
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
		Remove-Item $TempFolder -Recurse -Force
		Remove-Item $ImageFolder -Recurse -Force
		Remove-Item $MountFolder -Recurse -Force
		Remove-Item $WorkFolder -Recurse -Force
		Start-Sleep 3
		Break
	}
}
Catch
{
	Write-Output ''
	Write-Warning "An error occured changing the Image Edition. Dismounting and Discarding Image."
	[void](Dismount-WindowsImage -Path $MountFolder -Discard -ScratchDirectory $TempFolder)
	Remove-Item $TempFolder -Recurse -Force
	Remove-Item $ImageFolder -Recurse -Force
	Remove-Item $MountFolder -Recurse -Force
	Remove-Item $WorkFolder -Recurse -Force
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
	$paramConvert = @{
		Command	     = ('CMD.EXE /C $WimLib info $ImageFile $Index "Windows 10 Pro for Workstations" "Windows 10 Pro for Workstations" --image-property DISPLAYNAME="Windows 10 Pro for Workstations" --image-property DISPLAYDESCRIPTION="Windows 10 Pro for Workstations" --image-property FLAGS="ProfessionalWorkstation"')
		ErrorAction  = "Stop"
	}
	[void](Invoke-Expression @paramConvert)
	Write-Output ''
	Write-Output "Conversion successful."
	$ConversionComplete = $true
	Start-Sleep 3
}
Catch
{
	Write-Output ''
	Write-Warning "Unable to convert $HomeImage to Windows 10 Pro for Workstations."
	Remove-Item $TempFolder -Recurse -Force
	Remove-Item $ImageFolder -Recurse -Force
	Remove-Item $MountFolder -Recurse -Force
	Remove-Item $WorkFolder -Recurse -Force
	Break
}

If ($ConversionComplete.Equals($true))
{
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
	Start-Sleep 3
}

Try
{
	If ($ESD)
	{
		Write-Output ''
		Write-Verbose "Exporting Windows 10 Pro for Workstations to an ESD file. This will take some time to complete." -Verbose
		$paramExportESD = @{
			Command	     = ('CMD.EXE /C $WimLib export $ImageFile $Index $WorkFolder\install.esd --solid --check')
			ErrorAction  = "Stop"
		}
		[void](Invoke-Expression @paramExportESD)
	}
	Else
	{
		Write-Output ''
		Write-Verbose "Exporting Windows 10 Pro for Workstations." -Verbose
		$paramExportMaximum = @{
			Command	     = ('CMD.EXE /C $WimLib export $ImageFile $Index $WorkFolder\install.wim --compress="LZX" --check')
			ErrorAction  = "Stop"
		}
		[void](Invoke-Expression @paramExportMaximum)
	}
}
Catch
{
	Write-Output ''
	Write-Warning "Unable to export Windows 10 Pro for Workstations."
	Break
}
Finally
{
	$SaveFolder = Create-SaveDirectory
	Move-Item -Path $WorkFolder\install.wim -Destination $SaveFolder -Force
	Move-Item -Path $WorkFolder\*.cfg -Destination $SaveFolder -Force
	Remove-Item $TempFolder -Recurse -Force
	Remove-Item $ImageFolder -Recurse -Force
	Remove-Item $MountFolder -Recurse -Force
	Remove-Item $WorkFolder -Recurse -Force
	Write-Output ''
	Write-Output "Windows 10 Pro for Workstations saved to: $SaveFolder"
	Start-Sleep 3
	Write-Output ''
}
# SIG # Begin signature block
# MIIJKwYJKoZIhvcNAQcCoIIJHDCCCRgCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUXxSrl1N8Q6mm0X8+TtYzWQuy
# U6SgggYxMIIDFDCCAgCgAwIBAgIQgnJLApNodKpGiwFxYC7KeTAJBgUrDgMCHQUA
# MBgxFjAUBgNVBAMTDU9NTklDLlRFQ0gtQ0EwHhcNMTgwMzEzMTAxNDI3WhcNMzkx
# MjMxMjM1OTU5WjAYMRYwFAYDVQQDEw1PTU5JQy5URUNILUNBMIIBIjANBgkqhkiG
# 9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3DlhtznwS9RYFDwLLneugmUEZecwxytmEZU+
# eXPfC3e7k85aYAhN9UEEhm/VsJB/NAFc5+khXqLVEWcuuD0xnnJholKRft3uP9ng
# L/ebtVbuZR/nz8rSL6X3XrM9htU4sH2a6dzS4ESFbu6z3Xlg3sjrw7QN89XEcFEw
# vKp5okD2sHaqP1AS/yJVNWLovBWY+W/RAWeVvLTjjSflcXNpbp2MgkrOHC65eB6w
# PhgeATjP2/wprl6e2p7sVkRI9hQw6eQdDeWcYuTIY/9u/2uBVnjISnhrh3V58SpI
# n3jV0apM8+H/YfuhEML2l7zc6xQ0358QoWIi9srkqH8sBFkrkQIDAQABo2IwYDAT
# BgNVHSUEDDAKBggrBgEFBQcDAzBJBgNVHQEEQjBAgBB2Tn/VDn5XbZD6/biSSil9
# oRowGDEWMBQGA1UEAxMNT01OSUMuVEVDSC1DQYIQgnJLApNodKpGiwFxYC7KeTAJ
# BgUrDgMCHQUAA4IBAQDJ+S0c+mO4p+DsBF/kZYNqWcgJ3mD1keYX7O7aSEdG1pCX
# +o9l4cj+u4NSGqc1sgO0U0Ftwq9El6Bk8k2YeWxJ8oUD3yQqPv1EXSs6tB53A6zA
# 4nrm/1dmnqqQI9KSvEKZblr9KYTy6AoRcpzEezLM0sFXTaSqHGCPvCYP3Qar6oI7
# eoaO8OkzcNH7dTxuXRrTWQ7IUeAr2/bUAJAbgnjwZpQ/yxdmjOnu+OdBXGtoe8Rv
# G01nyxAj94TaCXsPcV8KxAusML4iEAlkmLsXtnpPY8jfnHpSx/LN0nEA5x3nwqPQ
# DxRy0ZIeHb5ZXAo7v5E+G358O5CQ/TNGt2jGOrHqMIIDFTCCAgGgAwIBAgIQVJ8q
# dzf/f7xETWjhXWNf/jAJBgUrDgMCHQUAMBgxFjAUBgNVBAMTDU9NTklDLlRFQ0gt
# Q0EwHhcNMTgwMzEzMTAyMjA5WhcNMzkxMjMxMjM1OTU5WjAZMRcwFQYDVQQDEw5P
# TU5JQy5URUNIIENTQzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOCR
# mWrJc2EZ6cvOJHj7YQEcijDJ0bLSV+3Gi6G9CB5tKjlubGu9KqzTugTUEzxww6qe
# fE6YSE4XSLevdaOVqcRKmKZ2iwwGIK5VCw54XpQLNBVpDO+3j2tmm3en3zvtb2G0
# 73FO9zio6IyLz+0eoIEiXRTlJow0c1LSLbEitGaG+0YD6gSre5bSz6CWxmAVQqcD
# 2u1YtXGXs7LccHLo/xyJtWgqmo4F+/8GCbN/9OXpgVdGQ0DA04kDFZJ2Jp22+sd4
# gfpyY8lLNURnKqGGHSND9PB4p+uH1KaIL8zULJxOumz7Te3lm/LxkAN/dUye7zFX
# K+Xl1YiT0xfQIgx8yhUCAwEAAaNiMGAwEwYDVR0lBAwwCgYIKwYBBQUHAwMwSQYD
# VR0BBEIwQIAQdk5/1Q5+V22Q+v24kkopfaEaMBgxFjAUBgNVBAMTDU9NTklDLlRF
# Q0gtQ0GCEIJySwKTaHSqRosBcWAuynkwCQYFKw4DAh0FAAOCAQEAMpU5vXMt8BxR
# wTMYnLyNsSGXPoF8PI9LuO+gytZwdzcPPAoU46OczHY/xw6XDxsvI+87ytSAgFBv
# 9/mla+e+9g8AIZUH9wHAGKRbn9pqLST3q+xHtYdrPN+KKOaN4DsL81kCMolNEPMt
# NrG2IqBMiJSKglsNNTHkuPB1yNSw3Ix9W7qTFcoByjObZsZBE9vz90AwyPzTMQwt
# +FiyYwZI1ELp1cGrX1vW3QGnzkdl/h0VEt1SDYvS712tVGRm2U49dF43bSwsKHdA
# sccJgiQaf2tld9QPRWbtUK0PgTosBCpzjsl8MFS7TsHJ2dFGLAHefFqMM+fZgQa8
# iuBBshmR3TGCAmQwggJgAgEBMCwwGDEWMBQGA1UEAxMNT01OSUMuVEVDSC1DQQIQ
# VJ8qdzf/f7xETWjhXWNf/jAJBgUrDgMCGgUAoIIBDTAZBgkqhkiG9w0BCQMxDAYK
# KwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG
# 9w0BCQQxFgQUtRbhBH8JIerwKgUnEezAz8b9chswgawGCisGAQQBgjcCAQwxgZ0w
# gZqggZeAgZQAVwBpAG4AZABvAHcAcwAgADEAMAAgAEgAbwBtAGUAIAB0AG8AIABX
# AGkAbgBkAG8AdwBzACAAMQAwACAAUAByAG8AIABmAG8AcgAgAFcAbwByAGsAcwB0
# AGEAdABpAG8AbgBzACAAZgB1AGwAbAAgAGMAbwBuAHYAZQByAHMAaQBvAG4AIABz
# AGMAcgBpAHAAdAAuMA0GCSqGSIb3DQEBAQUABIIBAGu0AiNyJmw54X17HdATgmwL
# uEQuJeqZ9Wjo+gM1eYWm2ZBi5Nxhq9Pn2cTo6EbJ/i09OdokZ7dudV2Y2ZQJCrZ+
# 77Nv526SUDY/uR6tE+bnQBKEQl7ccBaqSEv9TVa1tnughFZ1SLaDfdcF4NYPxS9i
# 1b3uyO47LRTa2iRLkVqt1t22TYgAcqtfIGm0iTQqO8Gx5fK5FvK0gfFQaki8/qFY
# GUFaIfezWAASQYcx2YYj5GKQECaaUizI4JAk3RyaS3Tr+jvwJL4Bw3mg+uLK9id3
# MTMSeOcK0kuuGdPbvRwB00y2zmklwCW1goPnrXoCBU742+38Q8bphXkiQikNkaI=
# SIG # End signature block
