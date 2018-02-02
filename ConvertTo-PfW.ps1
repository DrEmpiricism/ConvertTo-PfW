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
		Version:        2.3
		Last updated:	01/31/2018
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

If (Test-Path -Path "$PSScriptRoot\imagex.exe")
{
	Copy-Item -Path "$PSScriptRoot\imagex.exe" -Destination $env:TEMP -Force
	$Error.Clear()
	Clear-Host
}
ElseIf (Test-Path -Path "$PSSciptRoot\Encoded\imagex.txt")
{
	Copy-Item -Path "$PSSciptRoot\Encoded\imagex.txt" -Destination $env:TEMP -Force
	$FileContent = Get-Content -Path $env:TEMP\imagex.txt
	$FileContentDecoded = [System.Convert]::FromBase64String($FileContent)
	Set-Content -Path $env:TEMP\imagex.exe -Value $FileContentDecoded -Encoding Byte
	Remove-Item -Path $env:TEMP\imagex.txt -Force
	$Error.Clear()
	Clear-Host
}
Else
{
	If ((Test-Connection $env:COMPUTERNAME -Quiet) -eq $true)
	{
		(Invoke-WebRequest https://raw.githubusercontent.com/DrEmpiricism/ConvertTo-PfW/master/Encoded/imagex.txt).Content | Set-Content -Path $env:TEMP\imagex.txt
		$FileContent = Get-Content -Path $env:TEMP\imagex.txt
		$FileContentDecoded = [System.Convert]::FromBase64String($FileContent)
		Set-Content -Path $env:TEMP\imagex.exe -Value $FileContentDecoded -Encoding Byte
		Remove-Item -Path $env:TEMP\imagex.txt -Force
		$Error.Clear()
		Clear-Host
	}
	Else
	{
		Throw "Unable to detect or retrieve ImageX.exe."
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

If ((Test-Path -Path $env:TEMP\install.wim) -and (Test-Path -Path $env:TEMP\imagex.exe))
{
	[void]($WorkFolder = Create-WorkDirectory)
	[void]($TempFolder = Create-TempDirectory)
	[void]($ImageFolder = Create-ImageDirectory)
	[void]($MountFolder = Create-MountDirectory)
	Move-Item -Path $env:TEMP\install.wim -Destination $ImageFolder -Force
	Move-Item -Path $env:TEMP\imagex.exe -Destination $ImageFolder -Force
	$ImageFile = "$ImageFolder\install.wim"
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
		[void]($ImageInfo.Where({ $_.ImageName -contains $IndexImage }) | Remove-WindowsImage -ImagePath $ImageFile -Name $IndexImage)
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
	Throw "$HomeImage not detected."
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
Catch [System.IO.IOException]
{
	Write-Output ''
	Write-Error -Message "Unable to change Image Edition to Windows 10 Pro for Workstations." -Category WriteError
	Break
}

Try
{
	Write-Output ''
	Write-Verbose "Converting $HomeImage to Windows 10 Pro for Workstations." -Verbose
	Start-Process -Filepath CMD.exe -WorkingDirectory $ImageFolder -ArgumentList ('/c imagex /Info install.wim 1 "Windows 10 Pro for Workstations" "Windows 10 Pro for Workstations" /Flags ProfessionalWorkstation') -Verb runas -WindowStyle Hidden -Wait
	Write-Output ''
	Write-Output "Conversion successful."
	$ConversionComplete = $true
	Start-Sleep 3
}
Catch [System.ArgumentException]
{
	Write-Output ''
	Write-Error -Message "Unable to convert $HomeImage to Windows 10 Pro for Workstations." -Category InvalidArgument
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

If ($ESD)
{
	Write-Output ''
	Write-Verbose "Exporting and compressing Windows 10 Pro for Workstations into an ESD file. This will take a while." -Verbose
	[void](DISM /Export-Image /SourceImageFile:$ImageFile /SourceIndex:$Index /DestinationImageFile:$WorkFolder\install.esd /Compress:Recovery /CheckIntegrity)
	[void](Clear-WindowsCorruptMountPoint)
	$SaveFolder = Create-SaveDirectory
	Move-Item -Path $WorkFolder\install.esd -Destination $SaveFolder -Force
}
Else
{
	Write-Output ''
	Write-Verbose "Exporting and compressing Windows 10 Pro for Workstations." -Verbose
	[void](Export-WindowsImage -CheckIntegrity -CompressionType maximum -SourceImagePath $ImageFile -SourceIndex $Index -DestinationImagePath $WorkFolder\install.wim -ScratchDirectory $TempFolder)
	[void](Clear-WindowsCorruptMountPoint)
	$SaveFolder = Create-SaveDirectory
	Move-Item -Path $WorkFolder\install.wim -Destination $SaveFolder -Force
}
Move-Item -Path $WorkFolder\*.CFG -Destination $SaveFolder -Force
Remove-Item $TempFolder -Recurse -Force
Remove-Item $ImageFolder -Recurse -Force
Remove-Item $MountFolder -Recurse -Force
Remove-Item $WorkFolder -Recurse -Force
Write-Output ''
Write-Output "Windows 10 Pro for Workstations saved to $SaveFolder"
Start-Sleep 3
Write-Output ''
