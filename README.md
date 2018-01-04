# Overview
- Legitimately converts Windows 10 Home to Windows 10 Pro for Workstations.
- Does NOT perform any actions that are against Microsoft's Terms of Service or in any ways illegal.
- Microsoft offers a free Media Creation Tool for v1709 that will download their Fall Creator's Update v1709.
- There are other legitimate 3rd party sources where this media can also be obtained.

# How to run the executable
- Download the ConvertTo-PfW.exe.
- Unblock the download.
- Drag and drop an ISO or WIM file onto the ConvertTo-PfW.exe
- Let it run until completion.

# How to run the script
- Open an elevated PowerShell console and navigate to the root location of the ConvertTo-PfW.ps1
- Execute the script by pointing it to the ISO/WIM file.
-         .\ConvertTo-PfW.ps1 -SourcePath "Path to ISO or WIM file"
- Or use the Run.cmd batch script to automatically call the script (must set the ISO/WIM file variable in the batch script first).

# How it works
- If an Install.WIM is supplied, it will copy it to a temporary directory.
- If an ISO is supplied, it will mount the ISO, copy the Install.WIM to a temporary directory, then dismount the ISO.
- Detects the Windows 10 Home index image within the WIM.
- Changes the WIM's Edition ID to Windows 10 Pro for Workstations.
- Converts the WIM's default XML values to Windows 10 Pro for Workstations specific values.
- Generates a Windows 10 Pro for Workstations EI.CFG
- Exports the new Windows 10 Pro for Workstations WIM and EI.CFG to the user's desktop.

# Requirements for the executable
- Windows 10 Home Fall Creator's Update ISO media or Install.WIM (All-in-One or Single-Index).
- An active internet connection.

# Requirements for the script
- Windows 10 Home Fall Creator's Update ISO media or Install.WIM (All-in-One or Single-Index).

# Notes
-  An active internet connection allows the executable to automatically download the Base64 encoded ImageX.txt file from this repository.
