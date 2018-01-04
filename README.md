# Overview
- Legitimately converts Windows 10 Home to Windows 10 Pro for Workstations.
- Does NOT perform any actions that are against Microsoft's Terms of Service or in any ways illegal.
- Microsoft offers a free Media Creation Tool for v1709 that will download their Fall Creator's Update v1709.
- There are other legitimate 3rd party sources where this media can also be obtained.

# How to run it
- Drag and drop an ISO or WIM file onto the ConvertTo-PfW.exe

# How it works
- If an Install.WIM is supplied, it will copy it to a temporary directory.
- If an ISO is supplied, it will mount the ISO, copy the Install.WIM to a temporary directory, then dismount the ISO.
- Detects the Windows 10 Home index image within the WIM.
- Changes the WIM's Edition ID to Windows 10 Pro for Workstations.
- Converts the WIM's default XML values to Windows 10 Pro for Workstations specific values.
- Generates a Windows 10 Pro for Workstations EI.CFG
- Exports the new Windows 10 Pro for Workstations WIM, EI.CFG and XML info to the user's desktop.

# Requirements
- Windows 10 Home Fall Creator's Update ISO media or Install.WIM (All-in-One or Single-Index).

# Notes
- If the ImageX.exe is not detected in the script's root directory, the script will attempt to download the ImageX encoded Base64 file from this repository to use.
