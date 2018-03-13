# Overview
- Legitimately converts Windows 10 Home to Windows 10 Pro for Workstations.
- Does NOT perform any actions that are against Microsoft's Terms of Service or in any ways illegal.
- Microsoft offers a free Media Creation Tool for v1709 that will download their Fall Creator's Update v1709.
- There are other legitimate 3rd party sources where this media can also be obtained.

# How to run the script
- Open an elevated PowerShell console and navigate to the root location of the ConvertTo-PfW.ps1
- Execute the script by pointing it to the ISO/WIM file:
-         .\ConvertTo-PfW.ps1 -SourcePath "Path to ISO or WIM file"
- You can also supply a different final Install.WIM save location by using the parameter '-SavePath "Path to save location"'
- By using the -ESD switch, the script will export and compress the saved image into an ESD file instead of the default WIM file.
 **Be aware that ESD compression can take quite a while to complete and is also system intensive. If you are limited in time, or have an older device, it's probably better to stick with the default WIM file.**
-         .\ConvertTo-PfW.ps1 -SourcePath "Path to ISO or WIM file" -SavePath "Path to save location" -ESD
- Or use the Run.cmd batch script to automatically call the script (must set the ISO/WIM file variable in the batch script first).

# How it works
- If an Install.WIM is supplied, it will copy it to a temporary directory.
- If an ISO is supplied, it will mount the ISO, copy the Install.WIM to a temporary directory, then dismount the ISO.
- Detects the Windows 10 Home index image within the WIM.
- Changes the WIM's Edition ID to Windows 10 Pro for Workstations.
- Converts the WIM's default XML values to Windows 10 Pro for Workstations specific values.
- Generates a Windows 10 Pro for Workstations EI.CFG
- Exports the new Windows 10 Pro for Workstations WIM and EI.CFG to the user's desktop or the specified SavePath.

# How is the executable version different from the script version?
- The executable uses C# code, which utilizes the WimGapi.dll, to natively access the WIM file's handle where it can access the XMDocument metadata. This metadata is then retrieved and set using a PowerShell function wrapper.
- Simply drag and drop a WIM file or ISO onto the .EXE to begin the conversion process.

# Requirements
- Windows 10 Home Fall Creator's Update ISO media or Install.WIM (All-in-One or Single-Index), that contains Windows 10 Home (Core).
