# Overview
- Legitimately converts Windows 10 Home to Windows 10 Pro for Workstations.
- Does NOT perform any actions that are against Microsoft's Terms of Service or in any ways illegal.
- Microsoft offers a free Media Creation Tool for v1709+ that will download their Fall Creator's Update v1709.
- There are other legitimate 3rd party sources where this media can also be obtained.

# How to run the script
- Open an elevated PowerShell console and navigate to the root location of the ConvertTo-PfW.ps1
- Execute the script by pointing it to the ISO/WIM file:
-         .\ConvertTo-PfW.ps1 -SourcePath "E:\Windows 10 Fall.iso"
- You can also supply a different final save location by using the parameter '-SavePath "Path to save location"'
- By using the -ESD switch, the script will export and compress the saved image into an ESD file instead of the default WIM file.
 **Be aware that ESD compression can take quite a while to complete and is also system intensive. If you are limited in time, or have an older device, it's probably better to stick with the default WIM file.**
-         .\ConvertTo-PfW.ps1 -SourcePath "Path to ISO or WIM file" -SavePath "Path to save location" -ESD
- Or use the Run.cmd batch script to automatically call the script (must set the ISO/WIM file variable in the batch script first).

# How it works
- Copies the Windows Installation WIM file from the supplied source path.
- Detects the Windows 10 Home index image within the WIM, thus supplied images can be single-index or multi-index.
- Checks the health of the image before continuing with the conversion process.
- Changes the Windows 10 Home Edition ID to Windows 10 Pro for Workstations.
- Converts the Windows 10 Home default XML values to Windows 10 Pro for Workstations specific values.
- Generates a Windows 10 Pro for Workstations EI.CFG
- Exports the new Windows 10 Pro for Workstations WIM and EI.CFG to the user's desktop or the specified SavePath.

# How is the executable version different from the script version?
- The executable requires no additional files and runs completely independently.
- The executable uses C# code, utilizing the WimGapi.dll and a safe-handle class, to natively access the WIM file's handle where it can access and retrieve the XMDocument metadata of the image.
- It supports drag and drop of a WIM file or an ISO file onto the .EXE, which will automatically begin the conversion process.
- Allows for final compression selection.

# Requirements
- Windows 10 Home RS3-RS5 ISO media, or an RS3-RS5 install.wim (All-in-One or Single-Index) that contains Windows 10 Home (Core).
