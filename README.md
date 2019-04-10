# Overview
- Fully converts an ISO or WIM containing Windows 10 Home version 1709+ to a full Windows 10 Pro for Workstations image.
- Does NOT perform any actions that are against Microsoft's Terms of Service or in any ways illegal.
- Microsoft offers a free Media Creation Tool for v1709+ that will download their Fall Creator's Update v1709.
- There are other legitimate 3rd party sources where this media can also be obtained.

# How it works
- Copies the Windows Installation WIM file from the supplied source path.
- Detects the Windows 10 Home index image within the WIM, thus supplied images can be single-index or multi-index.
- Checks the health of the image before continuing with the conversion process.
- Changes the Windows 10 Home Edition ID to Windows 10 Pro for Workstations.
- Converts the Windows 10 Home default XML metadata values to Windows 10 Pro for Workstations specific values.
- Generates a Windows 10 Pro for Workstations EI.CFG
- Exports the new Windows 10 Pro for Workstations WIM, EI.CFG and log files to a folder on the user's desktop.

# Executable specifics
- The executable requires no additional files and runs completely independently.
- The executable uses C# code, utilizing the WimGapi.dll and a safe-handle class, to natively access the WIM file's handle where it can access and retrieve the XMDocument metadata of the image.
- It supports drag and drop of a WIM file or an ISO file onto the .EXE, which will automatically begin the conversion process.
- Allows for final compression selection.

# Requirements
- Windows 10 RS3 (1709) and above ISO/WIM installation media that contains Windows 10 Home (Core).
