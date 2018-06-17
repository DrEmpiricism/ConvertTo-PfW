# Overview
- Legitimately converts Windows 10 Home version 1709+ to Windows 10 Pro for Workstations.
- Does NOT perform any actions that are against Microsoft's Terms of Service or in any ways illegal.

# How to run the executable
- Download the ConvertTo-PfW.exe.
- Unblock the download.
- Drag and drop an ISO or WIM file onto the ConvertTo-PfW.exe
- Let it run until completion.

# How it works
- Detects the Windows 10 Home index image within the supplied image.
- Changes the Windows 10 Home Edition ID to Windows 10 Pro for Workstations.
- Uses WimGapi and P/Invoke to natively access and retrieve the WIM's XMDocument metadata and then converts the default XML values to Windows 10 Pro for Workstations specific values.
- Generates a Windows 10 Pro for Workstations EI.CFG.
- Allows for ESD final image compression.
- Exports the new Windows 10 Pro for Workstations WIM (or ESD) and EI.CFG to the desktop.

# Requirements
- Windows 10 ISO media or an install.wim (All-in-One or Single-Index) version 1709-1809+ (RS3-RS5)
