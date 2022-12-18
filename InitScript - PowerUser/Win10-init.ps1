# Windows 10 init script for power users

# Relaunch the script with administrator privileges
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
  Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $PSCommandArgs" -Verb RunAs
  Exit
}

Rename-Computer -NewName "Dragon-V4"

# Disable PowerThrottling
# Write-Output "Disabling PowerThrottling..."
# Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" -Name "PowerThrottlingOff" -Type DWord -Value 00000001

# Check if winget is installed
if (Test-Path ~\AppData\Local\Microsoft\WindowsApps\winget.exe){
  'Winget Already Installed'
}
else{
  # Installing winget from the Microsoft Store
  Write-Host "Winget not found, installing it now."
  Start-Process "ms-appinstaller:?source=https://aka.ms/getwinget"
  $nid = (Get-Process AppInstaller).Id
  Wait-Process -Id $nid
  Write-Host "Winget Installed - Ready for Next Task"
}

# install windows terminal
# winget install Microsoft.WindowsTerminal

# Set current network profile to private (allow file sharing, device discovery, etc.)
Write-Output "Setting current network profile to private..."
Set-NetConnectionProfile -NetworkCategory Private

# Disable ipv6
Write-Output "Disabling IPv6 stack..."
Disable-NetAdapterBinding -Name "*" -ComponentID "ms_tcpip6"

# Disable automatic reboot on crash (BSOD)
Write-Output "Disabling automatic reboot on crash (BSOD)..."
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "AutoReboot" -Type DWord -Value 0

# Enable F8 boot menu options
Write-Output "Enabling F8 boot menu options..."
bcdedit /set `{current`} BootMenuPolicy Legacy | Out-Null

# Disable automatic recovery mode during boot
# This causes boot process to always ignore startup errors and attempt to boot normally
# It is still possible to interrupt the boot and enter recovery mode manually. In order to disable even that, apply also DisableRecoveryAndReset tweak
Write-Output "Disabling automatic recovery mode during boot..."
bcdedit /set `{current`} BootStatusPolicy IgnoreAllFailures | Out-Null

# Show full directory path in Explorer title bar
Write-Output "Showing full directory path in Explorer title bar..."
If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\CabinetState")) {
  New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\CabinetState" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\CabinetState" -Name "FullPath" -Type DWord -Value 1

# Enable sharing mapped drives between users
Write-Output "Enabling sharing mapped drives between users..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLinkedConnections" -Type DWord -Value 1

# Show empty drives (with no media)
Write-Output "Showing empty drives (with no media)..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideDrivesWithNoMedia" -Type DWord -Value 0

# Show coloring of encrypted or compressed NTFS files (green for encrypted, blue for compressed)
Write-Output "Showing coloring of encrypted or compressed NTFS files..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowEncryptCompressedColor" -Type DWord -Value 1

# Enable Remote Desktop
Write-Output "Enabling Remote Desktop..."
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Type DWord -Value 0
Enable-NetFirewallRule -Name "RemoteDesktop*"

# Enable Windows Script Host
Write-Output "Enabling Windows Script Host..."
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -ErrorAction SilentlyContinue

# Enable Dark Theme
Write-Output "Enabling Dark Theme..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Type DWord -Value 0

# Set Dark Mode for System - Applicable since 1903
Write-Output "Setting Dark Mode for System..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Type DWord -Value 0

# Enable offering of Malicious Software Removal Tool through Windows Update
Write-Output "Enabling Malicious Software Removal Tool offering..."
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT" -Name "DontOfferThroughWUAU" -ErrorAction SilentlyContinue

# Enable receiving updates for other Microsoft products via Windows Update
Write-Output "Enabling updates for other Microsoft products..."
(New-Object -ComObject Microsoft.Update.ServiceManager).AddService2("7971f918-a847-4430-9279-4a52d1efe18d", 7, "") | Out-Null

# Enable Developer Mode
Write-Output "Enabling Developer Mode..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowDevelopmentWithoutDevLicense" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowAllTrustedApps" -Type DWord -Value 1

# Set Command prompt instead of PowerShell in Start Button context menu (Win+X) - Default in 1507 - 1607
Write-Output "Setting Command prompt instead of PowerShell in WinX menu..."
If ([System.Environment]::OSVersion.Version.Build -le 14393) {
  Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DontUsePowerShellOnWinX" -ErrorAction SilentlyContinue
} Else {
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DontUsePowerShellOnWinX" -Type DWord -Value 1
}

# Install .NET Framework 2.0, 3.0 and 3.5 runtimes - Requires internet connection
Write-Output "Installing .NET Framework 2.0, 3.0 and 3.5 runtimes..."
If ((Get-CimInstance -Class "Win32_OperatingSystem").ProductType -eq 1) {
  Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "NetFx3" } | Enable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue | Out-Null
} Else {
  Install-WindowsFeature -Name "NET-Framework-Core" -WarningAction SilentlyContinue | Out-Null
}

# # Install OpenSSH Client - Applicable since 1803
# Write-Output "Installing OpenSSH Client..."
# Get-WindowsCapability -Online | Where-Object { $_.Name -like "OpenSSH.Client*" } | Add-WindowsCapability -Online | Out-Null

# # Install OpenSSH Server - Applicable since 1809
# Write-Output "Installing OpenSSH Server..."
# Get-WindowsCapability -Online | Where-Object { $_.Name -like "OpenSSH.Server*" } | Add-WindowsCapability -Online | Out-Null

# Enable NTFS paths with length over 260 characters
Write-Output "Enabling NTFS paths with length over 260 characters..."
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "LongPathsEnabled" -Type DWord -Value 1

# Show file operations details
Write-Output "Showing file operations details..."
If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager")) {
  New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -Type DWord -Value 1

# Show hidden files
Write-Output "Showing hidden files..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 1

# Show protected operating system files
# Write-Output "Showing protected operating system files..."
# Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSuperHidden" -Type DWord -Value 1

# Disable file delete confirmation dialog
Write-Output "Disabling file delete confirmation dialog..."
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ConfirmFileDelete" -ErrorAction SilentlyContinue

# Show known file extensions
Write-Output "Showing known file extensions..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0

# Show seconds in taskbar
# Write-Output "Showing seconds in taskbar..."
# If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) {
#   New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" | Out-Null
# }
# Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSecondsInSystemClock" -Type DWord -Value 1

# Disable F1 Help key in Explorer and on the Desktop
Write-Output "Disabling F1 Help key..."
If (!(Test-Path "HKCU:\Software\Classes\TypeLib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win32")) {
  New-Item -Path "HKCU:\Software\Classes\TypeLib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win32" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Classes\TypeLib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win32" -Name "(Default)" -Type "String" -Value ""
If (!(Test-Path "HKCU:\Software\Classes\TypeLib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win64")) {
  New-Item -Path "HKCU:\Software\Classes\TypeLib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win64" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Classes\TypeLib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win64" -Name "(Default)" -Type "String" -Value ""

# Disable Edge desktop shortcut creation after certain Windows updates are applied
Write-Output "Disabling Edge shortcut creation..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "DisableEdgeDesktopShortcutCreation" -Type DWord -Value 1

# Disable Internet Explorer first run wizard
Write-Output "Disabling Internet Explorer first run wizard..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main")) {
  New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize" -Type DWord -Value 1

# Disable built-in Adobe Flash in IE and Edge
Write-Output "Disabling built-in Adobe Flash in IE and Edge..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer")) {
  New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer" -Name "DisableFlashInIE" -Type DWord -Value 1
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Addons")) {
  New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Addons" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Addons" -Name "FlashPlayerEnabled" -Type DWord -Value 0

# Hide 3D Objects icon from Explorer namespace - Hides the icon also from personal folders and open/save dialogs
Write-Output "Hiding 3D Objects icon from Explorer namespace..."
If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag")) {
  New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
If (!(Test-Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag")) {
  New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"

# Disable adding '- shortcut' to shortcut name
Write-Output "Disabling adding '- shortcut' to shortcut name..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "link" -Type Binary -Value ([byte[]](0,0,0,0))

# Disable search for app in store for unknown extensions
Write-Output "Disabling search for app in store for unknown extensions..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer")) {
  New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -Type DWord -Value 1

# Disable Windows Media Player's media sharing feature
Write-Output "Disabling media sharing..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer")) {
  New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventLibrarySharing" -Type DWord -Value 1

# Disable enhanced pointer precision
Write-Output "Disabling enhanced pointer precision..."
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSpeed" -Type String -Value "0"
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold1" -Type String -Value "0"
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold2" -Type String -Value "0"

# Disable Fullscreen optimizations
Write-Output "Disabling Fullscreen optimizations..."
Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_DXGIHonorFSEWindowsCompatible" -Type DWord -Value 1
Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_FSEBehavior" -Type DWord -Value 2
Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_FSEBehaviorMode" -Type DWord -Value 2
Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_HonorUserFSEBehaviorMode" -Type DWord -Value 1

# Disable Windows Defender Cloud
Write-Output "Disabling Windows Defender Cloud..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet")) {
  New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Type DWord -Value 2

# Disable biometric features
# Note: If you log on using biometrics (fingerprint, Windows Hello etc.) it's recommended to create a password recovery disk before applying this tweak.
Write-Output "Disabling biometric services..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics")) {
  New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics" -Name "Enabled" -Type DWord -Value 0

# Disable Remote Assistance - Not applicable to Server (unless Remote Assistance is explicitly installed)
Write-Output "Disabling Remote Assistance..."
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 0
Get-WindowsCapability -Online | Where-Object { $_.Name -like "App.Support.QuickAssist*" } | Remove-WindowsCapability -Online | Out-Null

# Disable Autoplay
Write-Output "Disabling Autoplay..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Type DWord -Value 1

# Disable Clipboard History - Applicable since 1809. Not applicable to Server
Write-Output "Disabling Clipboard History..."
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Clipboard" -Name "EnableClipboardHistory" -ErrorAction SilentlyContinue

# Disable Windows Update P2P delivery optimization completely
# Warning: Completely disabling delivery optimization can break Windows Store downloads - see https://github.com/Disassembler0/Win10-Initial-Setup-Script/issues/281
Write-Output "Disabling Windows Update P2P optimization..."
If ([System.Environment]::OSVersion.Version.Build -eq 10240) {
  # Method used in 1507
  If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" | Out-Null
  }
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Type DWord -Value 0
} Else {
  # Method used since 1511
  If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" | Out-Null
  }
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode" -Type DWord -Value 100
}

# Uninstall default Microsoft applications
Write-Output "Uninstalling default Microsoft applications..."
Get-AppxPackage "Microsoft.BingFinance" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.3DBuilder" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.AppConnector" | Remove-AppxPackage
Get-AppxPackage "Microsoft.BingFoodAndDrink" | Remove-AppxPackage
Get-AppxPackage "Microsoft.BingHealthAndFitness" | Remove-AppxPackage
Get-AppxPackage "Microsoft.BingMaps" | Remove-AppxPackage
Get-AppxPackage "Microsoft.BingNews" | Remove-AppxPackage
Get-AppxPackage "Microsoft.BingSports" | Remove-AppxPackage
Get-AppxPackage "Microsoft.BingTranslator" | Remove-AppxPackage
Get-AppxPackage "Microsoft.BingTravel" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.BingWeather" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.CommsPhone" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.ConnectivityStore" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.FreshPaint" | Remove-AppxPackage
Get-AppxPackage "Microsoft.GetHelp" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Getstarted" | Remove-AppxPackage
Get-AppxPackage "Microsoft.HelpAndTips" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.Media.PlayReadyClient.2" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.Messaging" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.Microsoft3DViewer" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.MicrosoftOfficeHub" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.MicrosoftPowerBIForWindows" | Remove-AppxPackage
Get-AppxPackage "Microsoft.MicrosoftSolitaireCollection" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.MicrosoftStickyNotes" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.MinecraftUWP" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.MixedReality.Portal" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.MoCamera" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.MSPaint" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.NetworkSpeedTest" | Remove-AppxPackage
Get-AppxPackage "Microsoft.OfficeLens" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Office.OneNote" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Office.Sway" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.OneConnect" | Remove-AppxPackage
Get-AppxPackage "Microsoft.People" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.Print3D" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.Reader" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.RemoteDesktop" | Remove-AppxPackage
Get-AppxPackage "Microsoft.SkypeApp" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.Todos" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Wallet" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.WebMediaExtensions" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.Whiteboard" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.WindowsAlarms" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.WindowsCamera" | Remove-AppxPackage
# Get-AppxPackage "microsoft.windowscommunicationsapps" | Remove-AppxPackage
Get-AppxPackage "Microsoft.WindowsFeedbackHub" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.WindowsMaps" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.WindowsPhone" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.Windows.Photos" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.WindowsReadingList" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.WindowsScan" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.WindowsSoundRecorder" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.WinJS.1.0" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.WinJS.2.0" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.YourPhone" | Remove-AppxPackage
Get-AppxPackage "Microsoft.ZuneMusic" | Remove-AppxPackage
Get-AppxPackage "Microsoft.ZuneVideo" | Remove-AppxPackage

# WSL 2 install - not needed to enable features, lets run this as last thing
wsl --install

Write-Output "Restarting pc ..."
Restart-Computer
