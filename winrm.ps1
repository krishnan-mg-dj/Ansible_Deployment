$current_path = Get-Location
$statuslog = "$current_path\status.log"
$errorlog = "$current_path\error.log"
$infolog = "$current_path\info.log"

function Test-Administrator {
    $user = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($user)
    $adminRole = [Security.Principal.WindowsBuiltInRole]::Administrator
    return $principal.IsInRole($adminRole)
}
if (Test-Administrator) {
    #Write-Output "Current user is a privileged user (administrator)."
	Write-Output "Current user is a privileged user (administrator)." > $errorlog
	Write-Output "Current user is a privileged user (administrator)." > $infolog
} else {
    Write-Output "Current user is a non-privileged user (non-administrator)."
	Write-Output "Current user is a non-privileged user (non-administrator)." >> $errorlog
	Write-Output "Current user is a non-privileged user (non-administrator)." > $infolog
	Write-Output "failed" > $statuslog
	exit 1
}
Set-Service WinRM -StartupType 'Automatic'  >> $errorlog 2>&1
if ($?) {
    Write-Output "Winrm service set to automatic" >> $errorlog
	Write-Output "Winrm service set to automatic" > $infolog
} else {
    Write-Output "Winrm service set to automatic failed" >> $errorlog
	Write-Output "Winrm service set to automatic failed" > $infolog
	Write-Output "failed" > $statuslog
	exit 1
}
Set-Item -Path WSMan:\localhost\Service\Auth\Certificate -Value $true
Set-Item -Path 'WSMan:\localhost\Service\AllowUnencrypted' -Value $true
Set-Item -Path 'WSMan:\localhost\Service\Auth\Basic' -Value $true
Set-Item -Path 'WSMan:\localhost\Service\Auth\CredSSP' -Value $true
New-NetFirewallRule -DisplayName "Allow WinRM HTTPS" -Direction Inbound -LocalPort 5985 -Protocol TCP -Action Allow >> $errorlog 2>&1
if ($?) {
    Write-Output "Firewall rule created for winrm connection" >> $errorlog
	Write-Output "Firewall rule created for winrm connection" > $infolog
} else {
    Write-Output "Winrm service set to automatic failed" >> $errorlog
	Write-Output "Winrm service set to automatic failed" > $infolog
	Write-Output "failed" > $statuslog
	exit 1
}
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force >> $errorlog 2>&1
if ($?) {
    Write-Output "Set to trust localhost" >> $errorlog
	Write-Output "Set to trust localhost" > $infolog
} else {
    Write-Output "Set to trust localhost failed" >> $errorlog
	Write-Output "Set to trust localhost failed" > $infolog
	Write-Output "failed" > $statuslog
	exit 1
}
New-ItemProperty -Name LocalAccountTokenFilterPolicy -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -PropertyType DWord -Value 1 -Force >> $errorlog 2>&1
if ($?) {
    Write-Output "update a registry entry (property) on a Windows system" >> $errorlog
	Write-Output "update a registry entry (property) on a Windows system" > $infolog
} else {
    Write-Output "update a registry entry failed to create" >> $errorlog
	Write-Output "update a registry entry failed to create" > $infolog
	Write-Output "failed" > $statuslog
	exit 1
}
Set-ExecutionPolicy Unrestricted -Force >> $errorlog 2>&1
if ($?) {
    Write-Output "Set ExecutionPolicy successfully" >> $errorlog
	Write-Output "Set ExecutionPolicy successfully" > $infolog
} else {
    Write-Output "Set ExecutionPolicy failed create" >> $errorlog
	Write-Output "Set ExecutionPolicy failed create" > $infolog
	Write-Output "failed" > $statuslog
	exit 1
}
Restart-Service WinRM >> $errorlog 2>&1
if ($?) {
    Write-Output "Restart Winrm service successfully" >> $errorlog
	Write-Output "Restart Winrm service successfully" > $infolog
} else {
    Write-Output "Restart Winrm service failed" >> $errorlog
	Write-Output "Restart Winrm service failed" > $infolog
	Write-Output "failed" > $statuslog
	exit 1
}
winrm enumerate winrm/config/Listener >> $errorlog 2>&1
if ($?) {
    Write-Output "start listener for winrm" >> $errorlog
	Write-Output "start listener for winrm" > $infolog
	Write-Output "success" > $statuslog
} else {
    Write-Output "start listener failed" >> $errorlog
	Write-Output "start listener failed" > $infolog
	Write-Output "failed" > $statuslog
	exit 1
}