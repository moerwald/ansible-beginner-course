# Based on https://adamtheautomator.com/winrm-https-ansible/

Write-Host "Starting WINRM server"

Set-Service -Name "WinRM" -StartupType Automatic
Start-Service -Name "WinRM"

Write-Host "Enable PS Remoting"
if (-not (Get-PSSessionConfiguration) -or (-not (Get-ChildItem WSMan:\localhost\Listener))) {
    ## Use SkipNetworkProfileCheck to make available even on Windows Firewall public profiles
    ## Use Force to not be prompted if we're sure or not.
    Enable-PSRemoting -SkipNetworkProfileCheck -Force
}

#region Enable cert-based auth
Write-Host "Enable certificate support for WSMAN"
Set-Item -Path WSMan:\localhost\Service\Auth\Certificate -Value $true
#endregion

#region Create a new user, which is goint to be mapped to the certifacte
$testUserAccountName = 'ansibletestuser'

Write-Host "Create user $testUserAccountName"

$testUserAccountPassword = (ConvertTo-SecureString -String 'p@$$w0rd12' -AsPlainText -Force)
if (-not (Get-LocalUser -Name $testUserAccountName -ErrorAction Ignore)) {
    $newUserParams = @{
        Name                 = $testUserAccountName
        AccountNeverExpires  = $true
        PasswordNeverExpires = $true
        Password             = $testUserAccountPassword
    }
    $null = New-LocalUser @newUserParams
}
#endregion

#region Import the certificate
$pubKeyFilePath = Resolve-Path '.\cert.pem'

Write-Host "Import user-certificate ($testUserAccountName)"
## Import the public key into Trusted Root Certification Authorities and Trusted People
$null = Import-Certificate -FilePath $pubKeyFilePath -CertStoreLocation 'Cert:\LocalMachine\Root'
$null = Import-Certificate -FilePath $pubKeyFilePath -CertStoreLocation 'Cert:\LocalMachine\TrustedPeople'

#endregion

#region Create server certificate
$hostname = hostname
Write-Host "Create new server certificate for $hostname"
$serverCert = New-SelfSignedCertificate -DnsName $hostName -CertStoreLocation 'Cert:\LocalMachine\My'
#endregion

#region Create WinRm Listener
## Find all HTTPS listners
$httpsListeners = Get-ChildItem -Path WSMan:\localhost\Listener\ | where-object { $_.Keys -match 'Transport=HTTPS' }

Write-Host "Create HTTPS WinRm listener"
## If not listeners are defined at all or no listener is configured to work with
## the server cert created, create a new one with a Subject of the computer's host name
## and bound to the server certificate.
if ((-not $httpsListeners) -or -not (@($httpsListeners).where( { $_.CertificateThumbprint -ne $serverCert.Thumbprint }))) {
    $newWsmanParams = @{
        ResourceUri = 'winrm/config/Listener'
        SelectorSet = @{ Transport = "HTTPS"; Address = "*" }
        ValueSet    = @{ Hostname = $hostName; CertificateThumbprint = $serverCert.Thumbprint }
        # UseSSL = $true
    }
    $null = New-WSManInstance @newWsmanParams
}

#endregion

#region Map user certificate to user

$credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $testUserAccountName, $testUserAccountPassword

## Find the cert thumbprint for the client certificate created on the Ansible host
$ansibleCert = Get-ChildItem -Path 'Cert:\LocalMachine\Root' | Where-Object {$_.Subject -eq 'CN=ansibletestuser'}

$params = @{
	Path = 'WSMan:\localhost\ClientCertificate'
	Subject = "$testUserAccountName@localhost"
	URI = '*'
	Issuer = $ansibleCert.Thumbprint
  Credential = $credential
	Force = $true
}
New-Item @params

#endregion

#region Deactivate UAC for WinRm

Write-Host "Deactivate UAC for WinRm"

$newItemParams = @{
    Path         = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    Name         = 'LocalAccountTokenFilterPolicy'
    Value        = 1
    PropertyType = 'DWORD'
    Force        = $true
}
$null = New-ItemProperty @newItemParams

#endregion


#region Ensure WinRM 5986 is open on the firewall
Write-Host "Ensure WinRM 5986 is open on the firewall"
 $ruleDisplayName = 'Windows Remote Management (HTTPS-In)'
 if (-not (Get-NetFirewallRule -DisplayName $ruleDisplayName -ErrorAction Ignore)) {
     $newRuleParams = @{
         DisplayName   = $ruleDisplayName
         Direction     = 'Inbound'
         LocalPort     = 5986
         RemoteAddress = 'Any'
         Protocol      = 'TCP'
         Action        = 'Allow'
         Enabled       = 'True'
         Group         = 'Windows Remote Management'
     }
     $null = New-NetFirewallRule @newRuleParams
 }
 #endregion


 ## Add the local user to the administrators group. If this step isn't doing, Ansible sees an "AccessDenied" error
Write-Host "Add $testUserAccountName to Administrators group"
Get-LocalUser -Name $testUserAccountName | Add-LocalGroupMember -Group 'Administrators'