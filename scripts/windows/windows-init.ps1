# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
# WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
# OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

<#
    .DESCRIPTION
    Initializes the Windows operating system builds.
#>

$ErrorActionPreference = 'Stop'

$firewallGroupName = 'Windows Remote Management'
$httpFirewallRuleDisplayName = 'Windows Remote Management (HTTP-In)'
$httpsFirewallRuleName = 'WINRM-HTTPS-In-TCP'
$httpsFirewallRuleDisplayName = 'Windows Remote Management (HTTPS-In)'
$httpsFirewallRuleDescription = 'Windows Remote Management Inbound HTTPS [TCP 5986]'
$httpsFirewallRuleProgram = 'System'
$httpsFirewallRuleAction = 'Allow'
$httpsFirewallRuleEnabled = 'False'
$httpsPort = 5986
$protocol = 'TCP'
$transport = 'HTTPS'

function Wrap {
    Param([ScriptBlock]$block)
    Write-Host "+ $($block.ToString().Trim())"
    Write-Host ''
    Try {
        Invoke-Command -ScriptBlock $block
    }
    Catch {
        Write-Error $_.Exception
    }
}

# Start the Windows initialization logging.
Start-Transcript -Path 'C:\windows-init.log' -Force
Write-Output 'Starting the Windows initialization logging...'

# Start the Windows Remote Management configuration.
Write-Output 'Starting the Windows Remote Management configuration...'

# Get the operating system information.
Write-Output 'Getting the operating system information...'
$osType = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name InstallationType
Write-Output "Operating system type: $osType"

# Disable the Network Location Wizard.
Write-Output 'Disabling the Network Location Wizard...'
Wrap { New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Network\NewNetworkWindowOff' -Force | Out-Null }

# Set network connections profile to private.
Write-Output 'Setting the network connection profiles to private...'
Wrap { Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Private }

if ($osType -eq 'Client') {
    # Set the Windows Remote Management on Windows Desktop configuration
    Write-Output 'Setting the Windows Remote Management on Windows Desktop configuration...'
    Write-Output 'Note: This configuration will be removed at the end of the build.'
    Wrap { Enable-PSRemoting -SkipNetworkProfileCheck -Force }
    Wrap { Set-WSManInstance -ResourceURI 'winrm/config' -ValueSet @{MaxTimeoutms = 18000 } }
    Wrap { Set-WSManInstance -ResourceURI 'winrm/config/winrs' -ValueSet @{MaxMemoryPerShellMB = 1024 } }
    Wrap { Set-WSManInstance -ResourceURI 'winrm/config/service' -ValueSet @{AllowUnencrypted = 'true'; } }
    Wrap { Set-WSManInstance -ResourceURI 'winrm/config/service/auth' -ValueSet @{Negotiate = 'true'; } }

    # Allow Windows Remote Management in the Windows Firewall.
    Write-Output 'Allowing Windows Remote Management in the Windows Firewall...'
    Write-Output 'Note: This configuration will be removed at the end of the build.'
    Wrap { Enable-NetFirewallRule -DisplayGroup $firewallGroupName -PassThru }
    Wrap { Get-NetFirewallRule -DisplayGroup $firewallGroupName | Get-NetFirewallAddressFilter | Where-Object { $_.RemoteAddress -Like 'LocalSubnet*' } | Get-NetFirewallRule | Set-NetFirewallRule -RemoteAddress Any }
    Wrap { Set-NetFirewallRule -DisplayName $httpFirewallRuleDisplayName -EdgeTraversalPolicy Allow -Confirm:$false -PassThru }
    
} elseif (($osType -eq 'Server') -or ($osType -eq 'Server Core')) {
    # Add the Windows Remote Management HTTPS listeners.
    Write-Output 'Adding the Windows Remote Management HTTPS listeners...'
    Wrap {
        $certificate = New-SelfSignedCertificate -CertStoreLocation Cert:\LocalMachine\My -DnsName $env:COMPUTERNAME
        New-Item -Path WSMan:\LocalHost\Listener -Transport $transport -Address * -CertificateThumbPrint $certificate.Thumbprint -Hostname $env:COMPUTERNAME -Port $httpsPort -Force | Out-Null
    }

    # Set the Windows Remote Management trusted hosts to all.
    Write-Output 'Setting the Windows Remote Management trusted hosts to all...'
    Wrap { Set-Item -Path WSMan:\localhost\Client/TrustedHosts -Value * -Force }

    # Remove the default Windows Remote Management HTTP listener.
    Write-Output 'Removing the default Windows Remote Management HTTP listener...'
    Wrap { Get-ChildItem WSMan:\localhost\Listener | ? { $_.Keys -contains 'Transport=HTTP' } | Remove-Item -Recurse -Confirm:$false }

    # Set the Windows Remote Management NTLM authentication configuration.
    Write-Output 'Setting the Windows Remote Management NTLM authentication configuration...'
    Wrap { Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel' -Value 2 -Type DWord -Force }
    Wrap { Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name 'NTLMMinServerSec' -Value 536870912 -Type DWord -Force }
    Wrap { Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'LocalAccountTokenFilterPolicy' -Value 1 -Force }

    # Disable the default Windows Remote Management firewall group rules.
    Write-Output 'Disabling the default Windows Remote Management firewall group rules...'
    Wrap { Disable-NetFirewallRule -DisplayGroup $firewallGroupName }

    # Set the Windows Remote Management over Inbound HTTPS on TCP 5986 firewall rule.
    Write-Output 'Setting the Windows Remote Management over Inbound HTTPS on TCP 5986 firewall rule...'
    Wrap {
        New-NetFirewallRule `
            -Name $httpsFirewallRuleName `
            -DisplayName $httpsFirewallRuleDisplayName `
            -Description $httpsFirewallRuleDescription `
            -Group $firewallGroupName `
            -Program $httpsFirewallRuleProgram `
            -Protocol $protocol `
            -LocalPort $httpsPort `
            -Action $httpsFirewallRuleAction `
            -Enabled $httpsFirewallRuleEnabled | Out-Null
    }

    # Enable Windows Remote Management over HTTPS in the Windows Firewall.
    Write-Output 'Enabling Windows Remote Management over HTTPS in the Windows Firewall...'
    Wrap { Enable-NetFirewallRule -DisplayName $httpsFirewallRuleDisplayName }
}

# Set the AutoLogonCount to 0.
Write-Output 'Setting the AutoLogonCount to 0...'
Wrap { Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'AutoLogonCount' -Value 0 -Force }

# Stop the Windows initialization logging.
Write-Output 'Stopping the Windows initialization logging...'
Wrap { Stop-Transcript }

# Save the Windows initialization log.
Write-Output 'Saving the Windows initialization log...'
New-Item -Path 'C:\Packer' -Type Directory -Force | Out-Null
$acl = Get-Acl 'C:\Packer'
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule('everyone', 'FullControl', 'ContainerInherit,Objectinherit', 'none', 'Allow')
$acl.AddAccessRule($rule)
Set-Acl -Path 'C:\Packer' -AclObject $acl

# Move the Windows initialization log.
Write-Output 'Moving the Windows initialization log...'
Move-Item -Path 'C:\windows-init.log' -Destination 'C:\Packer\' -Force

# Windows initialization completed.
Write-Host 'Completed the Windows initialization.'
