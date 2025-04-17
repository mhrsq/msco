# Script untuk instal Sysmon
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/mhrsq/msco/main/Sysmon64.exe" -OutFile "$env:TEMP\Sysmon64.exe"; Invoke-WebRequest -Uri "https://raw.githubusercontent.com/mhrsq/msco/main/ft-sysmonconfig-export.xml" -OutFile "$env:TEMP\config.xml"; Start-Process -FilePath "$env:TEMP\Sysmon64.exe" -ArgumentList "-accepteula -i $env:TEMP\config.xml" -Wait

Start-Sleep -Seconds 3

# Script untuk instal Wazuh agent
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.11.2-1.msi -OutFile $env:tmp\wazuh-agent; msiexec.exe /i $env:tmp\wazuh-agent /q WAZUH_MANAGER='182.23.30.24'

Start-Sleep -Seconds 3

# Script untuk update konfig Wazuh
(Get-Content "C:\Program Files (x86)\ossec-agent\internal_options.conf") -replace '^(logcollector\.remote_commands\s*=\s*)0', '${1}1' -replace '^(wazuh_command\.remote_commands\s*=\s*)0', '${1}1' | Set-Content "C:\Program Files (x86)\ossec-agent\internal_options.conf" -Encoding UTF8
Add-Content "C:\Program Files (x86)\ossec-agent\local_internal_options.conf" "logcollector.remote_commands=1`nwazuh_command.remote_commands=1"
Restart-Service -Name "WazuhSvc"

# Jalankan ulang Wazuh service
NET START WazuhSvc
