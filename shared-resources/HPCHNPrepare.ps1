<#
.Synopsis
    Prepare the HPC Pack head node.

.DESCRIPTION
    This script promotes the virtual machine created from HPC Image to a HPC head node.

.NOTES
    This cmdlet requires:
    1. The current computer is a virtual machine created from HPC Image.
    2. The current computer is domain joined.
    3. The current user is a domain user as well as local administrator.
    4. The current user is the sysadmin of the DB server instance

.EXAMPLE
    PS > HPCHNPrepare.ps1 -DBServerInstance ".\ComputeCluster"
    Prepare the HPC head node with local DB server instance ".\ComputeCluster"

.EXAMPLE
    PS > HPCHNPrepare.ps1 -DBServerInstance "MyRemoteDB\ComputeCluster" -RemoteDB
    Prepare the HPC head node with remote DB server instance "MyRemoteDB\ComputeCluster"
#>
Param
(
    # Specifies the database server instance
    [Parameter(Mandatory=$true)]
    [String] $DBServerInstance, 
    
    # (Optional) specifies the database name for HPC Management DB. If not specified, the default value is "HPCManagement"
    [Parameter(Mandatory=$false)]
    [String] $ManagementDB = "HPCManagement",

    # (Optional) specifies the database name for HPC Scheduler DB. If not specified, the default value is "HPCScheduler"
    [Parameter(Mandatory=$false)]
    [String] $SchedulerDB = "HPCScheduler",

    # (Optional) specifies the database name for HPC Monitoring DB. If not specified, the default value is "HPCMonitoring"
    [Parameter(Mandatory=$false)]
    [String] $MonitoringDB = "HPCMonitoring",

    # (Optional) specifies the database name for HPC Reporting DB. If not specified, the default value is "HPCReporting"
    [Parameter(Mandatory=$false)]
    [String] $ReportingDB = "HPCReporting",

    # (Optional) specifies the database name for HPC Diagnostics DB. If not specified, the default value is "HPCDiagnostics"
    [Parameter(Mandatory=$false)]
    [String] $DiagnosticsDB = "HPCDiagnostics",

    # (Optional) specifies this parameter if the database server is a remote server.
    [Parameter(Mandatory=$false)]
    [Switch] $RemoteDB,

    # (Optional) specifies the path of the log file. If not specified, the default value is "$env:windir\Temp\HPCHeadNodePrepare.log"
    [Parameter(Mandatory=$false)]
    [String] $LogFile = ""
)

Set-StrictMode -Version 3
$Script:LogFilePath = "$env:windir\Temp\HPCHeadNodePrepare.log"
if(-not [String]::IsNullOrEmpty($LogFile))
{
    $Script:LogFilePath = $LogFile
}

if(Test-Path -Path $Script:LogFilePath -PathType Leaf)
{
    Remove-Item -Path $Script:LogFilePath -Force
}

function WriteLog
{
    Param(
        [Parameter(Mandatory=$true, Position=0)]
        [ValidateNotNullOrEmpty()]
        [String] $Message,

        [Parameter(Mandatory=$false)]
        [ValidateSet("Error","Warning","Verbose")]
        [String] $LogLevel = "Verbose"
    )
    
    $timestr = Get-Date -Format 'MM/dd/yyyy HH:mm:ss'
    $NewMessage = "$timestr - $Message"
    switch($LogLevel)
    {
        "Error"     {Write-Error   $NewMessage; break}
        "Warning"   {Write-Warning $NewMessage; break}
        "Verbose"   {Write-Verbose $NewMessage; break}
    }
       
    try
    {
        # Write to both the log file and the console
        $NewMessage = "[$LogLevel]$timestr - $Message"
        Add-Content $Script:LogFilePath $NewMessage -ErrorAction SilentlyContinue
        $NewMessage | Write-Host
    }
    catch
    {
        #Ignore the error
    }
}

try
{
    # 0 for Standalone Workstation, 1 for Member Workstation, 2 for Standalone Server, 3 for Member Server, 4 for Backup Domain Controller, 5 for Primary Domain Controller
    $computeInfo = Get-WmiObject Win32_ComputerSystem
    $domainRole = $computeInfo.DomainRole
    if($domainRole -lt 3)
    {
        throw "$env:COMPUTERNAME is not domain joined"
    }

    WriteLog "Updating Cluster Name"
    Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\HPC -Name ClusterName -Value $env:COMPUTERNAME
    Set-ItemProperty -Path HKLM:\SOFTWARE\Wow6432Node\Microsoft\HPC -Name ClusterName -Value $env:COMPUTERNAME
    [Environment]::SetEnvironmentVariable("CCP_SCHEDULER", $env:COMPUTERNAME, [System.EnvironmentVariableTarget]::Machine)
    [Environment]::SetEnvironmentVariable("CCP_SCHEDULER", $env:COMPUTERNAME, [System.EnvironmentVariableTarget]::Process)
    $HPCBinPath = [System.IO.Path]::Combine($env:CCP_HOME, "Bin")

    $DBDic = @{
        "HPCManagement"  = $ManagementDB; 
        "HPCDiagnostics" = $DiagnosticsDB; 
        "HPCScheduler"   = $SchedulerDB; 
        "HPCReporting"   = $ReportingDB; 
        "HPCMonitoring"  = $MonitoringDB
    }

    WriteLog "Updating DB Connection Strings to Registry Table"
    foreach($db in $DBDic.Keys)
    {
        $regDbServerName = $db.Substring(3) + "DbServerName"
        Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\HPC -Name $regDbServerName -Value $DBServerInstance
        $regConnStrName = $db.Substring(3) + "DbConnectionString"
        $regConnStrValue = "Data Source={0};Initial Catalog={1};Integrated Security=True;" -f $DBServerInstance, $DBDic[$db]
        Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\HPC\Security -Name $regConnStrName -Value $regConnStrValue
    }


    if($RemoteDB.IsPresent)
    {
        $domainNetbiosName = $computeInfo.Domain.Split(".")[0].ToUpper()
        $machineAccount = "$domainNetbiosName\$env:COMPUTERNAME$"
        Import-Module "sqlps" -DisableNameChecking -Force
        foreach($db in $DBDic.Keys)
        {
            WriteLog ("Configuring Database " + $DBDic[$db])
            $dbNameVar = $db + "DBName"
            $sqlfilename = $db + "DB.sql"
            Get-Content "$HPCBinPath\$sqlfilename" | %{$_.Replace("`$($dbNameVar)", $DBDic[$db])} | Set-Content "$env:temp\$sqlfilename" -Force
            Invoke-Sqlcmd -ServerInstance $DBServerInstance -Database $DBDic[$db] -InputFile "$env:temp\$sqlfilename" -QueryTimeout 300 -ErrorAction SilentlyContinue
            Invoke-Sqlcmd -ServerInstance $DBServerInstance -Database $DBDic[$db] -InputFile "$HPCBinPath\AddDbUserForHpcService.sql" -Variable "TargetAccount=$machineAccount" -QueryTimeout 300
        }

        WriteLog "Inserting SDM Documents to HpcManagment database"
        $sdmDocs = @(
            "Microsoft.Ccp.ClusterModel.sdmDocument", 
            "Microsoft.Ccp.TemplateModel.sdmDocument", 
            "Microsoft.Ccp.NetworkModel.sdmDocument", 
            "Microsoft.Ccp.WdsModel.sdmDocument", 
            "Microsoft.Ccp.ComputerModel.sdmDocument", 
            "Microsoft.Hpc.NetBootModel.sdmDocument"
        )

        $sdmLArgs = @()
        $sdmLArgs += "-sql:`"`""
        foreach($doc in $sdmDocs)
        {
            $docFullPath = [System.IO.Path]::Combine($env:CCP_HOME, "Conf\$doc")
            $sdmLArgs += " `"$docFullPath`""
        }

        $p = Start-Process -FilePath "SdmL.exe" -ArgumentList $sdmLArgs -NoNewWindow -Wait -PassThru
        if($p.ExitCode -ne 0)
        {
            throw "Failed to insert SDM documents to HpcManagment database: $($p.ExitCode)"
        }
    }
    else
    {
        WriteLog "Starting SQL Server Services"
        $SQLServices = @('MSSQL$COMPUTECLUSTER', 'SQLBrowser', 'SQLWriter')
        $SQLServices | Set-Service -StartupType Automatic
        $SQLServices | Start-Service
    }

    $HNServiceList = @("HpcSdm", "HpcManagement", "HpcReporting", "HpcMonitoringClient", "HpcNodeManager", "msmpi", "HpcBroker", `
        "HpcDiagnostics", "HpcScheduler", "HpcMonitoringServer", "HpcSession", "HpcSoaDiagMon")

    foreach($svcname in $HNServiceList)
    {
        $service = Get-Service -Name $svcname -ErrorAction SilentlyContinue
        if($service -eq $null)
        {
            throw "The service $svcname doesn't exist"
        }
        else
        {
            WriteLog "Setting the startup type of the service $svcname to automatic"
            Set-Service -Name $svcname -StartupType Automatic

            # HpcBroker service will be started later
            if($svcname -ne "HpcBroker")
            {
                $retry = 0
                while($true)
                {
                    WriteLog "Starting service $svcname"
                    Start-Service -Name $svcname
                    if($?)
                    {
                        break
                    }
                    elseif($retry -lt 20)
                    {
                        WriteLog "Failed to start service $svcname, retry later ..."
                        Start-Sleep -Seconds 20
                        $retry++
                    }
                    else
                    {
                        throw ("Failed to start service $svcname : " + $Error[0])
                    }
                }
            }
        }
    }

    # Custom actions after Start-Serivce
    $retry = 0
    while($true)
    {
        WriteLog "Setting SpoolDir"
        $p = Start-Process -FilePath "cluscfg.exe" -ArgumentList "setparams SpoolDir=`"\\$env:COMPUTERNAME\CcpSpoolDir`"" -NoNewWindow -Wait -PassThru
        if($p.ExitCode -eq 0)
        {
            break
        }
        elseif($retry -lt 20)
        {
            WriteLog "Failed to set SpoolDir: $($p.ExitCode), retry later ..."
            Start-Sleep -Seconds 20
            $retry++
        }
        else
        {
            throw "Failed to set SpoolDir: $($p.ExitCode)"
        }
    }

    $retry = 0
    while($true)
    {
        WriteLog "Setting CCP_SERVICEREGISTRATION_PATH"
        $p = Start-Process -FilePath "cluscfg.exe" -ArgumentList "setenvs CCP_SERVICEREGISTRATION_PATH=`"\\$env:COMPUTERNAME\HpcServiceRegistration`"" -NoNewWindow -Wait -PassThru
        if($p.ExitCode -eq 0)
        {
            break
        }
        elseif($retry -lt 20)
        {
            WriteLog "Failed to set CCP_SERVICEREGISTRATION_PATH, retry later ..."
            Start-Sleep -Seconds 20
            $retry++
        }
        else
        {
            throw "Failed to set CCP_SERVICEREGISTRATION_PATH: $($p.ExitCode)"
        }
    }

    $retry = 0
    while($true)
    {
        WriteLog "Setting WDS listener Acls"
        $p = Start-Process -FilePath "sc.exe" -ArgumentList "control hpcmanagement 245" -NoNewWindow -Wait -PassThru
        if($p.ExitCode -eq 0)
        {
            break
        }
        elseif($retry -lt 20)
        {
            WriteLog "Failed to set Wds Listener Acls: $($p.ExitCode), retry later ..."
            Start-Sleep -Seconds 20
            $retry++
        }
        else
        {
            throw "Failed to set Wds Listener Acls: $($p.ExitCode)"
        }
    }

    Start-Sleep -Seconds 5
    $retry = 0
    while($true)
    {
        WriteLog "Enabling port sharing service"
        $p = Start-Process -FilePath "sc.exe" -ArgumentList "control hpcmanagement 249" -NoNewWindow -Wait -PassThru
        if($p.ExitCode -eq 0)
        {
            break
        }
        elseif($retry -lt 20)
        {
            WriteLog "Failed to enable port sharing service: $($p.ExitCode), retry later ..."
            Start-Sleep -Seconds 20
            $retry++
        }
        else
        {
            throw "Failed to enable port sharing service: $($p.ExitCode)"
        }
    }

    $retry = 0
    while($true)
    {
        WriteLog "Starting service HpcBroker"
        Start-Service -Name "HpcBroker"
        if($?)
        {
            break
        }
        elseif($retry -lt 20)
        {
            WriteLog "Failed to start service HpcBroker, retry later ..."
            Start-Sleep -Seconds 20
            $retry++
        }
        else
        {
            throw ("Failed to start service HpcBroker : " + $Error[0])
        }
    }

    WriteLog "importing diagnostics test cases"
    Start-Process -FilePath "test.exe" -ArgumentList "add `"$HPCBinPath\microsofttests.xml`"" -NoNewWindow -Wait
    Start-Process -FilePath "test.exe" -ArgumentList "add `"$HPCBinPath\exceltests.xml`"" -NoNewWindow -Wait

    WriteLog "Configuring monitoring service"
    Start-Process -FilePath "HpcMonUtil.exe" -ArgumentList "configure /v" -NoNewWindow -Wait

    $retry = 0
    while($true)
    {
        WriteLog "Publishing HPC runtime data share"
        $p = Start-Process -FilePath "cluscfg.exe" -ArgumentList "setenvs HPC_RUNTIMESHARE=`"\\$env:COMPUTERNAME\Runtime$`"" -NoNewWindow -Wait -PassThru
        if($p.ExitCode -eq 0)
        {
            break
        }
        elseif($retry -lt 20)
        {
            WriteLog "Failed to publish HPC runtime data share: $($p.ExitCode), retry later ..."
            Start-Sleep -Seconds 20
            $retry++
        }
        else
        {
            throw "Failed to publish HPC runtime data share: $($p.ExitCode)"
        }
    }

    WriteLog "Reloading HpcSession Service"
    Start-Process -FilePath "sc.exe" -ArgumentList "control HpcSession 128" -NoNewWindow -Wait
    
    WriteLog "HPC head node is now ready for use"
}
catch
{
    WriteLog ("Failed to Prepare HPC head node: " + ($_ | Out-String)) -LogLevel Error
    throw
}
# SIG # Begin signature block
# MIIdnwYJKoZIhvcNAQcCoIIdkDCCHYwCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUnFoctTrcXnGM40k7LwPpj2cR
# IlugghhVMIIEwzCCA6ugAwIBAgITMwAAAMzLuBPrXXItRQAAAAAAzDANBgkqhkiG
# 9w0BAQUFADB3MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSEw
# HwYDVQQDExhNaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EwHhcNMTYwOTA3MTc1ODU2
# WhcNMTgwOTA3MTc1ODU2WjCBszELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjENMAsGA1UECxMETU9QUjEnMCUGA1UECxMebkNpcGhlciBEU0UgRVNO
# OjE0OEMtQzRCOS0yMDY2MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBT
# ZXJ2aWNlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwe5bp0PH7Nar
# LeUDfq1E+Jd4WNpGm2kgEVzLGmOAjML+w5RXEzQOQuqTl8SfMUcrg1+to2Ihbu3h
# fPFFRQJq0cPH/i14X1w0cWP6jRqyAqv/T3lSM4O3dDSNZK+QUsUq0yXeF+FmvW0i
# gBHUpOpXEyxHha0QNzbJm9iyCXSu/WaUstgcq8wHA2gvuLdvSA6pDt+AgAUf0o/f
# 2Nwl25HtlDNRiI1PgfSRdw+W0gnSalk3xycrDVFDlVLavPccwXNc0YsNrKFr9T17
# baz3xYPTb/+90NtpUoBgSdpV2Rr7ev7l806lz4mlxEEqFv/xwk7Yws4BowtU9pE1
# zaPyNiV2GQIDAQABo4IBCTCCAQUwHQYDVR0OBBYEFPWhmmbVkedPZa+s2RQAnZdC
# m8+qMB8GA1UdIwQYMBaAFCM0+NlSRnAK7UD7dvuzK7DDNbMPMFQGA1UdHwRNMEsw
# SaBHoEWGQ2h0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3Rz
# L01pY3Jvc29mdFRpbWVTdGFtcFBDQS5jcmwwWAYIKwYBBQUHAQEETDBKMEgGCCsG
# AQUFBzAChjxodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY3Jv
# c29mdFRpbWVTdGFtcFBDQS5jcnQwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZI
# hvcNAQEFBQADggEBAJaBLYob96ccjvtcRqUl/51+iQ6TX4WoJCYb+jf3sMtgQLd4
# kLPpCB/2f8uuZePf9wSdjCu2SPFt1Px6vJysXk2B7rReYR3A8G0SsoUv/nCdFjp3
# dtr3lm2xkMU2wv5Ox4BO4Jf+0vT9+s3PbLnPZK/GjUJ1idWSG0sKpXgq7mpSw9SV
# 7jIjjdM0bupBd2xLCKfocxjYir5UYJWiC8C0kb//6F8/JL/n1Gr1Ty7mZdiFjW4F
# BEIxTU3r0EnAqtOv/O0cApLuC9AV1pFixlGgQRqlA/xRQLLaui3j5qGKeJeijYSz
# RJgTY5L21IbbuV6arIrZhpJkL059QogKBFgjmiIwggYBMIID6aADAgECAhMzAAAA
# xOmJ+HqBUOn/AAAAAADEMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTEwHhcNMTcwODExMjAyMDI0WhcNMTgwODExMjAyMDI0WjB0
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
# AoIBAQCIirgkwwePmoB5FfwmYPxyiCz69KOXiJZGt6PLX4kvOjMuHpF4+nypH4IB
# tXrLGrwDykbrxZn3+wQd8oUK/yJuofJnPcUnGOUoH/UElEFj7OO6FYztE5o13jhw
# VG877K1FCTBJwb6PMJkMy3bJ93OVFnfRi7uUxwiFIO0eqDXxccLgdABLitLckevW
# eP6N+q1giD29uR+uYpe/xYSxkK7WryvTVPs12s1xkuYe/+xxa8t/CHZ04BBRSNTx
# AMhITKMHNeVZDf18nMjmWuOF9daaDx+OpuSEF8HWyp8dAcf9SKcTkjOXIUgy+MIk
# ogCyvlPKg24pW4HvOG6A87vsEwvrAgMBAAGjggGAMIIBfDAfBgNVHSUEGDAWBgor
# BgEEAYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUy9ZihM9gOer/Z8Jc0si7q7fD
# E5gwUgYDVR0RBEswSaRHMEUxDTALBgNVBAsTBE1PUFIxNDAyBgNVBAUTKzIzMDAx
# MitjODA0YjVlYS00OWI0LTQyMzgtODM2Mi1kODUxZmEyMjU0ZmMwHwYDVR0jBBgw
# FoAUSG5k5VAF04KqFzc3IrVtqMp1ApUwVAYDVR0fBE0wSzBJoEegRYZDaHR0cDov
# L3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljQ29kU2lnUENBMjAxMV8y
# MDExLTA3LTA4LmNybDBhBggrBgEFBQcBAQRVMFMwUQYIKwYBBQUHMAKGRWh0dHA6
# Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMvTWljQ29kU2lnUENBMjAx
# MV8yMDExLTA3LTA4LmNydDAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IC
# AQAGFh/bV8JQyCNPolF41+34/c291cDx+RtW7VPIaUcF1cTL7OL8mVuVXxE4KMAF
# RRPgmnmIvGar27vrAlUjtz0jeEFtrvjxAFqUmYoczAmV0JocRDCppRbHukdb9Ss0
# i5+PWDfDThyvIsoQzdiCEKk18K4iyI8kpoGL3ycc5GYdiT4u/1cDTcFug6Ay67Sz
# L1BWXQaxFYzIHWO3cwzj1nomDyqWRacygz6WPldJdyOJ/rEQx4rlCBVRxStaMVs5
# apaopIhrlihv8cSu6r1FF8xiToG1VBpHjpilbcBuJ8b4Jx/I7SCpC7HxzgualOJq
# nWmDoTbXbSD+hdX/w7iXNgn+PRTBmBSpwIbM74LBq1UkQxi1SIV4htD50p0/GdkU
# ieeNn2gkiGg7qceATibnCCFMY/2ckxVNM7VWYE/XSrk4jv8u3bFfpENryXjPsbtr
# j4Nsh3Kq6qX7n90a1jn8ZMltPgjlfIOxrbyjunvPllakeljLEkdi0iHv/DzEMQv3
# Lz5kpTdvYFA/t0SQT6ALi75+WPbHZ4dh256YxMiMy29H4cAulO2x9rAwbexqSajp
# lnbIvQjE/jv1rnM3BrJWzxnUu/WUyocc8oBqAU+2G4Fzs9NbIj86WBjfiO5nxEmn
# L9wliz1e0Ow0RJEdvJEMdoI+78TYLaEEAo5I+e/dAs8DojCCBgcwggPvoAMCAQIC
# CmEWaDQAAAAAABwwDQYJKoZIhvcNAQEFBQAwXzETMBEGCgmSJomT8ixkARkWA2Nv
# bTEZMBcGCgmSJomT8ixkARkWCW1pY3Jvc29mdDEtMCsGA1UEAxMkTWljcm9zb2Z0
# IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5MB4XDTA3MDQwMzEyNTMwOVoXDTIx
# MDQwMzEzMDMwOVowdzELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEhMB8GA1UEAxMYTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBMIIBIjANBgkqhkiG
# 9w0BAQEFAAOCAQ8AMIIBCgKCAQEAn6Fssd/bSJIqfGsuGeG94uPFmVEjUK3O3RhO
# JA/u0afRTK10MCAR6wfVVJUVSZQbQpKumFwwJtoAa+h7veyJBw/3DgSY8InMH8sz
# JIed8vRnHCz8e+eIHernTqOhwSNTyo36Rc8J0F6v0LBCBKL5pmyTZ9co3EZTsIbQ
# 5ShGLieshk9VUgzkAyz7apCQMG6H81kwnfp+1pez6CGXfvjSE/MIt1NtUrRFkJ9I
# AEpHZhEnKWaol+TTBoFKovmEpxFHFAmCn4TtVXj+AZodUAiFABAwRu233iNGu8Qt
# VJ+vHnhBMXfMm987g5OhYQK1HQ2x/PebsgHOIktU//kFw8IgCwIDAQABo4IBqzCC
# AacwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUIzT42VJGcArtQPt2+7MrsMM1
# sw8wCwYDVR0PBAQDAgGGMBAGCSsGAQQBgjcVAQQDAgEAMIGYBgNVHSMEgZAwgY2A
# FA6sgmBAVieX5SUT/CrhClOVWeSkoWOkYTBfMRMwEQYKCZImiZPyLGQBGRYDY29t
# MRkwFwYKCZImiZPyLGQBGRYJbWljcm9zb2Z0MS0wKwYDVQQDEyRNaWNyb3NvZnQg
# Um9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHmCEHmtFqFKoKWtTHNY9AcTLmUwUAYD
# VR0fBEkwRzBFoEOgQYY/aHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwv
# cHJvZHVjdHMvbWljcm9zb2Z0cm9vdGNlcnQuY3JsMFQGCCsGAQUFBwEBBEgwRjBE
# BggrBgEFBQcwAoY4aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9N
# aWNyb3NvZnRSb290Q2VydC5jcnQwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZI
# hvcNAQEFBQADggIBABCXisNcA0Q23em0rXfbznlRTQGxLnRxW20ME6vOvnuPuC7U
# EqKMbWK4VwLLTiATUJndekDiV7uvWJoc4R0Bhqy7ePKL0Ow7Ae7ivo8KBciNSOLw
# UxXdT6uS5OeNatWAweaU8gYvhQPpkSokInD79vzkeJkuDfcH4nC8GE6djmsKcpW4
# oTmcZy3FUQ7qYlw/FpiLID/iBxoy+cwxSnYxPStyC8jqcD3/hQoT38IKYY7w17gX
# 606Lf8U1K16jv+u8fQtCe9RTciHuMMq7eGVcWwEXChQO0toUmPU8uWZYsy0v5/mF
# hsxRVuidcJRsrDlM1PZ5v6oYemIp76KbKTQGdxpiyT0ebR+C8AvHLLvPQ7Pl+ex9
# teOkqHQ1uE7FcSMSJnYLPFKMcVpGQxS8s7OwTWfIn0L/gHkhgJ4VMGboQhJeGsie
# IiHQQ+kr6bv0SMws1NgygEwmKkgkX1rqVu+m3pmdyjpvvYEndAYR7nYhv5uCwSdU
# trFqPYmhdmG0bqETpr+qR/ASb/2KMmyy/t9RyIwjyWa9nR2HEmQCPS2vWY+45CHl
# tbDKY7R4VAXUQS5QrJSwpXirs6CWdRrZkocTdSIvMqgIbqBbjCW/oO+EyiHW6x5P
# yZruSeD3AWVviQt9yGnI5m7qp5fOMSn/DsVbXNhNG6HY+i+ePy5VFmvJE6P9MIIH
# ejCCBWKgAwIBAgIKYQ6Q0gAAAAAAAzANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0
# IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTEwHhcNMTEwNzA4MjA1OTA5
# WhcNMjYwNzA4MjEwOTA5WjB+MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
# Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQgQ29kZSBTaWduaW5nIFBDQSAyMDEx
# MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAq/D6chAcLq3YbqqCEE00
# uvK2WCGfQhsqa+laUKq4BjgaBEm6f8MMHt03a8YS2AvwOMKZBrDIOdUBFDFC04kN
# eWSHfpRgJGyvnkmc6Whe0t+bU7IKLMOv2akrrnoJr9eWWcpgGgXpZnboMlImEi/n
# qwhQz7NEt13YxC4Ddato88tt8zpcoRb0RrrgOGSsbmQ1eKagYw8t00CT+OPeBw3V
# XHmlSSnnDb6gE3e+lD3v++MrWhAfTVYoonpy4BI6t0le2O3tQ5GD2Xuye4Yb2T6x
# jF3oiU+EGvKhL1nkkDstrjNYxbc+/jLTswM9sbKvkjh+0p2ALPVOVpEhNSXDOW5k
# f1O6nA+tGSOEy/S6A4aN91/w0FK/jJSHvMAhdCVfGCi2zCcoOCWYOUo2z3yxkq4c
# I6epZuxhH2rhKEmdX4jiJV3TIUs+UsS1Vz8kA/DRelsv1SPjcF0PUUZ3s/gA4bys
# AoJf28AVs70b1FVL5zmhD+kjSbwYuER8ReTBw3J64HLnJN+/RpnF78IcV9uDjexN
# STCnq47f7Fufr/zdsGbiwZeBe+3W7UvnSSmnEyimp31ngOaKYnhfsi+E11ecXL93
# KCjx7W3DKI8sj0A3T8HhhUSJxAlMxdSlQy90lfdu+HggWCwTXWCVmj5PM4TasIgX
# 3p5O9JawvEagbJjS4NaIjAsCAwEAAaOCAe0wggHpMBAGCSsGAQQBgjcVAQQDAgEA
# MB0GA1UdDgQWBBRIbmTlUAXTgqoXNzcitW2oynUClTAZBgkrBgEEAYI3FAIEDB4K
# AFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSME
# GDAWgBRyLToCMZBDuRQFTuHqp8cx0SOJNDBaBgNVHR8EUzBRME+gTaBLhklodHRw
# Oi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNSb29DZXJB
# dXQyMDExXzIwMTFfMDNfMjIuY3JsMF4GCCsGAQUFBwEBBFIwUDBOBggrBgEFBQcw
# AoZCaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNSb29DZXJB
# dXQyMDExXzIwMTFfMDNfMjIuY3J0MIGfBgNVHSAEgZcwgZQwgZEGCSsGAQQBgjcu
# AzCBgzA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9w
# cy9kb2NzL3ByaW1hcnljcHMuaHRtMEAGCCsGAQUFBwICMDQeMiAdAEwAZQBnAGEA
# bABfAHAAbwBsAGkAYwB5AF8AcwB0AGEAdABlAG0AZQBuAHQALiAdMA0GCSqGSIb3
# DQEBCwUAA4ICAQBn8oalmOBUeRou09h0ZyKbC5YR4WOSmUKWfdJ5DJDBZV8uLD74
# w3LRbYP+vj/oCso7v0epo/Np22O/IjWll11lhJB9i0ZQVdgMknzSGksc8zxCi1LQ
# sP1r4z4HLimb5j0bpdS1HXeUOeLpZMlEPXh6I/MTfaaQdION9MsmAkYqwooQu6Sp
# BQyb7Wj6aC6VoCo/KmtYSWMfCWluWpiW5IP0wI/zRive/DvQvTXvbiWu5a8n7dDd
# 8w6vmSiXmE0OPQvyCInWH8MyGOLwxS3OW560STkKxgrCxq2u5bLZ2xWIUUVYODJx
# Jxp/sfQn+N4sOiBpmLJZiWhub6e3dMNABQamASooPoI/E01mC8CzTfXhj38cbxV9
# Rad25UAqZaPDXVJihsMdYzaXht/a8/jyFqGaJ+HNpZfQ7l1jQeNbB5yHPgZ3BtEG
# sXUfFL5hYbXw3MYbBL7fQccOKO7eZS/sl/ahXJbYANahRr1Z85elCUtIEJmAH9AA
# KcWxm6U/RXceNcbSoqKfenoi+kiVH6v7RyOA9Z74v2u3S5fi63V4GuzqN5l5GEv/
# 1rMjaHXmr/r8i+sLgOppO6/8MO0ETI7f33VtY5E90Z1WTk+/gFcioXgRMiF670EK
# sT/7qMykXcGhiJtXcVZOSEXAQsmbdlsKgEhr/Xmfwb1tbWrJUnMTDXpQzTGCBLQw
# ggSwAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# KDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTECEzMAAADE
# 6Yn4eoFQ6f8AAAAAAMQwCQYFKw4DAhoFAKCByDAZBgkqhkiG9w0BCQMxDAYKKwYB
# BAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0B
# CQQxFgQUsDs5bHVepLkWEgFcdQLGrsJrbI0waAYKKwYBBAGCNwIBDDFaMFigNoA0
# AE0AaQBjAHIAbwBzAG8AZgB0ACAASABQAEMAIABQAGEAYwBrACAAMgAwADEAMgAg
# AFIAMqEegBxodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vSFBDMA0GCSqGSIb3DQEB
# AQUABIIBAFQMyspL+JU16jLg9u/m8zQydL4L7GIOVvppt6dCMmYfoccbIwegHakq
# bSFxP+eUxiKtSihUlA3tJN2F7AAo8Yw6CC0d+CmU3e/zklL3IxAkzcKhXqsRu0eH
# SB3JZz6klHPYVt+MScjC7b9EGburunn35afHdLCWIPXp2oXvbWMqxbpTyVHV96xA
# b3m8PttZJQU+qBdjpwK0yiG46x2lfo5O4Fg1ZvwmIsPYBhvPG8hKTI5LkPDS8khS
# RZzMANOjcWa8HNKFJA58ThslhOaaNbV+HKDkWilBXFKVytzer2kc9a8DCkptAara
# w61/LyJIXx8Bf+SG1A7uE1Y8mjyK6xKhggIoMIICJAYJKoZIhvcNAQkGMYICFTCC
# AhECAQEwgY4wdzELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAO
# BgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEh
# MB8GA1UEAxMYTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBAhMzAAAAzMu4E+tdci1F
# AAAAAADMMAkGBSsOAwIaBQCgXTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwG
# CSqGSIb3DQEJBTEPFw0xNzA5MTUxMTMxMjNaMCMGCSqGSIb3DQEJBDEWBBRAQQqR
# ugyYmAuzIwioBFxGpelVBjANBgkqhkiG9w0BAQUFAASCAQAL+JMOhzHemAT3YUuy
# 95BIwA4srwvZ2dqiBEg/FSTAQBR6io2Pte55mGQjOOAOnLKdGzJJfC+ikiFN3193
# sQWOrrDAKflTDZlMky/9nZVU7HL60LOgAlNyjbc4sR+AKnuvgsT9tAqPra//hxXX
# EkdJ6kayU4afFOqxC4y/0N6RP0OnhoKrtoh1o1ysTkYof0s2jfQ3D2NriVDs/2sZ
# b3tHjl9XIgAxL1iFxzoj0gAJ/0/UZ1yu+X4CTi2QfqbLhPT6SNsXkAXvCkNuP12C
# sbtenSg4mZKIOE+3WLbgOP2vyMfNJHnvdZ+gBKhbipXXW0ShZSUn01gatU/zhjZa
# NH5v
# SIG # End signature block
