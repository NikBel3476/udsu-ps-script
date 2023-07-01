Function New-User {
    <#
    .SYNOPSIS
        Создание нового пользователя
    .DESCRIPTION
        Данная функция создает нового пользователя и добавляет его в группу Пользователи
    .EXAMPLE
        #New-User "Student" "Student"
    .PARAMETER Name
        Имя нового пользователя (обязательный параметр)
    .PARAMETER Password
        Пароль (обязательный параметр)
    #>

    [CmdletBinding()]
    param (
        [PARAMETER(Mandatory = $True)][String]$Name,
        [PARAMETER(Mandatory = $True)][String]$Password
    )

    $Usr = Get-WMIObject -class Win32_UserProfile -ComputerName $env:COMPUTERNAME | Where-Object { $_.LocalPath.Split("\")[-1] -eq $Name }
    if ($null -eq $Usr) {
        $securePwd = convertto-securestring $Password -asplaintext -force
        $GroupSID = "S-1-5-32-545"
        New-LocalUser -User $Name -AccountNeverExpires:$true -FullName $Name -Password $securePwd -PasswordNeverExpires:$true
        Add-LocalGroupMember -SID $GroupSID -Member $Name

        Write-Host "-- Created user $Name with password $Password" -foregroundcolor Green
    }
    else {
        Write-Host "-- User $Name has not been created"
    }
}

Function Remove-Users {
    <#
    .SYNOPSIS
        Удаление пользователей
    .DESCRIPTION
        Данная функция удаляет пользователей, которые сейчас не активны и не являются специальными
        Удаляются в том числе рабочий каталог и реестр пользователей
    .EXAMPLE
        #Remove-Users
    #>
    [CmdletBinding()]

    $UsersProfiles = Get-WMIObject -class Win32_UserProfile -ComputerName $env:COMPUTERNAME | Where-Object { !($_.Loaded) -and !($_.Special) }
    foreach ($Usr in $UsersProfiles) {
        $UsrName = $Usr.LocalPath.Split("\")[2]
        Write-Host "-- Deleting user $UsrName ..." -foregroundcolor Green
        Remove-WmiObject -Path $Usr.__PATH
        Remove-LocalUser -Name $UsrName
        Write-Host "-- User $UsrName deleted" -foregroundcolor Green
    }
}

Function Remove-User {
    <#
    .SYNOPSIS
        Удаление пользователя
    .DESCRIPTION
        Данная функция удаляет пользователя
        Удаляются в том числе рабочий каталог и реестр пользователя
    .EXAMPLE
        #Remove-User -Name "Student"
    #>
    [CmdletBinding()]
    param (
        [PARAMETER(Mandatory = $True)][String]$Name
    )

    $UsrWmi = Get-WMIObject -class Win32_UserAccount -ComputerName $env:COMPUTERNAME | Where-Object { $_.Name -eq $Name }
    if ($UsrWmi) {
        # $UsrName = $UsrWmi.LocalPath.Split("\")[-1]
        $UsrName = $UsrWmi.Name
        Write-Host "-- Deleting WMI user $UsrName ..." -foregroundcolor Green
        # Remove-LocalUser -Name $UsrName
        Remove-LocalUser -SID $UsrWmi.SID    
        # Remove-WmiObject -Path $Usr.__PATH
        Write-Host "-- User WMI $UsrName deleted" -foregroundcolor Green
    }
    else {
        Write-Host "-- User WMI $UsrName not found"
    }

    $UsrCim = Get-CIMInstance -class Win32_UserProfile | Where-Object { $_.LocalPath.EndsWith($Name) }
    if ($UsrCim) {
        $taskName = "DeleteUserCIM"
        if ($UsrCim.Loaded) {
            Write-Host "-- User CIM $Name is Loaded now, computer will be restarted. You MUST log in as high priveleged user at startup!!!"
            $PathToWinlogon = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
            if (Test-RegistryValue -Path $PathToWinlogon -Name AutoAdminLogon) {
                Set-ItemProperty -Path $PathToWinlogon -Name AutoAdminLogon  -Value 0
            }
            else {
                New-ItemProperty -Path $PathToWinlogon -Name AutoAdminLogon  -Value 0 -PropertyType "String"
            }
            Write-Host "-- Winlogon disabled"

            $scriptPath = "C:\Scripts\run_as_admin.ps1"
            $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-File $scriptPath"
            $trigger = New-ScheduledTaskTrigger -AtLogon
            $principal = New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest
            $settings = New-ScheduledTaskSettingsSet
            $task = New-ScheduledTask -Action $action -Principal $principal -Trigger $trigger -Settings $settings
            Register-ScheduledTask -TaskName $taskName -InputObject $task -Force
            # schtasks /create /tn $taskName /tr "powershell -File $scriptPath" /sc onlogon /ru $env:USERDOMAIN\$env:USERNAME /f
            # schtasks /create /tn $taskName /tr "powershell Start-Process powershell -verb runas -ArgumentList "-File $scriptPath"" /sc onlogon /f
            write-host "-- Scheduled task to remove user profile" -foregroundcolor Green
            # shutdown /r /t 60 /c "Computer will be rebooted with 60 seconds"
            for (($i = 20); $i -gt 0; $i--) {
                write-host "The system will reboot in $i sec"
                Start-Sleep -Seconds 1
            }
            
            Restart-Computer
            exit
        }

        # remove task scheduled above
        $task = Get-ScheduledTask | Where-Object { $_.TaskName -eq $taskName } | Select-Object -First 1
        if ($null -ne $task) {
            $taskNameToRemove = $task.TaskName
            Unregister-ScheduledTask $taskNameToRemove -Confirm:$false
            # schtasks /delete /tn $taskName /f
            Write-Host "-- Task $taskNameToRemove unregistered"
        }

        $UsrName = $UsrCim.LocalPath.Split("\")[-1]
        Write-Host "-- Deleting CIM user $UsrName ..." -foregroundcolor Green
        Remove-CimInstance -InputObject $UsrCim
        Write-Host "-- User CIM $UsrName deleted" -foregroundcolor Green
    }
    else {
        Write-Host "-- User CIM $UsrName not found"
    }
}

# TODO: try it
# function Remove-LocalUserCompletely {

#     Param(
#         [Parameter(ValueFromPipelineByPropertyName)]
#         $Name
#     )

#     process {
#         $user = Get-LocalUser -Name $Name -ErrorAction Stop

#         # Remove the user from the account database
#         Remove-LocalUser -SID $user.SID

#         # Remove the profile of the user (both, profile directory and profile in the registry)
#         Get-CimInstance -Class Win32_UserProfile | ? SID -eq $user.SID | Remove-CimInstance
#     }
# }

# Example usage:
# Remove-LocalUserCompletely -Name 'myuser'

Function Test-RegistryValue {
    param(
        [Alias("PSPath")]
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [String]$Path
        ,
        [Parameter(Position = 1, Mandatory = $true)]
        [String]$Name
        ,
        [Switch]$PassThru
    ) 

    process {
        if (Test-Path $Path) {
            $Key = Get-Item -LiteralPath $Path
            if ($null -ne $Key.GetValue($Name, $null)) {
                if ($PassThru) {
                    Get-ItemProperty $Path $Name
                }
                else {
                    $true
                }
            }
            else {
                $false
            }
        }
        else {
            $false
        }
    }
}

Function Set-AutoLogon {
    <#
    .SYNOPSIS
        Включение автовхода для пользователя
    .DESCRIPTION
        Данная функция включает автовход для указанного пользователя
    .EXAMPLE
        #Set-AutoLogon  "Student" "Student"
    .PARAMETER Name
        Имя пользователя (обязательный параметр)
    .PARAMETER Password
        Пароль (обязательный параметр)
    #>

    [CmdletBinding()]
    param (
        [PARAMETER(Mandatory = $True)][String]$Name,
        [PARAMETER(Mandatory = $True)][String]$Password
    )

    $PathToWinlogon = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
    if (Test-RegistryValue -Path $PathToWinlogon -Name AutoAdminLogon) {
        Set-ItemProperty -Path $PathToWinlogon -Name AutoAdminLogon  -Value 1  
    }
    else {
        New-ItemProperty -Path $PathToWinlogon -Name AutoAdminLogon  -Value 1 -PropertyType "String"
    }
    if (Test-RegistryValue -Path $PathToWinlogon -Name DefaultUserName) {
        Set-ItemProperty -Path $PathToWinlogon -Name DefaultUserName -Value $Name
    }
    else {
        New-ItemProperty -Path $PathToWinlogon -Name DefaultUserName -Value $Name -PropertyType "String"
    }
    if (Test-RegistryValue -Path $PathToWinlogon -Name DefaultPassword) {
        Set-ItemProperty -Path $PathToWinlogon -Name DefaultPassword -Value $Password
    }
    else {
        New-ItemProperty -Path $PathToWinlogon -Name DefaultPassword -Value $Password -PropertyType "String"
    }

    Write-Host "-- Enabled winlogon for user $Name" -foregroundcolor Green
}

$Source = @'
using System;
using System.Collections.Generic;
using System.Text;

namespace MyLsaWrapper
{
    using System.Runtime.InteropServices;
    using System.Security;
    using System.Management;
    using System.Runtime.CompilerServices;
    using System.ComponentModel;

    using LSA_HANDLE = IntPtr;

    [StructLayout(LayoutKind.Sequential)]
    struct LSA_OBJECT_ATTRIBUTES
    {
        internal int Length;
        internal IntPtr RootDirectory;
        internal IntPtr ObjectName;
        internal int Attributes;
        internal IntPtr SecurityDescriptor;
        internal IntPtr SecurityQualityOfService;
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct LSA_UNICODE_STRING
    {
        internal ushort Length;
        internal ushort MaximumLength;
        [MarshalAs(UnmanagedType.LPWStr)]
        internal string Buffer;
    }
    sealed class Win32Sec
    {
        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true),
        SuppressUnmanagedCodeSecurityAttribute]
        internal static extern uint LsaOpenPolicy(
        LSA_UNICODE_STRING[] SystemName,
        ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
        int AccessMask,
        out IntPtr PolicyHandle
        );

        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true),
        SuppressUnmanagedCodeSecurityAttribute]
        internal static extern uint LsaAddAccountRights(
        LSA_HANDLE PolicyHandle,
        IntPtr pSID,
        LSA_UNICODE_STRING[] UserRights,
        int CountOfRights
        );

        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true),
        SuppressUnmanagedCodeSecurityAttribute]
        internal static extern int LsaLookupNames2(
        LSA_HANDLE PolicyHandle,
        uint Flags,
        uint Count,
        LSA_UNICODE_STRING[] Names,
        ref IntPtr ReferencedDomains,
        ref IntPtr Sids
        );

        [DllImport("advapi32")]
        internal static extern int LsaNtStatusToWinError(int NTSTATUS);

        [DllImport("advapi32")]
        internal static extern int LsaClose(IntPtr PolicyHandle);

        [DllImport("advapi32")]
        internal static extern int LsaFreeMemory(IntPtr Buffer);

    }
    /// <summary>
    /// This class is used to grant "Log on as a service", "Log on as a batchjob", "Log on localy" etc.
    /// to a user.
    /// </summary>
    public sealed class LsaWrapper : IDisposable
    {
        [StructLayout(LayoutKind.Sequential)]
        struct LSA_TRUST_INFORMATION
        {
            internal LSA_UNICODE_STRING Name;
            internal IntPtr Sid;
        }
        [StructLayout(LayoutKind.Sequential)]
        struct LSA_TRANSLATED_SID2
        {
            internal SidNameUse Use;
            internal IntPtr Sid;
            internal int DomainIndex;
            uint Flags;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct LSA_REFERENCED_DOMAIN_LIST
        {
            internal uint Entries;
            internal LSA_TRUST_INFORMATION Domains;
        }

        enum SidNameUse : int
        {
            User = 1,
            Group = 2,
            Domain = 3,
            Alias = 4,
            KnownGroup = 5,
            DeletedAccount = 6,
            Invalid = 7,
            Unknown = 8,
            Computer = 9
        }

        enum Access : int
        {
            POLICY_READ = 0x20006,
            POLICY_ALL_ACCESS = 0x00F0FFF,
            POLICY_EXECUTE = 0X20801,
            POLICY_WRITE = 0X207F8
        }
        const uint STATUS_ACCESS_DENIED = 0xc0000022;
        const uint STATUS_INSUFFICIENT_RESOURCES = 0xc000009a;
        const uint STATUS_NO_MEMORY = 0xc0000017;

        IntPtr lsaHandle;

        public LsaWrapper()
            : this(null)
        { }
        // // local system if systemName is null
        public LsaWrapper(string systemName)
        {
            LSA_OBJECT_ATTRIBUTES lsaAttr;
            lsaAttr.RootDirectory = IntPtr.Zero;
            lsaAttr.ObjectName = IntPtr.Zero;
            lsaAttr.Attributes = 0;
            lsaAttr.SecurityDescriptor = IntPtr.Zero;
            lsaAttr.SecurityQualityOfService = IntPtr.Zero;
            lsaAttr.Length = Marshal.SizeOf(typeof(LSA_OBJECT_ATTRIBUTES));
            lsaHandle = IntPtr.Zero;
            LSA_UNICODE_STRING[] system = null;
            if (systemName != null)
            {
                system = new LSA_UNICODE_STRING[1];
                system[0] = InitLsaString(systemName);
            }

            uint ret = Win32Sec.LsaOpenPolicy(system, ref lsaAttr,
            (int)Access.POLICY_ALL_ACCESS, out lsaHandle);
            if (ret == 0)
                return;
            if (ret == STATUS_ACCESS_DENIED)
            {
                throw new UnauthorizedAccessException();
            }
            if ((ret == STATUS_INSUFFICIENT_RESOURCES) || (ret == STATUS_NO_MEMORY))
            {
                throw new OutOfMemoryException();
            }
            throw new Win32Exception(Win32Sec.LsaNtStatusToWinError((int)ret));
        }

        public void AddPrivileges(string account, string privilege)
        {
            IntPtr pSid = GetSIDInformation(account);
            LSA_UNICODE_STRING[] privileges = new LSA_UNICODE_STRING[1];
            privileges[0] = InitLsaString(privilege);
            uint ret = Win32Sec.LsaAddAccountRights(lsaHandle, pSid, privileges, 1);
            if (ret == 0)
                return;
            if (ret == STATUS_ACCESS_DENIED)
            {
                throw new UnauthorizedAccessException();
            }
            if ((ret == STATUS_INSUFFICIENT_RESOURCES) || (ret == STATUS_NO_MEMORY))
            {
                throw new OutOfMemoryException();
            }
            throw new Win32Exception(Win32Sec.LsaNtStatusToWinError((int)ret));
        }

        public void Dispose()
        {
            if (lsaHandle != IntPtr.Zero)
            {
                Win32Sec.LsaClose(lsaHandle);
                lsaHandle = IntPtr.Zero;
            }
            GC.SuppressFinalize(this);
        }
        ~LsaWrapper()
        {
            Dispose();
        }
        // helper functions

        IntPtr GetSIDInformation(string account)
        {
            LSA_UNICODE_STRING[] names = new LSA_UNICODE_STRING[1];
            LSA_TRANSLATED_SID2 lts;
            IntPtr tsids = IntPtr.Zero;
            IntPtr tdom = IntPtr.Zero;
            names[0] = InitLsaString(account);
            lts.Sid = IntPtr.Zero;
            //Console.WriteLine("String account: {0}", names[0].Length);
            int ret = Win32Sec.LsaLookupNames2(lsaHandle, 0, 1, names, ref tdom, ref tsids);
            if (ret != 0)
                throw new Win32Exception(Win32Sec.LsaNtStatusToWinError(ret));
            lts = (LSA_TRANSLATED_SID2)Marshal.PtrToStructure(tsids,
            typeof(LSA_TRANSLATED_SID2));
            Win32Sec.LsaFreeMemory(tsids);
            Win32Sec.LsaFreeMemory(tdom);
            return lts.Sid;
        }

        static LSA_UNICODE_STRING InitLsaString(string s)
        {
            // Unicode strings max. 32KB
            if (s.Length > 0x7ffe)
                throw new ArgumentException("String too long");
            LSA_UNICODE_STRING lus = new LSA_UNICODE_STRING();
            lus.Buffer = s;
            lus.Length = (ushort)(s.Length * sizeof(char));
            lus.MaximumLength = (ushort)(lus.Length + sizeof(char));
            return lus;
        }
    }
    public class LsaWrapperCaller
    {
        public static void AddPrivileges(string account, string privilege)
        {
            using (LsaWrapper lsaWrapper = new LsaWrapper())
            {
                lsaWrapper.AddPrivileges(account, privilege);
            }
        }
    }
}
'@

Add-Type -TypeDefinition $Source | Out-Null


# -------------------------
# Пересоздание пользователя
# -------------------------
$UserName = "Student"
$Password = "Student"

# Remove-Users | Out-Null
Remove-User -Name $UserName
New-User $UserName $Password | Out-Null
Set-AutoLogon $UserName $Password | Out-Null
[MyLsaWrapper.LsaWrapperCaller]::AddPrivileges($UserName, "SeBatchLogonRight") | Out-Null
write-host "-- Allowed to log in as a batch job for the user $UserName" -foregroundcolor Green
# Set-AccessRule -Folder "C:\Users\$UserName\Desktop\" -UserName $env:USERNAME -Rules "CreateFiles, AppendData, Delete" -AccessControlType "Deny"

$setupUserScriptPath = "C:\Scripts\SetupUser.ps1"
# New-Item -ItemType File -Path $setupUserScriptPath -Force | Out-Null
# Copy-Item ".\SetupUser.ps1" $setupUserScriptPath -Force
# schtasks /create /tn "SetUserSettingsOnLogon" /tr "powershell -File $setupUserScriptPath" /sc onlogon /ru $env:USERDOMAIN\$UserName /rp $Password /f
$setupUserTaskName = "SetUserSettingsOnLogon"
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-File $setupUserScriptPath"
$trigger = New-ScheduledTaskTrigger -AtLogon
$principal = New-ScheduledTaskPrincipal -UserId $env:USERDOMAIN\$UserName -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet
$task = New-ScheduledTask -Action $action -Principal $principal -Trigger $trigger -Settings $settings
Register-ScheduledTask -TaskName $setupUserTaskName -InputObject $task -Force | Out-Null
write-host "-- Scheduled task to setup user $UserName" -foregroundcolor Green
# $taskObject = Get-ScheduledTask $setupUserTaskName
# $taskObject.Author = "$env:USERDOMAIN\$UserName"
# $taskObject | Set-ScheduledTask | Out-Null
# write-host "-- Task to setup user $UserName updated" -foregroundcolor Green

# shutdown /r /t 60 /c "Computer will be rebooted with 60 seconds"

for (($i = 20); $i -gt 0; $i--) {
    write-host "The system will reboot in $i sec"
    Start-Sleep -Seconds 1
}

Restart-Computer