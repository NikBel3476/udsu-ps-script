Function Set-Proxy {
    <#
    .SYNOPSIS
        Установка параметров прокси
    .DESCRIPTION
        Данная функция задает параметры прокси для пользователя
    .EXAMPLE
        #Set-Proxy a.cproxy.ru 8080
    .PARAMETER Server
        Адрес или доменное имя сервера (обязательный параметр)
    .PARAMETER Port
        Порт (обязательный параметр)
    #>

    [CmdletBinding()]
    param (
        [PARAMETER(Mandatory=$True)][String]$Server,
        [PARAMETER(Mandatory=$True)][Int]$Port
        )

	If ((Test-NetConnection -ComputerName $Server -Port $Port).TcpTestSucceeded) {
		Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -name ProxyServer -Value "$($Server):$($Port)"
        Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -name ProxyOverride -Value "<local>"
		Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -name ProxyEnable -Value 1
	} Else {
		Write-Error -Message "-- Invalid proxy server address or port:  $($Server):$($Port)"
	}
}

Function Set-AccessRule {
    <#
    .SYNOPSIS
        Установка правк на папку
    .DESCRIPTION
        Данная функция устанавливает заданные права на дирректорию
    .EXAMPLE
        #Set-AccessRule -Folder $env:USERPROFILE\Desktop\  -UserName $env:USERNAME -Rules CreateFiles,AppendData -AccessControlType Deny
    .PARAMETER Folder
        Дирректория, над которой производится действие (обязательный параметр)
    .PARAMETER UserName
        Имя учетной записи пользователя, для кого задаются права доступа (обязательный параметр)
    .PARAMETER Rules
        Права доступа через запятую(обязательный параметр)
    .PARAMETER AccessControlType
        Обязательный параметр, который может принмать одно из двух значений: Allow или Deny
    #>
    [CmdletBinding()]
    param (
        [PARAMETER(Mandatory=$True)][String]$Folder,
        [PARAMETER(Mandatory=$True)][String]$UserName,
        [PARAMETER(Mandatory=$True)][String]$Rules,
        [PARAMETER(Mandatory=$True)][String]$AccessControlType
        )

    #считываем текущий список ACL рабочего стола
    $acl = Get-Acl -Path $Folder
    #Создаем переменню с нужными правами
    $fileSystemRights = [System.Security.AccessControl.FileSystemRights]"$Rules"
    #Cоздаем переменную с указанием пользователя, прав доступа и типа разрешения
    $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($UserName, $fileSystemRights, $AccessControlType)
    #Передаем переменную в класс FileSystemAccessRule для создания объекта
    $acl.SetAccessRule($AccessRule)
    #Применяем разрешения к папке
    # $acl | Set-Acl $Folder
    Set-Acl -Path $Folder -AclObject $acl
}

function Set-PinnedApplication
{
    <#
    .SYNOPSIS
        Управление ярлыками на панели управления
    .DESCRIPTION
        Данная функция добавляет или удаляет ярлыки на панели управления пользователя
    .EXAMPLE
        #Set-PinnedApplication -Action UnpinfromTaskbar -FilePath "$env:ProgramFiles\Internet Explorer\iexplore.exe"
    .EXAMPLE
        #Set-PinnedApplication -Action PintoTaskbar -FilePath "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe"
    .PARAMETER Action
        Обязательный параметр, который может принимать одно из двух значений: UnpinfromTaskbar или PintoTaskbar
    .PARAMETER FilePath
        Имя учетной записи пользователя, для кого задаются права доступа (обязательный параметр)
    #>
    [CmdletBinding()]
    param(
            [Parameter(Mandatory=$True)][String]$Action, 
            [Parameter(Mandatory=$True)][String]$FilePath
    )
    if(-not (test-path $FilePath)) { 
        throw "FilePath does not exist."  
    }
    function InvokeVerb {
        param([string]$FilePath,$verb)
        $verb = $verb.Replace("&","")
        $path = split-path $FilePath
        $shell = new-object -com "Shell.Application" 
        $folder = $shell.Namespace($path)   
        $item = $folder.Parsename((split-path $FilePath -leaf))
        $itemVerb = $item.Verbs() | ? {$_.Name.Replace("&","") -eq $verb}
        if($itemVerb -eq $null){
            throw "Verb $verb not found."           
        } else {
            $itemVerb.DoIt()
        }
    }
    function GetVerb {
        param([int]$verbId)
        try {
            $t = [type]"CosmosKey.Util.MuiHelper"
        } catch {
            $def = [Text.StringBuilder]""
            [void]$def.AppendLine('[DllImport("user32.dll")]')
            [void]$def.AppendLine('public static extern int LoadString(IntPtr h,uint id, System.Text.StringBuilder sb,int maxBuffer);')
            [void]$def.AppendLine('[DllImport("kernel32.dll")]')
            [void]$def.AppendLine('public static extern IntPtr LoadLibrary(string s);')
            Add-Type -MemberDefinition $def.ToString() -name MuiHelper -namespace CosmosKey.Util            
        }
        if($global:CosmosKey_Utils_MuiHelper_Shell32 -eq $null){        
            $global:CosmosKey_Utils_MuiHelper_Shell32 = [CosmosKey.Util.MuiHelper]::LoadLibrary("shell32.dll")
        }
        $maxVerbLength=255
        $verbBuilder = New-Object Text.StringBuilder "",$maxVerbLength
        [void][CosmosKey.Util.MuiHelper]::LoadString($CosmosKey_Utils_MuiHelper_Shell32,$verbId,$verbBuilder,$maxVerbLength)
        return $verbBuilder.ToString()
    }
    $verbs = @{ 
        "PintoTaskbar"=5386
        "UnpinfromTaskbar"=5387
    }
    if($verbs.$Action -eq $null){
        Throw "Action $action not supported`nSupported actions are:`n`tPintoTaskbar`n`tUnpinfromTaskbar"
    }
    InvokeVerb -FilePath $FilePath -Verb $(GetVerb -VerbId $verbs.$action)
}

Set-Proxy cproxy.udsu.ru 8080
Set-AccessRule -Folder $env:USERPROFILE\Desktop\ -UserName $env:USERNAME -Rules "CreateFiles, AppendData, Delete" -AccessControlType "Deny"

# Set-PinnedApplication -Action UnpinfromTaskbar -FilePath "$env:ProgramFiles\Internet Explorer\iexplore.exe"
# Set-PinnedApplication -Action PintoTaskbar -FilePath "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe"
# Set-PinnedApplication -Action PintoTaskbar -FilePath "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Office 2013\Excel 2013.lnk"
# Set-PinnedApplication -Action PintoTaskbar -FilePath "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Office 2013\Word 2013.lnk"
# Set-PinnedApplication -Action PintoTaskbar -FilePath "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Office 2013\PowerPoint 2013.lnk"
# Set-PinnedApplication -Action PintoTaskbar -FilePath "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\АСКОН\КОМПАС-3D V16\КОМПАС-3D V16.lnk"

# Удаление задачи, после ее выполнения
Unregister-ScheduledTask -TaskName UdSUSettingStudent -Confirm:$false