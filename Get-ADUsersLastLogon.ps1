<#
  .SYNOPSIS
  Получение информации о последнем входе пользователя Active Directory

  .DESCRIPTION
  Cкрипт получает список пользователей из файла или группы Active Directory,
  запрашивает по каждому пользователю в Active Directory дополнительную информацию.
  Получает значение полей LastLogon и lastLogonTimestamp, выбирает наибольшее значение,
  и результат помещает в поле LastLogon. Результат выгружается в файл.

  ВАЖНО:

  При LDAP авторизации:

  BadLogonCount - меняется
  lastlogon и lastLogonTimeStamp - меняется
  logoncount - НЕ меняется

  .PARAMETER ADGroupName
  Указывает на группу Active Directory, откуда будет получен список пользователей.

  .PARAMETER UsersLoginsFileName
  Указывает на CSV-файл, откуда будет взят список пользователей.
  Файл обязательно должен содержать заголовок SamAccountName

  Пример файла:

  SamAccountName
  username1
  username2
  ...

  .INPUTS
  Скрипт Get-ADUsersLastLogon не принимает параметры через конвейер (pipe).

  .OUTPUTS
  Скрипт Get-ADUsersLastLogon создаёт CSV-файл. По-умолчанию,
  создаётся файл с именем ADUsers и к нему добавляется временная метка,
  время запуска файла. Файл сохраняется там-же, откуда был запущен скрипт,
  например ADUsers_050622.csv.

  Так же, скрипт создаёт log-файл. По-умолчанию log-файл
  размещается в C:\Windows\Temp и называется Get-ADUsersLastLogon.log.

  .EXAMPLE
  PS> .\Get-ADUsersLastLogon -ADGroupName 'Domain Users'

  .EXAMPLE
  PS> .\Get-ADUsersLastLogon -UsersLoginsFileName C:\Users\ADUsers.csv

  .LINK
  Последняя версия скрипта расположена по ссылке: https://github.com/mdanshin/Get-ADUsersLastLogon
#>

Param (
    [Parameter(Mandatory = $true,
        ParameterSetName = "Group")]
    [String]
    $ADGroupName,

    [Parameter(Mandatory = $true,
        ParameterSetName = "File")]
    [String]
    $UsersLoginsFileName
)

$ReportFileName = "ADUsers_{0:dd}{0:MM}{0:yy}.csv" -f [datetime]::Parse((Get-Date))
$ReportPath = Join-Path -Path (Get-Location).Path -ChildPath $ReportFileName
$UsersLoginsPath = (Join-Path -Path (Get-Location).Path -ChildPath $UsersLoginsFileName)

# Пусть к log-файлу
$LogPath = "C:\Windows\Temp"

# Расскомментироваь, если нужно писать лог в отдельные файлы, с timestamp в имени файла
#$LogName = "Get-ADUsersLastLogon_{0:G}.log" -f [int][double]::Parse((Get-Date -UFormat %s))

# Писать лог в единый файл
$LogName = "Get-ADUsersLastLogon.log"

$LogFile = Join-Path -Path $LogPath -ChildPath $LogName

function Write-Log {
    Param ([string]$Entry)
    $TimeStamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")
    $LogMessage = "$TimeStamp $Entry"
    Add-Content $LogFile -value $LogMessage -Encoding UTF8
    Write-Host $LogMessage -ForegroundColor Cyan
}

if ($ADGroupName) {
    try {
        # Получить пользователей из группы
        $ADGroup = Get-ADGroup $ADGroupName -ErrorAction Stop
        Write-Log("Получение данных о пользователях из группы $ADGroupName")
        $Users = Get-ADGroupMember -Identity $ADGroup
        Write-Log("Найдено пользователей: $($Users.Count)")
        $UsersLogins = $Users.SamAccountName
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        Write-Log("Группа $ADGroupName не найдена Active Directory")
        throw "Группа $ADGroupName не найдена Active Directory"
    }
}
else {
    # Получить пользователей из файла
    Write-Log("Получение данных о пользователях из файла $UsersLoginsPath")

    try {
        $Users = (Import-Csv -Path $UsersLoginsFileName)
        $UsersLogins = $Users.SamAccountName
        Write-Log("Найдено пользователей: $($UsersLogins.count)" )
    } catch [System.IO.FileNotFoundException]{
        Write-Log("Файл $UsersLoginsPath не найден")
        throw "Файл $UsersLoginsPath не найден"
    } catch {
        Write-Log( $PSItem.Exception.FileName )
    }
}

# Получить по пользователям информацию из AD
Write-Log( 'Начинаем сбор данных о пользователях Active Directory' )
$ADUsers = $UsersLogins | `
    Get-ADUser -Properties * -ErrorVariable NotFoundedUsers | `
    Select-Object `
    Name, `
    SamAccountName, `
    @{
        N = 'pwdLastSet';
        E = {
            if ($null -eq $_.pwdLastSet -or $_.pwdLastSet -eq 0 ) {
                'NULL'
            }
            else {
                [DateTime]::FromFileTime($_.pwdLastSet )
            }
        }
    },
    @{
        # The last time the user logged on. This value is stored as a large
        # integer that represents the number of 100-nanosecond intervals since
        # January 1, 1601 (UTC). A value of 0 or 0x7FFFFFFFFFFFFFFF (9223372036854775807)
        # means that the last logon time is unknown.
        # w32tm.exe /ntte 9223372036854775807
        Name       = 'LastLogon';
        Expression =
        {
            if ( ($null -eq $_.LastLogon -And $null -eq $_.lastLogonTimestamp) `
                    -or ($_.LastLogon -eq 0 -And $_.lastLogonTimestamp -eq 0) `
                    -or ($_.LastLogon -eq 9223372036854775807 -And $_.lastLogonTimestamp -eq 9223372036854775807) `
                    -or ($_.LastLogon -eq '1/1/1601 3:00:00 AM' -And $_.lastLogonTimestamp -eq '1/1/1601 3:00:00 AM') `
                    -or ($_.LastLogon -eq 0 -And $null -eq $_.lastLogonTimestamp) `
                    -or ($null -eq $_.LastLogon -And $_.lastLogonTimestamp -eq 0) `
            ) {
                'NULL'
            }
            else {
                if ($_.LastLogon -gt $_.lastLogonTimestamp) {
                    [DateTime]::FromFileTime($_.LastLogon )
                }
                else {
                    [DateTime]::FromFileTime($_.lastLogonTimestamp)
                }
            }
        }
    }

# Выгрузить в PST
$ADUsers | Export-Csv `
    -Path $ReportFileName `
    -Encoding UTF8 `
    -NoTypeInformation

Write-Log( "Данные сохранены в файл $ReportPath" )
Write-Log( "Log сохранён в файл' $LogFile" )

# Вывести ошибки (не найденных пользователей)
if (![string]::IsNullOrEmpty($NotFoundedUsers)) {
    Write-Log('The following users were not found in Active Directory:')

    foreach ($item in $NotFoundedUsers) {
        Write-Log( $item.TargetObject.ToString() )
    }
}