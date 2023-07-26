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

# Подключаем параметры, необходимые для работы скрипта
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

# Формирование имени выходного файла с данными пользователей
$ReportFileName = "ADUsers_{0:dd}{0:MM}{0:yy}.csv" -f [datetime]::Parse((Get-Date))
$ReportPath = Join-Path -Path (Get-Location).Path -ChildPath $ReportFileName

# Формирование пути к файлу с пользователями
$UsersLoginsPath = (Join-Path -Path (Get-Location).Path -ChildPath $UsersLoginsFileName)

# Путь к log-файлу
# $LogPath = "C:\Windows\Temp"

# Расскомментировать, если нужно писать лог в отдельные файлы, с timestamp в имени файла
# Например: Get-ADUsersLastLogon_1690400223.log
# $LogName = "Get-ADUsersLastLogon_{0:G}.log" -f [int][double]::Parse((Get-Date -UFormat %s))

# Расскомментировать, если нужно писать лог в единый файл
# Например: Get-ADUsersLastLogon.log
$LogName = "Get-ADUsersLastLogon.log"

if ($LogPath -ne $null) {
  $LogFile = Join-Path -Path $LogPath -ChildPath $LogName
} else {
  $LogFile = $LogName
}

# Функция для получения данных о последнем входе пользователя на контроллере домена
function Get-ADUserLastLogonOnDC {
    param (
        [string]$Username
    )

    # Получение всех контроллеров домена
    $domainControllers = Get-ADDomainController -Filter *
    $lastLogons = @()

    # Перебор всех контроллеров домена для получения информации о пользователе
    foreach ($dc in $domainControllers) {
        $dcName = $dc.HostName
        $user = Get-ADUser -Identity $Username -Server $dcName -Properties LastLogon, LastLogonTimestamp -ErrorAction SilentlyContinue

        if ($user) {
            $lastLogon1 = $user.LastLogon
            $lastLogon2 = $user.LastLogonTimestamp

            # Выбор наибольшего значения из двух полей lastLogon и lastLogonTimestamp
            if ($lastLogon1 -gt $lastLogon2) {
                $lastLogon = $lastLogon1
            } elseif ($lastLogon2 -ne 0) {
                $lastLogon = $lastLogon2
            } else {
                $lastLogon = $lastLogon1
            }

            # Добавление информации о последнем входе пользователя в массив
            $lastLogons += [PSCustomObject]@{
                Username = $Username
                LastLogon = [DateTime]::FromFileTime($lastLogon)
                DomainController = $dcName
            }
        }
    }

    return $lastLogons
}

# Функция для записи информации в лог
function Write-Log {
    Param ([string]$Entry)
    $TimeStamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")
    $LogMessage = "$TimeStamp $Entry"

    Add-Content $LogFile -value $LogMessage -Encoding UTF8
    Write-Host $LogMessage -ForegroundColor Cyan
}

# Если указан параметр ADGroupName, то получаем пользователей из группы
if ($ADGroupName) {
    try {
        # Получить пользователей из группы Active Directory
        $ADGroup = Get-ADGroup $ADGroupName -ErrorAction Stop
        Write-Log("Получение данных о пользователях из группы $ADGroupName")
        $Users = Get-ADGroupMember -Identity $ADGroup
        Write-Log("Найдено пользователей: $($Users.Count)")
        $UsersLogins = $Users.SamAccountName
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        Write-Log("Группа $ADGroupName не найдена в Active Directory")
        throw "Группа $ADGroupName не найдена в Active Directory"
    }
}
else {
    # Если указан параметр UsersLoginsFileName, то получаем пользователей из файла
    Write-Log("Получение данных о пользователях из файла $UsersLoginsPath")

    try {
        $Users = (Import-Csv -Path $UsersLoginsFileName)
        $UsersLogins = $Users.SamAccountName
        Write-Log("Найдено пользователей: $($UsersLogins.count)")
    } catch [System.IO.FileNotFoundException]{
        Write-Log("Файл $UsersLoginsPath не найден")
        throw "Файл $UsersLoginsPath не найден"
    } catch {
        Write-Log( $PSItem.Exception.FileName )
    }
}

# Получить по пользователям информацию из Active Directory
Write-Log('Начинаем сбор данных о пользователях Active Directory')
$ADUsers = $UsersLogins | ForEach-Object {
    $userLogons = Get-ADUserLastLogonOnDC -Username $_

    if ($userLogons.Count -gt 0) {
        $latestLogon = $userLogons | Sort-Object -Property LastLogon | Select-Object -Last 1
        $latestLogon
    }
}

# Выгрузить в CSV
$ADUsers | Export-Csv `
    -Path $ReportFileName `
    -Encoding UTF8 `
    -NoTypeInformation

Write-Log( "Данные сохранены в файл $ReportPath" )
Write-Log( "Log сохранён в файл' $LogFile" )

# Отображение результата в консоле
$ADUsers | Format-Table

# Вывести ошибки (не найденных пользователей)
if (![string]::IsNullOrEmpty($NotFoundedUsers)) {
    Write-Log('The following users were not found in Active Directory:')

    foreach ($item in $NotFoundedUsers) {
        Write-Log( $item.TargetObject.ToString() )
    }
}
