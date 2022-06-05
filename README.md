# КРАТКТОЕ ОПИСАНИЕ
  Получение информации о последнем входе пользователя Active Directory

# ОПИСАНИЕ
  Cкрипт получает список пользователей из файла или группы Active Directory,
  запрашивает по каждому пользователю в Active Directory дополнительную информацию.
  Получает значение полей LastLogon и lastLogonTimestamp, выбирает наибольшее значение,
  и результат помещает в поле LastLogon. Результат выгружается в файл.

# ПАРАМЕТР ADGroupName
  Указывает на группу Active Directory, откуда будет получен список пользователей.

# ПАРАМЕТР UsersLoginsFileName
  Указывает на CSV-файл, откуда будет взят список пользователей.
  Файл обязательно должен содержать заголовок SamAccountName

  Пример файла:

  SamAccountName
  username1
  username2
  ...

# ВВОД
  Скрипт Get-ADUsersLastLogon не принимает параметры через конвейер (pipe).

# ВЫВОД
  Скрипт Get-ADUsersLastLogon создаёт CSV-файл. По-умолчанию,
  создаётся файл с именем ADUsers и к нему добавляется временная метка,
  время запуска файла. Файл сохраняется там-же, откуда был запущен скрипт,
  например ADUsers_050622.csv.

  Так же, скрипт создаёт log-файл. По-умолчанию log-файл
  размещается в C:\Windows\Temp и называется Get-ADUsersLastLogon.log.

# ПРИМЕР 1
  PS> .\Get-ADUsersLastLogon -ADGroupName 'Domain Users'

# ПРИМЕР 2
  PS> .\Get-ADUsersLastLogon -UsersLoginsFileName C:\Users\ADUsers.csv

# Ссылка
  Последняя версия скрипта расположена по ссылке: https://github.com/mdanshin/Get-ADUsersLastLogon
