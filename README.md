# Набор скриптов PowerShell для помощи администрирования компьютерных классов

Инструкция:
1. Выйти из учётной записи 'Student' и войти в учётную запись администратора
2. Подождать ~20 секунд, так как процессы, связанные с учётной записью Student не сразу прекращают свою работу  
   (Опционально) Проверить статус загрузки профиля можно следующим образом:
   * В терминале PowerShell выполнить команду `get-wmiobject -class win32_userprofile`
   * Найти профиль Student
   * Атрибут профиля 'Loaded' должен иметь значение 'False'
3. Создать папку 'scripts' в корне диска 'C' (Абсолюный путь - C:\scripts)
4. Скопировать все файлы из папки, в которой лежит этот README.md
в только что созданную папку (C:\scripts)
5. Открыть PowerShell с правами администратора
6. Выполнить команду: `cd C:/scripts`
7. Выполнить команду: `.\run_as_admin.ps1`
8. Если возникла следующая ошибка:  
`... выполнение сценариев отключено в этой системе ...`, то необходимо
выполнить команду `Set-ExecutionPolicy RemoteSigned`
и на появившийся вопрос ответить символом `A`, затем снова выполнить команду `.\run_as_admin.ps1` 
9. Дождаться перезагрузки. После перезагрузки должно появиться приветствие для нового пользователя
10. Ввести пароль, когда появится окно ввода пароля администратора