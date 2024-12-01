# access_policy

Репозиторий содержит примеры из доклада на конференции Golang Conf 2024 ["Декларативная платформа управления доступом: от ролей к динамическим политикам"](https://golangconf.ru/moscow/2024/abstracts/13424).
В коде продемонтрирована работа с декларативными политиками доступа на языке rego.

Автор: Олег Козырев, Senior Golang Developer.  
https://t.me/olezhek28go

Политики можно проверять также с помощью cli под названием **opa**.
Её можно установить на mac через команду `brew install opa`.

Запустить политику с выводом отладочных сообщений, которые печатаются в самой политике через функцию **print()**:  
`opa eval -f raw -d permission_check.rego -i input.json 'data.permission_check.permissionsGranted'`

Пример для политики из папки `cmd/4_complex_policy`
