# access_policy

Политики можно проверять также с помощью cli под названием **opa**.
Её можно установить на mac через команду `brew install opa`.  

Запустить политику с выводом отладочных сообщений, которые печатаются в самой политике через функцию **print()**:  
`opa eval -f raw -d permission_check.rego -i input.json 'data.permission_check.permissionsGranted'`  

Пример для политики из папки `cmd/4_complex_policy`
