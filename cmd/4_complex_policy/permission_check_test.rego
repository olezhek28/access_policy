package permission_check_test

import data.permission_check

# Тест: Проверка, что у пользователя есть все необходимые права
test_permissions_granted {
    input := {"user_permissions": ["read", "write"]}

    result := permission_check.permissionsGranted with input as input
    result  # Ожидаем, что permissionsGranted возвращает true
}

# Тест: Проверка, что у пользователя нет всех необходимых прав
test_permissions_missing {
    input := {"user_permissions": ["read"]}

    result := permission_check.permissionsGranted with input as input
    not result  # Ожидаем, что permissionsGranted возвращает false
}

# Тест: Проверка списка недостающих прав
test_missing_permissions {
    input := {"user_permissions": ["read"]}

    result := permission_check.missingPermissions with input as input
    result == {"write"}  # Ожидаем, что недостающие права включают "write"
}
