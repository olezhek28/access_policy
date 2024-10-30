package final_check_test

import data.final_check

# Тест: Доступ разрешен, когда ресурс валиден и все права имеются
test_access_allowed_when_resource_and_permissions_valid {
    input := {
        "source_uuid": "0FF8AFB4-55D2-4836-B17C-643AD59BBB2F",
        "source_slug": "some_slug",
        "user_permissions": ["read", "write"]
    }

    result := final_check.result with input as input

    result.access_allowed  # Ожидаем, что доступ разрешен
    result.resource_valid  # Ресурс должен быть валиден
    result.permissions_granted  # Права должны быть предоставлены
    count(result.missing_permissions) == 0  # Нет недостающих прав
}

# Тест: Доступ запрещен, когда ресурс не валиден
test_access_denied_when_resource_invalid {
    input := {
        "source_uuid": "incorrect_uuid",
        "source_slug": "some_slug",
        "user_permissions": ["read", "write"]
    }

    result := final_check.result with input as input

    not result.access_allowed  # Ожидаем, что доступ запрещен
    not result.resource_valid  # Ресурс не должен быть валиден
    result.permissions_granted  # Права должны быть предоставлены
    count(result.missing_permissions) == 0  # Нет недостающих прав
}

# Тест: Доступ запрещен, когда у пользователя отсутствуют необходимые права
test_access_denied_when_permissions_missing {
    input := {
        "source_uuid": "0FF8AFB4-55D2-4836-B17C-643AD59BBB2F",
        "source_slug": "some_slug",
        "user_permissions": ["read"]  # Отсутствует право "write"
    }

    result := final_check.result with input as input

    not result.access_allowed  # Ожидаем, что доступ запрещен
    result.resource_valid  # Ресурс должен быть валиден
    not result.permissions_granted  # Права не должны быть предоставлены
    result.missing_permissions == {"write"}  # "write" должно быть в недостающих правах
}

# Тест: Доступ запрещен, когда ни ресурс, ни права не валидны
test_access_denied_when_resource_and_permissions_invalid {
    input := {
        "source_uuid": "incorrect_uuid",
        "source_slug": "incorrect_slug",
        "user_permissions": ["read"]  # Отсутствует право "write"
    }
    
    result := final_check.result with input as input

    not result.access_allowed  # Ожидаем, что доступ запрещен
    not result.resource_valid  # Ресурс не должен быть валиден
    not result.permissions_granted  # Права не должны быть предоставлены
    result.missing_permissions == {"write"}  # "write" должно быть в недостающих правах
}
