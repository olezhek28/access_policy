package resource_check_test

import data.resource_check

# Тест: Проверка, что ресурс валиден при совпадении UUID и slug
test_resource_valid {
    input := {
        "source_uuid": "0FF8AFB4-55D2-4836-B17C-643AD59BBB2F",
        "source_slug": "some_slug"
    }

    result := resource_check.resourceCondition with input as input
    result  # Ожидаем, что resourceCondition возвращает true
}

# Тест: Проверка, что ресурс не валиден, если UUID не совпадает
test_resource_invalid_uuid {
    input := {
        "source_uuid": "incorrect_uuid",
        "source_slug": "some_slug"
    }

    result := resource_check.resourceCondition with input as input
    not result  # Ожидаем, что resourceCondition возвращает false
}

# Тест: Проверка, что ресурс не валиден, если slug не совпадает
test_resource_invalid_slug {
    input := {
        "source_uuid": "0FF8AFB4-55D2-4836-B17C-643AD59BBB2F",
        "source_slug": "incorrect_slug"
    }

    result := resource_check.resourceCondition with input as input
    not result  # Ожидаем, что resourceCondition возвращает false
}

# Тест: Проверка, что ресурс не валиден, если ни UUID, ни slug не совпадают
test_resource_invalid_uuid_and_slug {
    input := {
        "source_uuid": "incorrect_uuid",
        "source_slug": "incorrect_slug"
    }

    result := resource_check.resourceCondition with input as input
    not result  # Ожидаем, что resourceCondition возвращает false
}
