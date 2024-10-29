package resource_check

policy_resource := {
	"source_uuid": "0FF8AFB4-55D2-4836-B17C-643AD59BBB2F",
    "source_slug": "some_slug"
}

# Массив несоответствий с подсказками
mismatches := [
    {
        "field": key,
        "actual": input[key],
        "expected": policy_resource[key],
        "hint": sprintf("Expected %v for %v, but got %v", [policy_resource[key], key, input[key]])
    } |

    policy_resource[key] != input[key]
]

# Итоговый статус
resource_status := {
    "is_valid": count(mismatches) == 0,
    "mismatches": mismatches
}
