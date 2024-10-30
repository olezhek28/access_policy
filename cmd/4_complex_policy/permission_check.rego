package permission_check

default permissionsGranted = false

# Set необходимых прав для операции
required_permissions := {"read", "write"}

# Преобразуем массив прав пользователя в set (set'ы можно вычитать друг из друга)
user_permissions_set := {perm | perm := lower(input.user_permissions[_])}

# Вычисление недостающих прав
missingPermissions := required_permissions - user_permissions_set

# Проверка, что все требуемые права присутствуют у пользователя
permissionsGranted {
    print(missingPermissions)
    count(missingPermissions) == 0
}
