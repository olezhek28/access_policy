package final_check

import data.resource_check
import data.permission_check

# Итоговый результат, который учитывает ресурс и права
default accessAllowed = false

accessAllowed {
    resource_check.resourceCondition
    permission_check.permissionsGranted
    print("resourceCondition:", resource_check.resourceCondition)
    print("permissionsGranted:", permission_check.permissionsGranted)
}

# Диагностическая информация о недостающих правах или несоответствии ресурса
result = {
    "access_allowed": accessAllowed,
    "resource_valid": resource_check.resourceCondition,
    "permissions_granted": permission_check.permissionsGranted,
    "missing_permissions": permission_check.missingPermissions
}
