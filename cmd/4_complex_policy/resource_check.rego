package resource_check

default resourceCondition = false

policy_resource := {
	"source_uuid": "0FF8AFB4-55D2-4836-B17C-643AD59BBB2F",
    "source_slug": "some_slug"
}

# Ожидаем, что ресурс имеет корректный ID и имя
resourceCondition {
	policy_resource.source_uuid == input.source_uuid
	policy_resource.source_slug == input.source_slug
	print("Resource check passed")
}
