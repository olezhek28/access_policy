package main

import (
	"context"
	"fmt"

	"github.com/fatih/color"
	"github.com/open-policy-agent/opa/rego"
)

const (
	accessAllowedKey      = "access_allowed"
	resourceValidKey      = "resource_valid"
	permissionsGrantedKey = "permissions_granted"
	missingPermissionsKey = "missing_permissions"
)

type teatCase struct {
	name  string
	input map[string]interface{}
}

type result struct {
	accessAllowed      bool
	resourceValid      bool
	permissionsGranted bool
	missingPermissions []string
}

func main() {
	ctx := context.Background()

	// Входные данные для проверки
	inputData := []teatCase{
		{
			name: "Доступ разрешен, все параметры валидны",
			input: map[string]interface{}{
				"source_uuid":      "0FF8AFB4-55D2-4836-B17C-643AD59BBB2F",
				"source_slug":      "some_slug",
				"user_permissions": []string{"read", "write"},
			},
		},
		{
			name: "Доступ разрешен, все параметры валидны, но права не в том регистре",
			input: map[string]interface{}{
				"source_uuid":      "0FF8AFB4-55D2-4836-B17C-643AD59BBB2F",
				"source_slug":      "some_slug",
				"user_permissions": []string{"Read", "wRite"},
			},
		},
		{
			name: "Доступ запрещен, идентификатор ресурса не валиден",
			input: map[string]interface{}{
				"source_uuid":      "invalid_uuid",
				"source_slug":      "some_slug",
				"user_permissions": []string{"read", "write"},
			},
		},
		{
			name: "Доступ запрещен, slug ресурса не валиден",
			input: map[string]interface{}{
				"source_uuid":      "0FF8AFB4-55D2-4836-B17C-643AD59BBB2F",
				"source_slug":      "invalid_slug",
				"user_permissions": []string{"read", "write"},
			},
		},
		{
			name: "Доступ запрещен, недостаточно прав доступа к ресурсу",
			input: map[string]interface{}{
				"source_uuid":      "0FF8AFB4-55D2-4836-B17C-643AD59BBB2F",
				"source_slug":      "some_slug",
				"user_permissions": []string{"write"},
			},
		},
	}

	for _, data := range inputData {
		fmt.Printf(color.BlueString("Кейс: \"%s\":\n", data.name))
		allowed, err := checkAccess(ctx, data)
		if err != nil {
			fmt.Printf("Ошибка при проверке доступа: %v\n", err)
			continue
		}

		if allowed.accessAllowed {
			fmt.Println(color.GreenString("Доступ разрешен"))
		} else {
			fmt.Println(color.RedString("Доступ запрещен"))
			if !allowed.resourceValid {
				fmt.Println("Ресурс не валиден")
			}
			if !allowed.permissionsGranted {
				fmt.Println("Недостаточно прав доступа к ресурсу")
				fmt.Printf("Не хватает прав: %v\n", allowed.missingPermissions)
			}
		}

		fmt.Println()
	}

}

func checkAccess(ctx context.Context, testCase teatCase) (result, error) {
	// Загружаем и компилируем объединённую политику
	query, err := rego.New(
		// Запрос к результату правила allow в пакете authorization.
		// data:
		// Пространство политик по-умолчанию.
		// Всё что описано в файле политики, доступно через data, если специально не задавать кастомное пространство.
		// final_check:
		// Пакет, в котором находится политика. Задается в поле package политики.
		// result:
		// Именованное правило, в результате которого лежит финальный ответ по вопросу доступа.
		rego.Query("data.final_check.result"),
		// В отличие от rego.Module, который принимает политику как строку,
		// rego.Load ищет и загружает Rego-файлы по заданным путям.
		// Это полезно для организации больших проектов, где политики хранятся в отдельных файлах.
		// Первый аргумент:
		// Имя файлов с политиками.
		// Второй аргумент:
		// Дополнительные опции загрузки, которые можно настроить, например,
		// для включения и исключения определенных файлов. Можно передать nil, если нет особых требований.
		rego.Load([]string{"./resource_check.rego", "./permission_check.rego", "./final_check.rego"}, nil),
	).
		// Метод PrepareForEval используется для предварительной подготовки
		// запроса, чтобы его можно было повторно использовать с разными входными
		// данными без необходимости заново загружать и компилировать политику каждый раз.
		PrepareForEval(ctx)
	if err != nil {
		return result{}, fmt.Errorf("ошибка при компиляции политики: %w", err)
	}

	// Выполнение запроса
	rs, err := query.Eval(ctx, rego.EvalInput(testCase.input))
	if err != nil {
		return result{}, fmt.Errorf("ошибка при оценке политики: %w", err)
	}
	if len(rs) == 0 {
		return result{}, fmt.Errorf("политика не вернула результат")
	}

	res, ok := rs[0].Expressions[0].Value.(map[string]interface{})
	if !ok {
		return result{}, fmt.Errorf("невозможно преобразовать результат в map[string]interface{}")
	}

	return unmarshal(res)
}

func unmarshal(data map[string]interface{}) (result, error) {
	accessAllowed, ok := data[accessAllowedKey].(bool)
	if !ok {
		return result{}, fmt.Errorf("невозможно преобразовать %s в bool", accessAllowedKey)
	}

	resourceValid, ok := data[resourceValidKey].(bool)
	if !ok {
		return result{}, fmt.Errorf("невозможно преобразовать %s в bool", resourceValidKey)
	}

	permissionsGranted, ok := data[permissionsGrantedKey].(bool)
	if !ok {
		return result{}, fmt.Errorf("невозможно преобразовать %s в bool", permissionsGrantedKey)
	}

	missingPermissionsRaw, ok := data[missingPermissionsKey].([]interface{})
	if !ok {
		return result{}, fmt.Errorf("невозможно преобразовать %s в []interface{}", missingPermissionsKey)
	}

	missingPermissions := make([]string, 0, len(missingPermissionsRaw))
	for _, v := range missingPermissionsRaw {
		perm, okPerm := v.(string)
		if !okPerm {
			return result{}, fmt.Errorf("невозможно преобразовать %s в string", missingPermissionsKey)
		}

		missingPermissions = append(missingPermissions, perm)
	}

	return result{
		accessAllowed:      accessAllowed,
		resourceValid:      resourceValid,
		permissionsGranted: permissionsGranted,
		missingPermissions: missingPermissions,
	}, nil
}
