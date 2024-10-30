package main

import (
	"bytes"
	"context"
	"fmt"
	"text/template"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/fatih/color"
	"github.com/open-policy-agent/opa/rego"
)

const (
	accessAllowedKey      = "access_allowed"
	resourceValidKey      = "resource_valid"
	permissionsGrantedKey = "permissions_granted"
	missingPermissionsKey = "missing_permissions"
)

// PolicyData Данные для подстановки в шаблоны
type PolicyData struct {
	SourceUUID          string
	SourceSlug          string
	RequiredPermissions []string
}

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

	var (
		sourceUUID = gofakeit.UUID()
		sourceSlug = gofakeit.Word()
	)

	data := PolicyData{
		SourceUUID:          sourceUUID,
		SourceSlug:          sourceSlug,
		RequiredPermissions: []string{"create", "read", "update", "delete"},
	}

	policies, err := generatePolicies(data)
	if err != nil {
		fmt.Printf("Ошибка при генерации политик: %v\n", err)
		return
	}

	// Входные данные для проверки
	inputData := []teatCase{
		{
			name: "Доступ разрешен, все параметры валидны",
			input: map[string]interface{}{
				"source_uuid":      sourceUUID,
				"source_slug":      sourceSlug,
				"user_permissions": []string{"create", "read", "update", "delete"},
			},
		},
		{
			name: "Доступ разрешен, все параметры валидны, но права не в том регистре",
			input: map[string]interface{}{
				"source_uuid":      sourceUUID,
				"source_slug":      sourceSlug,
				"user_permissions": []string{"cReate", "Read", "updAte", "Delete"},
			},
		},
		{
			name: "Доступ запрещен, идентификатор ресурса не валиден",
			input: map[string]interface{}{
				"source_uuid":      "invalid_uuid",
				"source_slug":      sourceSlug,
				"user_permissions": []string{"create", "read", "update", "delete"},
			},
		},
		{
			name: "Доступ запрещен, slug ресурса не валиден",
			input: map[string]interface{}{
				"source_uuid":      sourceUUID,
				"source_slug":      "invalid_slug",
				"user_permissions": []string{"create", "read", "update", "delete"},
			},
		},
		{
			name: "Доступ запрещен, недостаточно прав доступа к ресурсу",
			input: map[string]interface{}{
				"source_uuid":      sourceUUID,
				"source_slug":      sourceSlug,
				"user_permissions": []string{"read"},
			},
		},
	}

	for _, input := range inputData {
		fmt.Printf(color.BlueString("Кейс: \"%s\":\n", input.name))
		allowed, err := checkAccess(ctx, policies, input)
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

func generatePolicies(data PolicyData) ([]string, error) {
	// Генерация каждого файла
	finalCheckPolicy, err := generatePolicy("final_check_policy.tmpl", data)
	if err != nil {
		return nil, fmt.Errorf("ошибка генерации шаблона final_check_policy: %w", err)
	}

	permissionCheckPolicy, err := generatePolicy("permission_check_policy.tmpl", data)
	if err != nil {
		return nil, fmt.Errorf("ошибка генерации шаблона permission_check_policy: %w", err)
	}

	resourceCheckPolicy, err := generatePolicy("resource_check_policy.tmpl", data)
	if err != nil {
		return nil, fmt.Errorf("ошибка генерации шаблона resource_check_policy: %w", err)
	}

	return []string{finalCheckPolicy, permissionCheckPolicy, resourceCheckPolicy}, nil
}

func generatePolicy(templatePath string, data PolicyData) (string, error) {
	// Загружаем шаблон из файла
	tmpl, err := template.ParseFiles(templatePath)
	if err != nil {
		return "", fmt.Errorf("ошибка загрузки шаблона: %w", err)
	}

	// Применяем шаблон к данным
	var output bytes.Buffer
	err = tmpl.Execute(&output, data)
	if err != nil {
		return "", fmt.Errorf("ошибка выполнения шаблона: %w", err)
	}

	return output.String(), nil
}

func checkAccess(ctx context.Context, policies []string, testCase teatCase) (result, error) {
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
		rego.Module("final_check_policy.rego", policies[0]),
		rego.Module("permission_check_policy.rego", policies[1]),
		rego.Module("resource_check_policy.rego", policies[2]),
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
