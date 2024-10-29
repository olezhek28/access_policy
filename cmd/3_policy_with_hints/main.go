package main

import (
	"context"
	"fmt"

	"github.com/fatih/color"
	"github.com/open-policy-agent/opa/rego"
)

const (
	isValidKey    = "is_valid"
	mismatchesKey = "mismatches"

	fieldKey    = "field"
	expectedKey = "expected"
	actualKey   = "actual"
	hintKey     = "hint"
)

func main() {
	ctx := context.Background()

	testCheckAccess(ctx)
	//testCheckAccessWithDetails(ctx)
}

func testCheckAccess(ctx context.Context) {
	inputData := []map[string]interface{}{
		{
			"source_uuid": "0FF8AFB4-55D2-4836-B17C-643AD59BBB2F",
			"source_slug": "some_slug",
		},
		{
			"source_uuid": "0FF8AFB4-55D2-4836-B17C-643AD59BBB2F",
			"source_slug": "invalid_slug",
		},
		{
			"source_uuid": "invalid_uuid",
			"source_slug": "some_slug",
		},
		{
			"source_uuid": "invalid_uuid",
			"source_slug": "invalid_slug",
		},
	}

	for i, data := range inputData {
		fmt.Printf(color.BlueString("Проверка доступа %d:\n"), i+1)
		allowed, err := checkAccess(ctx, data)
		if err != nil {
			fmt.Printf("Ошибка при проверке доступа: %v\n", err)
			continue
		}

		if allowed {
			fmt.Println(color.GreenString("Ресурс валиден"))
		} else {
			fmt.Println(color.RedString("Ресурс не валиден"))
		}

		fmt.Println()
	}
}

func checkAccess(ctx context.Context, inputData map[string]interface{}) (bool, error) {
	// Создаем объект rego, который включает в себя политику и запрос к ней
	query, err := rego.New(
		// Запрос к результату правила allow в пакете authorization.
		// data:
		// Пространство политик по-умолчанию.
		// Всё что описано в файле политики, доступно через data, если специально не задавать кастомное пространство.
		// resource_check:
		// Пакет, в котором находится политика. Задается в поле package политики.
		// resourceCondition:
		// Именованное правило, в результате которого лежит финальный ответ по вопросу доступа.
		rego.Query("data.resource_check.resourceCondition"),
		// В отличие от rego.Module, который принимает политику как строку,
		// rego.Load ищет и загружает Rego-файлы по заданным путям.
		// Это полезно для организации больших проектов, где политики хранятся в отдельных файлах.
		// Первый аргумент:
		// Имя файла с политикой.
		// Второй аргумент:
		// Дополнительные опции загрузки, которые можно настроить, например,
		// для включения и исключения определенных файлов. Можно передать nil, если нет особых требований.
		rego.Load([]string{"./resource_check.rego"}, nil),
	).
		// Метод PrepareForEval используется для предварительной подготовки
		// запроса, чтобы его можно было повторно использовать с разными входными
		// данными без необходимости заново загружать и компилировать политику каждый раз.
		PrepareForEval(ctx)
	if err != nil {
		return false, fmt.Errorf("ошибка при компиляции политики: %w", err)
	}

	// Выполнение запроса
	rs, err := query.Eval(ctx, rego.EvalInput(inputData))
	if err != nil {
		return false, fmt.Errorf("ошибка при оценке политики: %w", err)
	}
	if len(rs) == 0 {
		return false, fmt.Errorf("политика не вернула результат")
	}

	result, ok := rs[0].Expressions[0].Value.(bool)
	if !ok {
		return false, fmt.Errorf("невозможно преобразовать результат в bool")
	}

	return result, nil
}

func testCheckAccessWithDetails(ctx context.Context) {
	inputData := []map[string]interface{}{
		{
			"source_uuid": "0FF8AFB4-55D2-4836-B17C-643AD59BBB2F",
			"source_slug": "some_slug",
		},
		{
			"source_uuid": "0FF8AFB4-55D2-4836-B17C-643AD59BBB2F",
			"source_slug": "invalid_slug",
		},
		{
			"source_uuid": "invalid_uuid",
			"source_slug": "some_slug",
		},
		{
			"source_uuid": "invalid_uuid",
			"source_slug": "invalid_slug",
		},
	}

	for i, data := range inputData {
		fmt.Printf(color.BlueString("Проверка доступа %d:\n"), i+1)
		allowed, details, err := checkAccessWithDetails(ctx, data)
		if err != nil {
			fmt.Printf("Ошибка при проверке доступа: %v\n", err)
			continue
		}

		if allowed {
			fmt.Println(color.GreenString("Ресурс валиден"))
		} else {
			fmt.Println(color.RedString("Ресурс не валиден"))
			for field, detail := range details {
				fmt.Printf("- %s: %s\n", field, detail)
			}
		}

		fmt.Println()
	}
}

func checkAccessWithDetails(ctx context.Context, inputData map[string]interface{}) (bool, map[string]string, error) {
	// Создаем объект rego, который включает в себя политику и запрос к ней
	query, err := rego.New(
		// Запрос к результату правила allow в пакете authorization.
		// data:
		// Пространство политик по-умолчанию.
		// Всё что описано в файле политики, доступно через data, если специально не задавать кастомное пространство.
		// resource_check:
		// Пакет, в котором находится политика. Задается в поле package политики.
		// resource_status:
		// Именованное правило, в результате которого лежит финальный ответ по вопросу доступа.
		rego.Query("data.resource_check.resource_status"),
		// В отличие от rego.Module, который принимает политику как строку,
		// rego.Load ищет и загружает Rego-файлы по заданным путям.
		// Это полезно для организации больших проектов, где политики хранятся в отдельных файлах.
		// Первый аргумент:
		// Имя файла с политикой.
		// Второй аргумент:
		// Дополнительные опции загрузки, которые можно настроить, например,
		// для включения и исключения определенных файлов. Можно передать nil, если нет особых требований.
		rego.Load([]string{"./resource_check_with_details.rego"}, nil),
	).
		// Метод PrepareForEval используется для предварительной подготовки
		// запроса, чтобы его можно было повторно использовать с разными входными
		// данными без необходимости заново загружать и компилировать политику каждый раз.
		PrepareForEval(ctx)
	if err != nil {
		return false, nil, fmt.Errorf("ошибка при компиляции политики: %w", err)
	}

	// Выполнение запроса
	rs, err := query.Eval(ctx, rego.EvalInput(inputData))
	if err != nil {
		return false, nil, fmt.Errorf("ошибка при оценке политики: %w", err)
	}
	if len(rs) == 0 {
		return false, nil, fmt.Errorf("политика не вернула результат")
	}

	result, ok := rs[0].Expressions[0].Value.(map[string]interface{})
	if !ok {
		return false, nil, fmt.Errorf("невозможно преобразовать результат в map[string]interface{}")
	}

	isValid, ok := result[isValidKey].(bool)
	if !ok {
		return false, nil, fmt.Errorf("невозможно преобразовать %s в bool", isValidKey)
	}

	if isValid {
		return true, nil, nil
	}

	mismatches, ok := result[mismatchesKey].([]interface{})
	if !ok {
		return false, nil, fmt.Errorf("невозможно преобразовать %s в []interface{}", mismatchesKey)
	}

	details := make(map[string]string, len(mismatches))
	for _, mismatch := range mismatches {
		detail, okDetail := mismatch.(map[string]interface{})
		if !okDetail {
			return false, nil, fmt.Errorf("невозможно преобразовать %s в map[string]interface{}", mismatchesKey)
		}

		fieldName, okDetail := detail[fieldKey].(string)
		if !okDetail {
			return false, nil, fmt.Errorf("невозможно преобразовать %s в string", fieldKey)
		}

		expected, okDetail := detail[expectedKey].(string)
		if !okDetail {
			return false, nil, fmt.Errorf("невозможно преобразовать %s в string", expectedKey)
		}

		actual, okDetail := detail[actualKey].(string)
		if !okDetail {
			return false, nil, fmt.Errorf("невозможно преобразовать %s в string", actualKey)
		}

		hint, okDetail := detail[hintKey].(string)
		if !okDetail {
			return false, nil, fmt.Errorf("невозможно преобразовать %s в string", hintKey)
		}

		details[fieldName] = fmt.Sprintf("Ожидалось: %v, Получено: %v, Подсказка: %v", expected, actual, hint)
	}

	return false, details, nil
}
