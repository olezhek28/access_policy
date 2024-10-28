package main

import (
	"context"
	"fmt"
	"log"

	"github.com/open-policy-agent/opa/rego"
)

// Определяем Rego-политику как строку
const policy = `
package authorization

default allow = false

allow {
    input.role == "admin"
}

allow {
    input.role == "manager"
    input.experience_years > 5
}
`

type authParams struct {
	role            string
	experienceYears int
}

// Функция для выполнения политики
func checkAccess(ctx context.Context, params authParams) (bool, error) {
	input := map[string]interface{}{
		"role":             params.role,
		"experience_years": params.experienceYears,
	}

	// Создаем объект rego, который включает в себя политику и запрос к ней
	regoQuery := rego.New(
		// Запрос к результату правила allow в пакете authorization.
		// data:
		// Пространство политик по-умолчанию.
		// Всё что описано в файле политики, доступно через data, если специально не задавать кастомное пространство.
		// authorization:
		// Пакет, в котором находится политика. Задается в поле package политики.
		// allow:
		// Правила, которое мы хотим проверить политики.
		// Если истинно хотя бы одно из правил, то результат запроса будет true, иначе false.
		rego.Query("data.authorization.allow"),

		// Позволяет определить политику как строку в Go-коде
		// Первый аргумент:
		// Имя модуля, которое используется для отладки и в сообщениях об ошибках.
		// Если политика загружается из файла, то хорошей практикой будет назвать модуль по имени файла, в котором находится политика.
		// Второй аргумент:
		// Строка с кодом Rego, и она будет интерпретироваться как политика OPA.
		rego.Module("authorization_inline.rego", policy),

		// Принимает динамические входные данные для Rego-политики.
		// Эти данные становятся доступными через переменную input внутри Rego и позволяют создавать гибкие правила,
		// основанные на изменяющихся значениях.
		rego.Input(input),
	)

	// Выполняем запрос к политике
	rs, err := regoQuery.Eval(ctx)
	if err != nil {
		return false, fmt.Errorf("ошибка при оценке политики: %w", err)
	}

	// Извлекаем результат из запроса.
	// При простом запросе, как у нас `data.authorization.allow`
	// ответ будет содержать лишь один элемент в ответе true или false.
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return false, nil
	}

	allowed, ok := rs[0].Expressions[0].Value.(bool)
	if !ok {
		return false, fmt.Errorf("невозможно преобразовать результат в bool")
	}

	return allowed, nil
}

func main() {
	ctx := context.Background()

	person1 := authParams{
		role: "admin",
	}

	allowed, err := checkAccess(ctx, person1)
	if err != nil {
		log.Fatalf("ошибка при проверке доступа: %v", err)
	}

	fmt.Printf("Доступ первого человека: %v\n", allowed)

	person2 := authParams{
		role:            "manager",
		experienceYears: 3,
	}

	allowed, err = checkAccess(ctx, person2)
	if err != nil {
		log.Fatalf("ошибка при проверке доступа: %v", err)
	}

	fmt.Printf("Доступ второго человека: %v\n", allowed)
}
