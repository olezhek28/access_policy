package main

import (
	"context"
	"fmt"
	"log"

	"github.com/open-policy-agent/opa/rego"
)

type authParams struct {
	role            string
	experienceYears int
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
		// Секции, которые мы хотим проверить на истинность.
		// Если истинна хотя бы одна из секций, то результат запроса будет true, иначе false.
		rego.Query("data.authorization.allow"),

		// В отличие от rego.Module, который принимает политику как строку,
		// rego.Load ищет и загружает Rego-файлы по заданным путям.
		// Это полезно для организации больших проектов, где политики хранятся в отдельных файлах.
		// Первый аргумент:
		// Имя файла с политикой.
		// Второй аргумент:
		// Дополнительные опции загрузки, которые можно настроить, например,
		// для включения и исключения определенных файлов. Можно передать nil, если нет особых требований.
		rego.Load([]string{"authorization_policy.rego"}, nil), // Загрузка политики из файла

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
