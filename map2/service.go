package map2

import (
	"sort"
)

type Data[T any] struct {
	Key string
	Val T
}

func Sorted[T any](params map[string]T) []Data[T] {
	keys := make([]string, 0, len(params))
	for key := range params {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	arr := []Data[T]{}
	for _, key := range keys {
		arr = append(arr, Data[T]{
			Key: key,
			Val: params[key],
		})
	}
	return arr
}
