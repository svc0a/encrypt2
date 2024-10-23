package map2

import (
	"sort"
)

type Data[T any] struct {
	Key string
	Val T
}

func Sorted[T any](params map[string]T) []Data[T] {
	// 将参数按照键名排序
	keys := make([]string, 0, len(params))
	for key := range params {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	// 按照指定格式拼接键值对
	arr := []Data[T]{}
	for _, key := range keys {
		arr = append(arr, Data[T]{
			Key: key,
			Val: params[key],
		})
	}
	return arr
}
