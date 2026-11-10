// Package apipath 是 Gin 路由参数形态（:param）与 OpenAPI 形态（{param}）
// 双向转换的单一事实源——handlers（OpenAPI 生成）、mcpserver（工具规格路径
// 还原）与两侧对账测试共用同一实现，避免多份转换在新增参数形态时静默分叉。
package apipath

import "strings"

// ToOpenAPI 将 Gin 的 :param 路径段转换为 OpenAPI 的 {param}。
func ToOpenAPI(path string) string {
	parts := strings.Split(path, "/")
	for index, part := range parts {
		if name, found := strings.CutPrefix(part, ":"); found {
			parts[index] = "{" + name + "}"
		}
	}
	return strings.Join(parts, "/")
}

// ToGin 将 OpenAPI 的 {param} 路径段还原为 Gin 的 :param（ToOpenAPI 反函数，
// 全替换循环——多参路径逐段转换）。
func ToGin(path string) string {
	for {
		i := strings.IndexByte(path, '{')
		if i < 0 {
			return path
		}
		j := strings.IndexByte(path[i:], '}')
		if j < 0 {
			return path
		}
		path = path[:i] + ":" + path[i+1:i+j] + path[i+j+1:]
	}
}
