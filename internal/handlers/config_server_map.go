package handlers

import "fmt"

// validateServerMapCoordinates 是威胁大屏站点坐标范围校验的单源：
// 通用 PUT /config（主节点基础设置）与集群节点坐标端点共用。
// 0,0 合法，表示未设置。
func validateServerMapCoordinates(lat, lon *float64) error {
	if lat != nil && (*lat < -90 || *lat > 90) {
		return fmt.Errorf("本站纬度必须在 -90 到 90 之间")
	}
	if lon != nil && (*lon < -180 || *lon > 180) {
		return fmt.Errorf("本站经度必须在 -180 到 180 之间")
	}
	return nil
}
