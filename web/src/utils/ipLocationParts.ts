// 归属地文本拆分单源：后端形如 `中国·广东省·深圳市`（海外 `美国·California`）。
// 光流地域键（threatFlowRules.flowRegionKey）与弧线起点
// （threatShared.arcOriginForLocation）共用同一拆分规则——两处各自 split('·')
// 会在分隔符/段数变化时让「键里的省」与「端点用的省」漂移。
//
// 独立小模块（不挂在 threatShared）：threatFlowRules 是独立 chunk，而
// threatShared 静态依赖 chinaProvinces/countryCentroids 大表——反向依赖会把
// 大表拖进光流规则 chunk。

export function parseIpLocation(ipLocation: string | undefined): { country: string; province: string } {
  const [country = '', province = ''] = (ipLocation ?? '').split('·')
  return { country, province }
}
