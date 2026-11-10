import type { ClusterNodeMode } from '../types/index.ts'

/** 首次注册只在 master→slave 跃迁时关闭；slave→slave 是重新注册，必须保留弹框。 */
export const shouldCloseRegistrationDialog = (
  open: boolean,
  originMode: ClusterNodeMode | null,
  currentMode: ClusterNodeMode,
): boolean => open && originMode === 'master' && currentMode === 'slave'
