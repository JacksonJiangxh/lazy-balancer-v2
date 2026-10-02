// ——Element Plus 弹框（el-popover / el-tooltip）视口安全 popper 选项（U9 家族共享）——
// EP 未显式开启 Popper 的 flip（placement 固定则不回退）且无 preventOverflow。
// 统一补：flip 多向回退 + preventOverflow（视口内留 8px 余量）。
// 第 48 轮追加（用户反馈：靠底行仍越界）：回退候选必须含水平方向——摘要弹框可达
// 视口高度量级（62vh），上下都不够时纯垂直回退无解，Popper 只能保持原 placement
// 并溢出（实测 620px 视口下靠底行溢出 116px）。首选 placement 应放到空间约束最小
// 的一侧（Rules 锁摘要 right-start 先例，用户裁定）；小弹框保持 top 首选，回退顺
// 序统一为 右 → 左 → 上 → 下。弹框内容超高时由各 popper-class 的 max-height +
// overflow-y 内部滚动承接。
export const popperViewportSafe = {
  modifiers: [
    { name: 'flip', options: { fallbackPlacements: ['right', 'left', 'top', 'bottom'] } },
    { name: 'preventOverflow', options: { padding: 8 } },
  ],
}
