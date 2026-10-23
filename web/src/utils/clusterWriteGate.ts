// 集群管理页写门单源。
//
// stores/auth 的 readOnlyReason 先判节点模式（slave 优先于角色短路）：从节点上
// **任何**角色都只会得到 'slave'，'non-admin' 永远不会出现。因此只按 reason
// 集合判「未知/非管理员」会漏掉「从节点 + 非管理员」组合——UI 呈现可写，
// 破坏性按钮（提升为主节点/重新注册/服务控制）可点，点击后只得到后端 403。
//
// 角色必须独立参与：非 admin 恒只读；节点模式未知（unknown）fail-closed；
// 从节点 admin 仍可操作集群管理（既有契约，节点自身可提升为主节点）。
export type ClusterWriteGateInput = {
  readonly readOnlyReason: 'slave' | 'non-admin' | 'unknown' | null
  readonly role: string | null | undefined
}

export const clusterWriteBlocked = ({ readOnlyReason, role }: ClusterWriteGateInput): boolean =>
  readOnlyReason === 'unknown' || role !== 'admin'
