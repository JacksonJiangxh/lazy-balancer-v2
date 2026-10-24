import { computed, watch, type ComputedRef, type Ref } from 'vue'

/**
 * 页码夹紧 + 分页切片单一范式（用户裁定，取代三处并存实现——
 * Rules/SecurityRules 的 watch 夹紧、BlockPages/Policies 的 computed 内副作用
 * 赋值）：列表收缩（删除/搜索收窄）或页大小变化使当前页超出最大页时自动回夹，
 * 杜绝「删除末页末条后空页」。只返回分页切片；最大页是内部夹紧用的中间量
 * （无消费方对外暴露只会诱使调用方重复实现夹紧）。
 *
 * 夹紧是**双向**的：页码同时受 [1, maxPage] 约束。只做上界夹紧时，
 * page<=0 会让 slice 的负下标落到列表尾部（page=-1 返回倒数第二页），
 * 是一次静默的错行渲染；el-pagination 的 min=1 只是当前调用方的巧合，
 * 不能当作本组合子的边界契约。
 */
export function useClampedPagination<T>(items: Ref<T[]> | ComputedRef<T[]>, page: Ref<number>, pageSize: Ref<number>) {
  const maxPage = computed(() => Math.max(1, Math.ceil(items.value.length / pageSize.value)))
  const clampPage = (): void => {
    const next = Math.min(Math.max(1, page.value), maxPage.value)
    if (next !== page.value) page.value = next
  }
  // 双源监听：maxPage 收缩（列表缩窄/页大小变化）与 page 越界写入（0/负数/
  // 恢复态脏值）都要收敛，否则切片下标会带着越界值算出去。
  watch([maxPage, page], clampPage, { immediate: true }) // 恢复态初始 page>maxPage 立即夹紧
  const pagedItems = computed(() => {
    const start = (page.value - 1) * pageSize.value
    return items.value.slice(start, start + pageSize.value)
  })
  return { pagedItems }
}
