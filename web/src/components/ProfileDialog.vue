<template>
  <el-dialog
    :model-value="modelValue"
    width="min(520px, 92vw)"
    :close-on-click-modal="false"
    :before-close="beforeClose"
    class="profile-dialog"
    @update:model-value="(v: boolean) => emit('update:modelValue', v)"
    @opened="handleOpen"
  >
    <template #header>
      <DialogHeader :icon="User" title="个人资料" :subtitle="isOIDCUser ? 'OIDC 企业认证账户' : '本地账户'" />
    </template>
    <div v-if="isReadOnly" class="info-note-bar profile-readonly-note"><span class="info-note-desc">{{ authStore.readOnlyMessage }}</span></div>
    <el-form :model="profileForm" label-width="96px" class="profile-form" :disabled="saving">
      <el-form-item label="用户名">
        <el-input v-model="profileForm.username" disabled />
      </el-form-item>
      <template v-if="isOIDCUser">
        <el-form-item label="显示名">
          <el-input :model-value="profileForm.display_name" disabled />
        </el-form-item>
        <el-form-item label="认证方式">
          <el-tag type="primary" effect="plain" size="small">OIDC 企业认证</el-tag>
        </el-form-item>
        <el-form-item label-width="0">
          <div class="oidc-hint-block">显示名与密码由认证服务管理，如需修改请前往 OIDC 服务</div>
        </el-form-item>
      </template>
      <template v-else>
        <el-form-item label="显示名">
          <el-input ref="displayNameInput" v-model="profileForm.display_name" :disabled="isReadOnly" placeholder="选填" maxlength="50" />
        </el-form-item>
        <el-form-item label="新密码">
          <el-input ref="passwordInput" v-model="profileForm.password" :disabled="isReadOnly" type="password" minlength="8" maxlength="24" placeholder="如不修改请留空（8-24位）" show-password />
        </el-form-item>
        <el-form-item label="确认新密码">
          <el-input v-model="profileForm.passwordConfirm" :disabled="isReadOnly" type="password" minlength="8" maxlength="24" placeholder="再次输入新密码" show-password />
        </el-form-item>
        <el-form-item label="当前密码">
          <el-input v-model="profileForm.currentPassword" :disabled="isReadOnly" type="password" maxlength="72" :placeholder="profileForm.password ? '修改密码时必填' : '填写新密码后需确认'" show-password />
        </el-form-item>
      </template>
    </el-form>
    <template #footer>
      <el-button :disabled="saving" @click="closeProfile">取消</el-button>
      <el-button v-if="!isOIDCUser" type="primary" :loading="saving" :disabled="isReadOnly || saving" @click="saveProfile">保存</el-button>
    </template>
  </el-dialog>
</template>

<script setup lang="ts">
import { computed, nextTick, ref, watch } from 'vue'
import { User } from '@element-plus/icons-vue'
import type { ElInput } from 'element-plus'
import DialogHeader from '@/components/DialogHeader.vue'
import { request, mfaAwareSuccess, ApiRequestError } from '@/utils/api'
import { isCurrentPasswordRejection } from '@/utils/profileUpdate'
import { validatePassword } from '@/utils/credentials'
import { useAuthStore } from '@/stores/auth'

const props = withDefaults(defineProps<{ modelValue: boolean; focusField?: 'display_name' | 'password' | null }>(), { focusField: null })
const emit = defineEmits<{ 'update:modelValue': [value: boolean] }>()
const authStore = useAuthStore()
const displayNameInput = ref<InstanceType<typeof ElInput> | null>(null)
const passwordInput = ref<InstanceType<typeof ElInput> | null>(null)
const isOIDCUser = computed(() => authStore.user?.auth_provider === 'oidc')
const isReadOnly = computed(() => authStore.readOnlyReason === 'slave' || authStore.readOnlyReason === 'unknown')
const saving = ref(false)
const profileForm = ref({ username: '', display_name: '', password: '', passwordConfirm: '', currentPassword: '' })
const syncProfileForm = () => {
  profileForm.value = {
    username: authStore.user?.username || '',
    display_name: authStore.user?.display_name || '',
    password: '',
    passwordConfirm: '',
    currentPassword: '',
  }
}
const handleOpen = async () => {
  syncProfileForm()
  await nextTick()
  if (props.focusField === 'password') passwordInput.value?.focus()
  else if (props.focusField === 'display_name') displayNameInput.value?.focus()
}
watch(() => props.modelValue, (visible) => { if (visible) syncProfileForm() })
const beforeClose = (done: () => void): void => { if (!saving.value) done() }
const closeProfile = (): void => { if (!saving.value) emit('update:modelValue', false) }
const saveProfile = async () => {
  if (isReadOnly.value || saving.value) return
  const passwordError = validatePassword(profileForm.value.password)
  if (passwordError) { authStore.showToast('warning', passwordError); return }
  if (profileForm.value.password && !profileForm.value.currentPassword) { authStore.showToast('warning', '请输入当前密码'); return }
  if (profileForm.value.password && profileForm.value.password !== profileForm.value.passwordConfirm) { authStore.showToast('warning', '两次输入的新密码不一致'); return }
  saving.value = true
  const passwordChanged = Boolean(profileForm.value.password)
  try {
    await request.patch('/users/me', {
      display_name: profileForm.value.display_name,
      ...(profileForm.value.password && { password: profileForm.value.password, current_password: profileForm.value.currentPassword }),
    })
    emit('update:modelValue', false)
    if (passwordChanged) {
      authStore.showToast('success', '密码已修改，请重新登录')
      await authStore.logout()
    } else {
      mfaAwareSuccess('保存成功')
      await authStore.fetchUser()
    }
  } catch (error: unknown) {
    if (error instanceof ApiRequestError && isCurrentPasswordRejection('patch', '/users/me', error.status, error.message)) {
      authStore.showToast('error', error.message)
    } else {
      console.error('Failed to save profile:', error)
    }
  } finally {
    saving.value = false
  }
}
</script>

<style scoped>
.profile-form { padding: 4px 28px 0; }
.profile-form :deep(.el-form-item) { margin-bottom: 20px; }
.profile-form :deep(.el-form-item__label) { color: var(--el-text-color-regular); }
.profile-readonly-note { margin: 0 28px 12px; }
.oidc-hint-block {
  width: 100%;
  padding: 8px 12px;
  border-radius: 4px;
  background: var(--el-fill-color-light);
  color: var(--el-text-color-secondary);
  font-size: 12px;
  line-height: 1.7;
}
</style>
