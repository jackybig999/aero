<template>
  <AeroConsole :mode="forcedMode" :embedded="embedded" />
</template>

<script setup>
import { computed } from 'vue'
import AeroConsole from './components/AeroConsole.vue'

const params = new URLSearchParams(location.search)
const forcedMode = computed(() => params.get('mode') || window.__AERO_WEBUI__?.mode || '')
const embedded = computed(() => params.get('embed') === '1' || window.__AERO_WEBUI__?.embedded === true)
</script>
