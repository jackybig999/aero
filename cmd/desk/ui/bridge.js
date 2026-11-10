// AERO OS Native Bridge (Go w.Bind memory RPC wrapper - zero HTTP)
window.bridge = {
  // 1. Network Center
  getNetStatus: async () => {
    if (typeof window.goGetNetStatus === 'function') {
      return await window.goGetNetStatus();
    }
    return { connected: false, ready: false, listen: '127.0.0.1:55555' };
  },
  toggleNetPower: async (targetOn) => {
    if (typeof window.goToggleNetPower === 'function') {
      return await window.goToggleNetPower(targetOn);
    }
    return { status: 'error', error: 'Go runtime not ready' };
  },
  setNetMode: async (mode) => {
    if (typeof window.goSetNetMode === 'function') {
      return await window.goSetNetMode(mode);
    }
    return { status: 'error' };
  },
  applyNetSub: async (subUrl) => {
    if (typeof window.goApplyNetSub === 'function') {
      return await window.goApplyNetSub(subUrl);
    }
    return { status: 'error' };
  },
  probeNet: async () => {
    if (typeof window.goProbeNet === 'function') {
      return await window.goProbeNet();
    }
    return { ok: false };
  },

  // 2. Browser Sandbox & Kernel
  getProfiles: async () => {
    if (typeof window.goGetProfiles === 'function') {
      return await window.goGetProfiles() || [];
    }
    return [];
  },
  createProfile: async (name, kernelType, country, proxyStr) => {
    if (typeof window.goCreateProfile === 'function') {
      return await window.goCreateProfile(name, kernelType, country, proxyStr);
    }
    return null;
  },
  createProfileAdvanced: async (req) => {
    if (typeof window.goCreateProfileAdvanced === 'function') {
      return await window.goCreateProfileAdvanced(JSON.stringify(req));
    }
    return null;
  },
  startProfile: async (id) => {
    if (typeof window.goStartProfile === 'function') {
      return await window.goStartProfile(id);
    }
    return { status: 'error' };
  },
  stopProfile: async (id) => {
    if (typeof window.goStopProfile === 'function') {
      return await window.goStopProfile(id);
    }
    return { status: 'error' };
  },
  deleteProfile: async (id) => {
    if (typeof window.goDeleteProfile === 'function') {
      return await window.goDeleteProfile(id);
    }
    return { status: 'error' };
  },
  cloneProfile: async (id) => {
    if (typeof window.goCloneProfile === 'function') {
      return await window.goCloneProfile(id);
    }
    return { status: 'error' };
  },
  getKernels: async () => {
    if (typeof window.goGetKernels === 'function') {
      return await window.goGetKernels() || [];
    }
    return [];
  },
  downloadKernel: async (name) => {
    if (typeof window.goDownloadKernel === 'function') {
      return await window.goDownloadKernel(name);
    }
    return { status: 'error' };
  },
  deleteKernel: async (name) => {
    if (typeof window.goDeleteKernel === 'function') {
      return await window.goDeleteKernel(name);
    }
    return { status: 'error' };
  },

  // 3. AI Developer Tools
  getAITools: async () => {
    if (typeof window.goGetAITools === 'function') {
      return await window.goGetAITools() || [];
    }
    return [];
  },
  launchAITool: async (toolKey, cwd) => {
    if (typeof window.goLaunchAITool === 'function') {
      return await window.goLaunchAITool(toolKey, cwd);
    }
    return { status: 'error' };
  },
  setToolCWD: async (toolKey, cwd) => {
    if (typeof window.goSetToolCWD === 'function') {
      return await window.goSetToolCWD(toolKey, cwd);
    }
    return { status: 'error' };
  },
  selectDirectory: async () => {
    if (typeof window.goSelectDirectory === 'function') {
      return await window.goSelectDirectory();
    }
    return '';
  },

  // 4. API Matrix
  getAPIs: async () => {
    if (typeof window.goGetAPIs === 'function') {
      return await window.goGetAPIs() || [];
    }
    return [];
  },
  saveAPI: async (id, key, baseURL) => {
    if (typeof window.goSaveAPI === 'function') {
      return await window.goSaveAPI(id, key, baseURL);
    }
    return { status: 'error' };
  },
  testAPI: async (id) => {
    if (typeof window.goTestAPI === 'function') {
      return await window.goTestAPI(id);
    }
    return { status: 'error', latency_ms: 0 };
  },

  // 5. Audit & Logs
  getLogs: async () => {
    if (typeof window.goGetLogs === 'function') {
      return await window.goGetLogs() || [];
    }
    return [];
  },
  clearLogs: async () => {
    if (typeof window.goClearLogs === 'function') {
      return await window.goClearLogs();
    }
    return { status: 'ok' };
  },
  exportLogs: async (path) => {
    if (typeof window.goExportLogs === 'function') {
      return await window.goExportLogs(path || '');
    }
    return { status: 'error' };
  },
  getHistory: async () => {
    if (typeof window.goGetHistory === 'function') {
      return await window.goGetHistory() || [];
    }
    return [];
  }
};
