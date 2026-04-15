import axios, { type AxiosInstance, type AxiosRequestConfig } from "axios";

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

// Access token stored in memory only (never localStorage)
let accessToken: string | null = null;

export function setAccessToken(token: string | null) {
  accessToken = token;
}

export function getAccessToken(): string | null {
  return accessToken;
}

export const api: AxiosInstance = axios.create({
  baseURL: `${API_URL}/api/v1`,
  headers: { "Content-Type": "application/json" },
  withCredentials: true,
});

// Attach access token to every request
api.interceptors.request.use((config) => {
  if (accessToken) {
    config.headers.Authorization = `Bearer ${accessToken}`;
  }
  return config;
});

// Auto-refresh on 401
api.interceptors.response.use(
  (res) => res,
  async (error) => {
    const original = error.config as AxiosRequestConfig & { _retry?: boolean };
    if (error.response?.status === 401 && !original._retry) {
      original._retry = true;
      try {
        const refreshToken = localStorage.getItem("cg_refresh_token");
        if (!refreshToken) {
          window.location.href = "/login";
          return Promise.reject(error);
        }
        const res = await axios.post(`${API_URL}/api/v1/auth/refresh`, {
          refresh_token: refreshToken,
        });
        const newToken = res.data.access_token;
        setAccessToken(newToken);
        original.headers = { ...original.headers, Authorization: `Bearer ${newToken}` };
        return api(original);
      } catch {
        localStorage.removeItem("cg_refresh_token");
        setAccessToken(null);
        window.location.href = "/login";
        return Promise.reject(error);
      }
    }
    return Promise.reject(error);
  }
);

// API methods
export const authApi = {
  login: (email: string, password: string) =>
    api.post("/auth/login", { email, password }),
  register: (data: { company_name: string; full_name: string; email: string; password: string }) =>
    api.post("/auth/register", data),
  refresh: (refresh_token: string) =>
    api.post("/auth/refresh", { refresh_token }),
  me: () => api.get("/auth/me"),
};

export const devicesApi = {
  list: () => api.get("/devices"),
  get: (id: string) => api.get(`/devices/${id}`),
  create: (data: { hostname: string; os: string }) => api.post("/devices", data),
  delete: (id: string) => api.delete(`/devices/${id}`),
  action: (id: string, data: { action_type: string; params: object; justification: string }) =>
    api.post(`/devices/${id}/action`, data),
};

export const alertsApi = {
  list: (params?: { severity?: string; status_filter?: string; limit?: number; offset?: number }) =>
    api.get("/alerts", { params }),
  get: (id: string) => api.get(`/alerts/${id}`),
  updateStatus: (id: string, data: { status: string; notes?: string }) =>
    api.put(`/alerts/${id}/status`, data),
  approveAction: (id: string, data: { approved: boolean; justification: string; action_type: string; params?: object }) =>
    api.post(`/alerts/${id}/approve-action`, data),
  analyze: (id: string) => api.post(`/alerts/${id}/analyze`),
};

export const forensicsApi = {
  listEvidence: (params?: { device_id?: string; alert_id?: string }) =>
    api.get("/forensics/evidence", { params }),
  getEvidence: (id: string) => api.get(`/forensics/evidence/${id}`),
  uploadEvidence: (formData: FormData) =>
    api.post("/forensics/evidence", formData, { headers: { "Content-Type": "multipart/form-data" } }),
  getCustodyChain: (id: string) => api.get(`/forensics/evidence/${id}/custody-chain`),
  getDownloadUrl: (id: string) => api.get(`/forensics/evidence/${id}/download`),
  verifyIntegrity: (id: string) => api.post(`/forensics/evidence/${id}/verify`),
};

export const threatIntelApi = {
  enrich: (data: { ioc_type: string; value: string }) => api.post("/threat-intel/enrich", data),
  batchEnrich: (iocs: Array<{ type: string; value: string }>) =>
    api.post("/threat-intel/enrich/batch", { iocs }),
  campaigns: (iocs: Array<{ type: string; value: string }>) =>
    api.post("/threat-intel/campaigns", { iocs }),
};

export const billingApi = {
  getPlans: () => api.get("/billing/plans"),
  getSubscription: () => api.get("/billing/subscription"),
  subscribe: (plan: string) => api.post("/billing/subscribe", { plan }),
  cancel: () => api.put("/billing/cancel"),
};
