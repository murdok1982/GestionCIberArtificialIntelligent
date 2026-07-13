import axios, { AxiosInstance, InternalAxiosRequestConfig } from "axios";

// Access token is kept ONLY in memory (never localStorage) to avoid XSS token theft.
// The refresh token is stored in an httpOnly, SameSite cookie set by the backend,
// so the browser sends it automatically on /auth/refresh (requires withCredentials).
let accessToken: string | null = null;

export function getAccessToken(): string | null {
  return accessToken;
}

export function setAccessToken(token: string | null): void {
  accessToken = token;
}

// Refresh token is managed by the backend via httpOnly cookie; nothing to store here.
export function getRefreshToken(): string | null {
  return null;
}

export function setRefreshToken(_token: string | null): void {
  /* no-op: refresh token lives in an httpOnly cookie */
}

const baseURL =
  (typeof import.meta !== "undefined" &&
    (import.meta as any).env?.NEXT_PUBLIC_API_URL) ||
  "/api/v1";

const apiClient: AxiosInstance = axios.create({
  baseURL,
  timeout: 15000,
  withCredentials: true,
  headers: { "Content-Type": "application/json" },
});

// De-duplicate concurrent refresh calls so a 401 storm triggers a single refresh.
let refreshPromise: Promise<string | null> | null = null;

async function refreshAccess(): Promise<string | null> {
  if (!refreshPromise) {
    refreshPromise = (async () => {
      try {
        const { data } = await axios.post(
          `${baseURL}/auth/refresh`,
          {},
          { withCredentials: true }
        );
        accessToken = data.access_token;
        return data.access_token as string;
      } catch {
        accessToken = null;
        return null;
      } finally {
        refreshPromise = null;
      }
    })();
  }
  return refreshPromise;
}

apiClient.interceptors.request.use((config: InternalAxiosRequestConfig) => {
  if (accessToken) {
    config.headers.set("Authorization", `Bearer ${accessToken}`);
  }
  return config;
});

apiClient.interceptors.response.use(
  (response) => response,
  async (error) => {
    const original = error.config;
    if (
      error.response?.status === 401 &&
      original &&
      !original._retry
    ) {
      // Only attempt refresh for authenticated endpoints (not the refresh itself).
      if (!original.url?.includes("/auth/refresh")) {
        original._retry = true;
        const newToken = await refreshAccess();
        if (newToken) {
          original.headers.set("Authorization", `Bearer ${newToken}`);
          return apiClient(original);
        }
      }
      accessToken = null;
    }
    return Promise.reject(error);
  }
);

export interface User {
  id: string;
  email: string;
  full_name: string;
  role: string;
  tenant_id: string;
  mfa_enabled?: boolean;
}

export interface AuthResponse {
  access_token: string;
  refresh_token?: string;
  token_type: string;
  user: User;
  tenant?: Record<string, unknown>;
}

export const authApi = {
  async login(email: string, password: string): Promise<{ data: AuthResponse }> {
    const response = await apiClient.post<AuthResponse>("/auth/login", {
      email,
      password,
    });
    setAccessToken(response.data.access_token);
    if (response.data.refresh_token) {
      setRefreshToken(response.data.refresh_token);
    }
    return { data: response.data };
  },

  async register(payload: {
    company_name: string;
    full_name: string;
    email: string;
    password: string;
  }): Promise<{ data: AuthResponse }> {
    const response = await apiClient.post<AuthResponse>("/auth/register", payload);
    setAccessToken(response.data.access_token);
    if (response.data.refresh_token) {
      setRefreshToken(response.data.refresh_token);
    }
    return { data: response.data };
  },

  async refresh(): Promise<{ data: { access_token: string; token_type: string } }> {
    const response = await apiClient.post("/auth/refresh");
    setAccessToken(response.data.access_token);
    return { data: response.data };
  },

  async logout(): Promise<void> {
    try {
      await apiClient.post("/auth/logout");
    } finally {
      setAccessToken(null);
      setRefreshToken(null);
    }
  },

  async me(): Promise<{ data: User }> {
    const response = await apiClient.get<User>("/auth/me");
    return { data: response.data };
  },
};

export const devicesApi = {
  async list() {
    return apiClient.get("/devices");
  },
  async get(id: string) {
    return apiClient.get(`/devices/${id}`);
  },
  async telemetry(id: string, params?: Record<string, unknown>) {
    return apiClient.get(`/devices/${id}/telemetry`, { params });
  },
};

export const alertsApi = {
  async list(params?: Record<string, unknown>) {
    return apiClient.get("/alerts", { params });
  },
  async get(id: string) {
    return apiClient.get(`/alerts/${id}`);
  },
};

export const threatIntelApi = {
  async query(ioc: string) {
    return apiClient.get("/threat-intel", { params: { ioc } });
  },
};

export const billingApi = {
  async plans() {
    return apiClient.get("/billing/plans");
  },
  async subscription() {
    return apiClient.get("/billing/subscription");
  },
};

export default apiClient;