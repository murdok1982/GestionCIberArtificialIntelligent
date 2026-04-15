"use client";
import { create } from "zustand";
import type { User } from "@/types";
import { setAccessToken } from "@/lib/api";

interface AuthState {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  setUser: (user: User | null, accessToken: string, refreshToken: string) => void;
  logout: () => void;
  setLoading: (loading: boolean) => void;
}

export const useAuthStore = create<AuthState>((set) => ({
  user: null,
  isAuthenticated: false,
  isLoading: true,

  setUser: (user, accessToken, refreshToken) => {
    setAccessToken(accessToken);
    if (typeof window !== "undefined") {
      localStorage.setItem("cg_refresh_token", refreshToken);
    }
    set({ user, isAuthenticated: !!user, isLoading: false });
  },

  logout: () => {
    setAccessToken(null);
    if (typeof window !== "undefined") {
      localStorage.removeItem("cg_refresh_token");
    }
    set({ user: null, isAuthenticated: false, isLoading: false });
  },

  setLoading: (loading) => set({ isLoading: loading }),
}));
