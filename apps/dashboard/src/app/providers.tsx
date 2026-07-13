"use client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { useAuthStore } from "@/store/authStore";
import { authApi, getAccessToken } from "@/lib/api";

export function Providers({ children, nonce: _nonce }: { children: React.ReactNode; nonce?: string }) {
  const [queryClient] = useState(
    () =>
      new QueryClient({
        defaultOptions: {
          queries: {
            staleTime: 30 * 1000, // 30s
            retry: 1,
            refetchOnWindowFocus: false,
          },
        },
      })
  );

  const setUser = useAuthStore((s) => s.setUser);
  const setLoading = useAuthStore((s) => s.setLoading);
  const logout = useAuthStore((s) => s.logout);

  // Rehydrate the session from the httpOnly refresh cookie on first load.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        await authApi.refresh();
        const { data: user } = await authApi.me();
        if (!cancelled && user) {
          setUser(user, getAccessToken() ?? "", "");
        }
      } catch {
        if (!cancelled) logout();
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>;
}
