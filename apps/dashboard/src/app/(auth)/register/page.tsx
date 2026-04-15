"use client";
import { useState } from "react";
import { useRouter } from "next/navigation";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { Shield, AlertCircle } from "lucide-react";
import { authApi } from "@/lib/api";
import { useAuthStore } from "@/store/authStore";

const registerSchema = z.object({
  company_name: z.string().min(2, "Company name must be at least 2 characters"),
  full_name: z.string().min(2, "Full name required"),
  email: z.string().email("Invalid email address"),
  password: z
    .string()
    .min(12, "Password must be at least 12 characters")
    .regex(/[A-Z]/, "Must contain uppercase")
    .regex(/[0-9]/, "Must contain a number")
    .regex(/[^A-Za-z0-9]/, "Must contain a special character"),
  confirm_password: z.string(),
}).refine((d) => d.password === d.confirm_password, {
  message: "Passwords do not match",
  path: ["confirm_password"],
});

type RegisterForm = z.infer<typeof registerSchema>;

export default function RegisterPage() {
  const router = useRouter();
  const { setUser } = useAuthStore();
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  const { register, handleSubmit, formState: { errors } } = useForm<RegisterForm>({
    resolver: zodResolver(registerSchema),
  });

  const onSubmit = async (data: RegisterForm) => {
    setIsLoading(true);
    setError(null);
    try {
      const res = await authApi.register({
        company_name: data.company_name,
        full_name: data.full_name,
        email: data.email,
        password: data.password,
      });
      setUser(res.data.user, res.data.access_token, res.data.refresh_token);
      router.push("/dashboard");
    } catch (err: any) {
      setError(err.response?.data?.detail || "Registration failed. Please try again.");
    } finally {
      setIsLoading(false);
    }
  };

  const Field = ({ label, name, type = "text", placeholder }: { label: string; name: keyof RegisterForm; type?: string; placeholder?: string }) => (
    <div>
      <label className="block text-sm font-medium text-slate-300 mb-1.5">{label}</label>
      <input
        {...register(name)}
        type={type}
        placeholder={placeholder}
        className="w-full px-3 py-2.5 bg-[#141B2D] border border-[#1E2D47] rounded-lg text-white placeholder-slate-600 focus:outline-none focus:border-blue-500 transition-colors"
      />
      {errors[name] && <p className="text-red-400 text-xs mt-1">{errors[name]?.message as string}</p>}
    </div>
  );

  return (
    <div className="min-h-screen bg-[#0A0E1A] cyber-grid flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        <div className="flex items-center justify-center gap-3 mb-8">
          <div className="p-3 rounded-xl bg-blue-600/20 border border-blue-500/30">
            <Shield className="w-8 h-8 text-blue-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white">CyberGuard</h1>
            <p className="text-xs text-slate-500">Security Operations Platform</p>
          </div>
        </div>

        <div className="bg-[#0F1629] border border-[#1E2D47] rounded-2xl p-8 shadow-2xl">
          <h2 className="text-xl font-semibold text-white mb-1">Create your organization</h2>
          <p className="text-sm text-slate-500 mb-6">Start your 14-day free trial</p>

          {error && (
            <div className="flex items-center gap-2 p-3 mb-4 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-sm">
              <AlertCircle className="w-4 h-4 flex-shrink-0" />
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
            <Field label="Company / Organization Name" name="company_name" placeholder="Acme Corp" />
            <Field label="Your Full Name" name="full_name" placeholder="Jane Smith" />
            <Field label="Work Email" name="email" type="email" placeholder="jane@acmecorp.com" />
            <Field label="Password" name="password" type="password" placeholder="Min. 12 chars, uppercase, number, symbol" />
            <Field label="Confirm Password" name="confirm_password" type="password" placeholder="Repeat password" />

            <button
              type="submit"
              disabled={isLoading}
              className="w-full py-2.5 px-4 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed text-white font-medium rounded-lg transition-colors"
            >
              {isLoading ? "Creating account..." : "Create organization"}
            </button>
          </form>

          <div className="mt-6 pt-6 border-t border-[#1E2D47] text-center">
            <p className="text-sm text-slate-500">
              Already have an account?{" "}
              <a href="/login" className="text-blue-400 hover:text-blue-300">Sign in</a>
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
