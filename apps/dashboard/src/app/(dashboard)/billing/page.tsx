"use client";
import { useQuery, useMutation } from "@tanstack/react-query";
import { CheckCircle, Zap, Shield, Building2, CreditCard, AlertTriangle } from "lucide-react";
import { billingApi } from "@/lib/api";
import { formatDateTime, statusColor } from "@/lib/utils";
import type { Plan, Subscription } from "@/types";

const PLAN_ICONS = { starter: Zap, pro: Shield, enterprise: Building2 };

function PlanCard({ plan, current, onSelect }: { plan: Plan; current?: Subscription; onSelect: (id: string) => void }) {
  const isActive = current?.plan === plan.id && current.status === "active";
  const Icon = PLAN_ICONS[plan.id as keyof typeof PLAN_ICONS] ?? Shield;

  return (
    <div className={`relative bg-[#141B2D] border rounded-xl p-6 flex flex-col transition-all ${plan.popular ? "border-blue-500 shadow-lg shadow-blue-500/10" : "border-[#1E2D47] hover:border-[#2E4163]"} ${isActive ? "ring-2 ring-emerald-500/30" : ""}`}>
      {plan.popular && (
        <div className="absolute -top-3 left-1/2 -translate-x-1/2 px-3 py-0.5 bg-blue-600 text-white text-xs font-bold rounded-full">
          MOST POPULAR
        </div>
      )}
      {isActive && (
        <div className="absolute top-3 right-3 flex items-center gap-1 text-emerald-400 text-xs">
          <CheckCircle className="w-3.5 h-3.5" /> Current plan
        </div>
      )}
      <div className={`p-3 rounded-xl w-fit mb-4 ${plan.popular ? "bg-blue-600/20 text-blue-400" : "bg-slate-700/30 text-slate-400"}`}>
        <Icon className="w-5 h-5" />
      </div>
      <h3 className="text-lg font-bold text-white mb-1">{plan.name}</h3>
      <div className="mb-4">
        <span className="text-3xl font-bold text-white">${plan.price_per_device}</span>
        <span className="text-slate-500 text-sm">/endpoint/month</span>
      </div>
      <p className="text-sm text-slate-500 mb-4">
        {plan.max_devices ? `Up to ${plan.max_devices} devices` : "Unlimited devices"}
      </p>
      <ul className="space-y-2 mb-6 flex-1">
        {plan.features.map((f) => (
          <li key={f} className="flex items-start gap-2 text-sm text-slate-300">
            <CheckCircle className="w-4 h-4 text-emerald-400 flex-shrink-0 mt-0.5" />
            {f}
          </li>
        ))}
      </ul>
      <button
        onClick={() => onSelect(plan.id)}
        disabled={isActive}
        className={`w-full py-2.5 rounded-lg text-sm font-medium transition-colors ${isActive ? "bg-emerald-600/20 text-emerald-400 cursor-default border border-emerald-500/30" : plan.popular ? "bg-blue-600 hover:bg-blue-700 text-white" : "border border-[#1E2D47] text-slate-300 hover:bg-[#0F1629]"}`}
      >
        {isActive ? "Active" : "Subscribe"}
      </button>
    </div>
  );
}

export default function BillingPage() {
  const { data: plans = [] } = useQuery<Plan[]>({
    queryKey: ["billing-plans"],
    queryFn: () => billingApi.getPlans().then((r) => r.data),
  });

  const { data: subscription, isLoading } = useQuery<Subscription>({
    queryKey: ["subscription"],
    queryFn: () => billingApi.getSubscription().then((r) => r.data),
  });

  const subscribeMutation = useMutation({
    mutationFn: (plan: string) => billingApi.subscribe(plan),
    onSuccess: (res) => {
      if (res.data.client_secret) {
        // In production: redirect to Stripe payment page or use Stripe.js
        alert("Redirect to payment: " + res.data.client_secret);
      }
    },
  });

  const cancelMutation = useMutation({
    mutationFn: () => billingApi.cancel(),
    onSuccess: () => alert("Subscription will cancel at end of billing period."),
  });

  return (
    <div className="space-y-8 animate-fade-in">
      {/* Current subscription status */}
      {!isLoading && subscription && (subscription as any).status && (
        <div className="bg-[#141B2D] border border-[#1E2D47] rounded-xl p-5">
          <div className="flex items-start justify-between">
            <div>
              <h3 className="text-sm font-semibold text-white mb-3 flex items-center gap-2">
                <CreditCard className="w-4 h-4 text-blue-400" /> Current Subscription
              </h3>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-sm">
                <div><p className="text-xs text-slate-500 mb-0.5">Plan</p><p className="text-white font-semibold capitalize">{subscription.plan}</p></div>
                <div>
                  <p className="text-xs text-slate-500 mb-0.5">Status</p>
                  <p className={`font-semibold capitalize ${statusColor(subscription.status)}`}>{subscription.status.replace("_", " ")}</p>
                </div>
                <div><p className="text-xs text-slate-500 mb-0.5">Active Devices</p><p className="text-white font-semibold">{subscription.active_devices}</p></div>
                <div><p className="text-xs text-slate-500 mb-0.5">Next Renewal</p><p className="text-white font-semibold">{subscription.current_period_end ? formatDateTime(subscription.current_period_end).split(" ")[0] : "—"}</p></div>
              </div>
            </div>
            {subscription.status === "active" && (
              <button
                onClick={() => { if (confirm("Cancel subscription at end of period?")) cancelMutation.mutate(); }}
                className="text-xs text-slate-500 hover:text-red-400 transition-colors"
              >
                Cancel plan
              </button>
            )}
          </div>
          {subscription.status === "past_due" && (
            <div className="mt-4 flex items-center gap-2 p-3 bg-red-500/10 border border-red-500/30 rounded-lg text-red-400 text-sm">
              <AlertTriangle className="w-4 h-4" />
              Payment failed. Update your payment method to keep access.
            </div>
          )}
        </div>
      )}

      {/* Plans */}
      <div>
        <h2 className="text-lg font-semibold text-white mb-1">Choose a Plan</h2>
        <p className="text-sm text-slate-500 mb-5">Billed monthly per active endpoint. Cancel anytime.</p>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {plans.map((plan) => (
            <PlanCard
              key={plan.id}
              plan={plan}
              current={subscription}
              onSelect={(id) => subscribeMutation.mutate(id)}
            />
          ))}
        </div>
      </div>

      <p className="text-xs text-slate-600 text-center">
        Payments are processed securely by Stripe. CyberGuard never stores credit card information.
      </p>
    </div>
  );
}
