import uuid
from fastapi import APIRouter, Depends, HTTPException, Request, Header
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel
from typing import Optional
import stripe

from apps.api.database import get_db
from apps.api.middleware.auth import get_current_user
from apps.api.core.rbac import require_permission
from apps.api.models.subscription import Subscription, SubscriptionStatus
from apps.api.models.tenant import Tenant
from apps.api.models.user import User, UserRole
from apps.api.agents.billing_agent import BillingAgent, PLAN_PRICES
from apps.api.config import settings

router = APIRouter(prefix="/billing", tags=["Billing"])
billing_agent = BillingAgent()


class SubscribeRequest(BaseModel):
    plan: str
    payment_method_id: Optional[str] = None


@router.get("/plans")
async def get_plans():
    """Public endpoint: available plans and pricing."""
    return [
        {
            "id": "starter",
            "name": "Starter",
            "price_per_device": 9.0,
            "max_devices": 10,
            "currency": "USD",
            "billing_period": "monthly",
            "features": [
                "Process & network monitoring",
                "10 detection rules",
                "Basic alerting",
                "7-day log retention",
                "Email support",
            ],
        },
        {
            "id": "pro",
            "name": "Pro",
            "price_per_device": 19.0,
            "max_devices": 100,
            "currency": "USD",
            "billing_period": "monthly",
            "features": [
                "Everything in Starter",
                "Digital forensics module",
                "Threat intelligence enrichment",
                "Gemma AI analysis",
                "MITRE ATT&CK mapping",
                "30-day log retention",
                "Priority support",
            ],
            "popular": True,
        },
        {
            "id": "enterprise",
            "name": "Enterprise",
            "price_per_device": 39.0,
            "max_devices": None,
            "currency": "USD",
            "billing_period": "monthly",
            "features": [
                "Everything in Pro",
                "Unlimited devices",
                "Custom detection rules",
                "SIEM integration",
                "Compliance reporting",
                "90-day log retention",
                "Dedicated support",
                "SLA guarantee",
            ],
        },
    ]


@router.get("/subscription")
async def get_subscription(
    current_user: User = Depends(require_permission("billing:read")),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Subscription).where(Subscription.tenant_id == current_user.tenant_id)
        .order_by(Subscription.created_at.desc())
    )
    sub = result.scalar_one_or_none()
    if not sub:
        return {"status": "no_subscription", "tenant_id": str(current_user.tenant_id)}

    active_devices = await billing_agent.count_active_devices(current_user.tenant_id, db)

    return {
        "id": str(sub.id),
        "plan": sub.plan,
        "status": sub.status,
        "price_per_device": float(sub.price_per_device),
        "active_devices": active_devices,
        "current_period_start": sub.current_period_start.isoformat() if sub.current_period_start else None,
        "current_period_end": sub.current_period_end.isoformat() if sub.current_period_end else None,
    }


@router.post("/subscribe")
async def create_subscription(
    data: SubscribeRequest,
    current_user: User = Depends(require_permission("billing:write")),
    db: AsyncSession = Depends(get_db),
):
    if current_user.role not in (UserRole.owner, UserRole.admin):
        raise HTTPException(status_code=403, detail="Only owners and admins can manage billing")

    tenant_result = await db.execute(select(Tenant).where(Tenant.id == current_user.tenant_id))
    tenant = tenant_result.scalar_one_or_none()

    # Create or retrieve Stripe customer
    if not tenant.stripe_customer_id:
        customer_id = await billing_agent.create_stripe_customer(tenant.name, current_user.email)
        tenant.stripe_customer_id = customer_id
        await db.flush()
    else:
        customer_id = tenant.stripe_customer_id

    active_devices = await billing_agent.count_active_devices(current_user.tenant_id, db)

    subscription_data = await billing_agent.create_subscription(customer_id, data.plan, max(active_devices, 1))

    plan_data = PLAN_PRICES.get(data.plan, PLAN_PRICES["starter"])
    sub = Subscription(
        id=uuid.uuid4(),
        tenant_id=current_user.tenant_id,
        stripe_subscription_id=subscription_data["subscription_id"],
        stripe_customer_id=customer_id,
        plan=data.plan,
        price_per_device=plan_data["price_per_device"],
        active_devices=active_devices,
        status=SubscriptionStatus.incomplete,
    )
    db.add(sub)
    await db.flush()

    return {
        "subscription_id": subscription_data["subscription_id"],
        "status": subscription_data["status"],
        "client_secret": subscription_data.get("client_secret"),
    }


@router.post("/webhook")
async def stripe_webhook(request: Request, stripe_signature: str = Header(None)):
    """Handle Stripe webhook events. Signature is verified before processing."""
    payload = await request.body()

    try:
        event = stripe.Webhook.construct_event(
            payload, stripe_signature, settings.STRIPE_WEBHOOK_SECRET
        )
    except stripe.error.SignatureVerificationError:
        raise HTTPException(status_code=400, detail="Invalid Stripe signature")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Webhook error: {e}")

    async with __import__("apps.api.database", fromlist=["AsyncSessionLocal"]).AsyncSessionLocal() as db:
        await billing_agent.handle_stripe_webhook(event["type"], event["data"], db)
        await db.commit()

    return {"status": "ok", "event_type": event["type"]}


@router.put("/cancel")
async def cancel_subscription(
    current_user: User = Depends(require_permission("billing:write")),
    db: AsyncSession = Depends(get_db),
):
    if current_user.role != UserRole.owner:
        raise HTTPException(status_code=403, detail="Only owners can cancel subscriptions")

    result = await db.execute(
        select(Subscription).where(
            Subscription.tenant_id == current_user.tenant_id,
            Subscription.status == SubscriptionStatus.active,
        )
    )
    sub = result.scalar_one_or_none()
    if not sub:
        raise HTTPException(status_code=404, detail="No active subscription found")

    stripe.Subscription.modify(sub.stripe_subscription_id, cancel_at_period_end=True)
    sub.status = SubscriptionStatus.canceled

    return {"status": "cancellation_scheduled", "ends_at": sub.current_period_end.isoformat() if sub.current_period_end else None}
