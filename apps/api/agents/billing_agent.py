"""
BILLING AGENT
Manages Stripe subscriptions, device counting, and automatic activation/deactivation.
"""
import uuid
import logging
import stripe
from apps.api.config import settings

logger = logging.getLogger(__name__)

stripe.api_key = settings.STRIPE_SECRET_KEY

PLAN_PRICES = {
    "starter": {"price_id": settings.STRIPE_PRICE_STARTER, "max_devices": 10, "price_per_device": 9.0},
    "pro": {"price_id": settings.STRIPE_PRICE_PRO, "max_devices": 100, "price_per_device": 19.0},
    "enterprise": {"price_id": settings.STRIPE_PRICE_ENTERPRISE, "max_devices": 9999, "price_per_device": 39.0},
}


class BillingAgent:

    async def handle_stripe_webhook(self, event_type: str, event_data: dict, db) -> None:
        """Handle Stripe webhook events."""
        from sqlalchemy import select, update
        from apps.api.models.subscription import Subscription, SubscriptionStatus
        from apps.api.models.tenant import Tenant
        from datetime import datetime

        subscription_obj = event_data.get("object", {})
        stripe_sub_id = subscription_obj.get("id")

        if event_type == "customer.subscription.created":
            logger.info(f"Subscription created: {stripe_sub_id}")

        elif event_type == "customer.subscription.updated":
            if stripe_sub_id:
                result = await db.execute(
                    select(Subscription).where(Subscription.stripe_subscription_id == stripe_sub_id)
                )
                sub = result.scalar_one_or_none()
                if sub:
                    sub.status = subscription_obj.get("status", sub.status)
                    if subscription_obj.get("current_period_start"):
                        sub.current_period_start = datetime.fromtimestamp(subscription_obj["current_period_start"])
                    if subscription_obj.get("current_period_end"):
                        sub.current_period_end = datetime.fromtimestamp(subscription_obj["current_period_end"])
                    await db.flush()

        elif event_type == "customer.subscription.deleted":
            if stripe_sub_id:
                result = await db.execute(
                    select(Subscription).where(Subscription.stripe_subscription_id == stripe_sub_id)
                )
                sub = result.scalar_one_or_none()
                if sub:
                    sub.status = SubscriptionStatus.canceled
                    tenant_result = await db.execute(select(Tenant).where(Tenant.id == sub.tenant_id))
                    tenant = tenant_result.scalar_one_or_none()
                    if tenant:
                        tenant.is_active = False
                    await db.flush()

        elif event_type == "invoice.payment_failed":
            logger.warning(f"Payment failed for subscription: {stripe_sub_id}")

    async def count_active_devices(self, tenant_id: uuid.UUID, db) -> int:
        from sqlalchemy import select, func
        from apps.api.models.device import Device

        result = await db.execute(
            select(func.count(Device.id)).where(
                Device.tenant_id == tenant_id,
                Device.is_active == True,
            )
        )
        return result.scalar() or 0

    async def check_device_limit(self, tenant_id: uuid.UUID, db) -> bool:
        """Returns True if tenant can add more devices."""
        from sqlalchemy import select
        from apps.api.models.tenant import Tenant

        result = await db.execute(select(Tenant).where(Tenant.id == tenant_id))
        tenant = result.scalar_one_or_none()
        if not tenant:
            return False

        current_count = await self.count_active_devices(tenant_id, db)
        return current_count < tenant.max_devices

    async def create_stripe_customer(self, tenant_name: str, email: str) -> str:
        """Create a Stripe customer and return customer_id."""
        customer = stripe.Customer.create(
            name=tenant_name,
            email=email,
            metadata={"source": "cyberguard"},
        )
        return customer.id

    async def create_subscription(self, customer_id: str, plan: str, device_count: int) -> dict:
        """Create a Stripe subscription for a tenant."""
        plan_data = PLAN_PRICES.get(plan, PLAN_PRICES["starter"])
        subscription = stripe.Subscription.create(
            customer=customer_id,
            items=[{
                "price": plan_data["price_id"],
                "quantity": max(device_count, 1),
            }],
            payment_behavior="default_incomplete",
            expand=["latest_invoice.payment_intent"],
        )
        return {
            "subscription_id": subscription.id,
            "status": subscription.status,
            "client_secret": subscription.latest_invoice.payment_intent.client_secret
            if subscription.latest_invoice and subscription.latest_invoice.payment_intent
            else None,
        }

    async def update_subscription_quantity(self, stripe_subscription_id: str, quantity: int) -> None:
        """Update the device count in Stripe subscription."""
        subscription = stripe.Subscription.retrieve(stripe_subscription_id)
        item_id = subscription["items"]["data"][0]["id"]
        stripe.SubscriptionItem.modify(item_id, quantity=max(quantity, 1))
        logger.info(f"Updated subscription {stripe_subscription_id} quantity to {quantity}")
