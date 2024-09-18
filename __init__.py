import asyncio

from fastapi import APIRouter
from loguru import logger

from .crud import db
from .tasks import wait_for_paid_invoices
from .views import nostrnfcauth_generic_router
from .views_api import nostrnfcauth_api_router
from .views_lnurl import nostrnfcauth_lnurl_router

nostrnfcauth_static_files = [
    {
        "path": "/nostrnfcauth/static",
        "name": "nostrnfcauth_static",
    }
]

nostrnfcauth_ext: APIRouter = APIRouter(prefix="/nostrnfcauth", tags=["nostrnfcauth"])
nostrnfcauth_ext.include_router(nostrnfcauth_generic_router)
nostrnfcauth_ext.include_router(nostrnfcauth_api_router)
nostrnfcauth_ext.include_router(nostrnfcauth_lnurl_router)

scheduled_tasks: list[asyncio.Task] = []


def nostrnfcauth_stop():
    for task in scheduled_tasks:
        try:
            task.cancel()
        except Exception as ex:
            logger.warning(ex)


def nostrnfcauth_start():
    from lnbits.tasks import create_permanent_unique_task

    task = create_permanent_unique_task("ext_nostrnfcauth", wait_for_paid_invoices)
    scheduled_tasks.append(task)


__all__ = [
    "db",
    "nostrnfcauth_ext",
    "nostrnfcauth_static_files",
    "nostrnfcauth_start",
    "nostrnfcauth_stop",
]
