import json
import secrets
from http import HTTPStatus
from urllib.parse import urlparse

import bolt11
from fastapi import APIRouter, HTTPException, Query, Request
from lnbits.core.services import create_invoice, pay_invoice
from lnurl import encode as lnurl_encode
from lnurl.types import LnurlPayMetadata
from loguru import logger
from starlette.responses import HTMLResponse

from .crud import (
    create_hit,
    get_card,
    get_card_by_external_id,
    get_card_by_otp,
    get_hit,
    get_hits_today,
    spend_hit,
    update_card_counter,
    update_card_otp,
)
from .nxp424 import decrypt_sun, get_sun_mac

nostrnfcauth_lnurl_router = APIRouter()


# /nostrnfcauth/api/v1/scan?p=00000000000000000000000000000000&c=0000000000000000
@nostrnfcauth_lnurl_router.get("/api/v1/scan/{external_id}")
async def api_scan(p, c, request: Request, external_id: str):
    # some wallets send everything as lower case, no bueno
    p = p.upper()
    c = c.upper()
    card = None
    counter = b""
    card = await get_card_by_external_id(external_id)
    if not card:
        return {"status": "ERROR", "reason": "No card."}
    if not card.enable:
        return {"status": "ERROR", "reason": "Card is disabled."}
    try:
        card_uid, counter = decrypt_sun(bytes.fromhex(p), bytes.fromhex(card.k1))
        if card.uid.upper() != card_uid.hex().upper():
            return {"status": "ERROR", "reason": "Card UID mis-match."}
        if c != get_sun_mac(card_uid, counter, bytes.fromhex(card.k2)).hex().upper():
            return {"status": "ERROR", "reason": "CMAC does not check."}
    except Exception:
        return {"status": "ERROR", "reason": "Error decrypting card."}

    ctr_int = int.from_bytes(counter, "little")

    if ctr_int <= card.counter:
        return {"status": "ERROR", "reason": "This link is already used."}

    await update_card_counter(ctr_int, card.id)

    # gathering some info for hit record
    assert request.client
    ip = request.client.host
    if "x-real-ip" in request.headers:
        ip = request.headers["x-real-ip"]
    elif "x-forwarded-for" in request.headers:
        ip = request.headers["x-forwarded-for"]

    agent = request.headers["user-agent"] if "user-agent" in request.headers else ""
    todays_hits = await get_hits_today(card.id)

    hits_amount = 0
    for hit in todays_hits:
        hits_amount = hits_amount + hit.amount
    if hits_amount > card.daily_limit:
        return {"status": "ERROR", "reason": "Max daily limit spent."}
    hit = await create_hit(card.id, ip, agent, card.counter, ctr_int)

    # # the raw lnurl
    # lnurlpay_raw = str(request.url_for("nostrnfcauth.lnurlp_response", hit_id=hit.id))
    # # bech32 encoded lnurl
    # lnurlpay_bech32 = lnurl_encode(lnurlpay_raw)
    # # create a lud17 lnurlp to support lud19, add payLink field of the withdrawRequest
    # lnurlpay_nonbech32_lud17 = lnurlpay_raw.replace("https://", "lnurlp://").replace(
    #     "http://", "lnurlp://"
    # )

    # define a collection of badges with title and image url
    badges = [
        {"title": "Challenge Coin", "image": "https://cdn.satellite.earth/378ec02dfe70e532dba09b93d920bf673f3f363be7714aa66adf6729ee7e356e.jpg"},
        {"title": "Chainsaw Level 1", "image": "https://cdn.satellite.earth/2f1dccd44aae97521631ecc7a5e66e8f2580ab50e2fd6f2d28e762df164320b4.jpg"},
        {"title": "Transatlantic Sailing", "image": "https://cdn.satellite.earth/7a21629630f04df0de026801ce42c25dbbae52b4e64e3b9030e4e1e308f2bfec.jpg"},
    ]

    return {
        # "tag": "withdrawRequest",
        # "callback": str(request.url_for("nostrnfcauth.lnurl_callback", hit_id=hit.id)),
        # "k1": hit.id,
        # "minWithdrawable": 1 * 1000,
        # "maxWithdrawable": card.tx_limit * 1000,
        # "defaultDescription": f"Boltcard (refund address lnurl://{lnurlpay_bech32})",
        # "payLink": lnurlpay_nonbech32_lud17,  # LUD-19 compatibility
        "npub": card.npub
    }


@nostrnfcauth_lnurl_router.get(
    "/api/v1/lnurl/cb/{hit_id}",
    status_code=HTTPStatus.OK,
    name="nostrnfcauth.lnurl_callback",
)
async def lnurl_callback(
    hit_id: str,
    k1: str = Query(None),
    pr: str = Query(None),
):
    # TODO: why no hit_id? its not used why is it passed by url?
    logger.debug(f"TODO: why no hit_id? {hit_id}")
    if not k1:
        return {"status": "ERROR", "reason": "Missing K1 token"}

    hit = await get_hit(k1)

    if not hit:
        return {
            "status": "ERROR",
            "reason": "Record not found for this charge (bad k1)",
        }
    if hit.spent:
        return {"status": "ERROR", "reason": "Payment already claimed"}
    if not pr:
        return {"status": "ERROR", "reason": "Missing payment request"}

    try:
        invoice = bolt11.decode(pr)
    except bolt11.Bolt11Exception:
        return {"status": "ERROR", "reason": "Failed to decode payment request"}

    card = await get_card(hit.card_id)
    assert card
    assert invoice.amount_msat, "Invoice amount is missing"
    hit = await spend_hit(card_id=hit.id, amount=int(invoice.amount_msat / 1000))
    assert hit
    try:
        await pay_invoice(
            wallet_id=card.wallet,
            payment_request=pr,
            max_sat=card.tx_limit,
            extra={"tag": "nostrnfcauth", "hit": hit.id},
        )
        return {"status": "OK"}
    except Exception as exc:
        return {"status": "ERROR", "reason": f"Payment failed - {exc}"}


# /nostrnfcauth/api/v1/auth?a=00000000000000000000000000000000
@nostrnfcauth_lnurl_router.get("/api/v1/auth")
async def api_auth(a, request: Request):
    if a == "00000000000000000000000000000000":
        response = {"k0": "0" * 32, "k1": "1" * 32, "k2": "2" * 32}
        return response

    card = await get_card_by_otp(a)
    if not card:
        raise HTTPException(
            detail="Card does not exist.", status_code=HTTPStatus.NOT_FOUND
        )

    new_otp = secrets.token_hex(16)
    await update_card_otp(new_otp, card.id)

    lnurlw_base = (
        f"{urlparse(str(request.url)).netloc}/nostrnfcauth/api/v1/scan/{card.external_id}"
    )

    response = {
        "card_name": card.card_name,
        "id": str(1),
        "k0": card.k0,
        "k1": card.k1,
        "k2": card.k2,
        "k3": card.k1,
        "k4": card.k2,
        "lnurlw_base": "lnurlw://" + lnurlw_base,
        "protocol_name": "new_bolt_card_response",
        "protocol_version": str(1),
    }

    return response


###############LNURLPAY REFUNDS#################


@nostrnfcauth_lnurl_router.get(
    "/api/v1/lnurlp/{hit_id}",
    response_class=HTMLResponse,
    name="nostrnfcauth.lnurlp_response",
)
async def lnurlp_response(req: Request, hit_id: str):
    hit = await get_hit(hit_id)
    assert hit
    card = await get_card(hit.card_id)
    assert card
    if not hit:
        return {"status": "ERROR", "reason": "LNURL-pay record not found."}
    if not card.enable:
        return {"status": "ERROR", "reason": "Card is disabled."}
    pay_response = {
        "tag": "payRequest",
        "callback": str(req.url_for("nostrnfcauth.lnurlp_callback", hit_id=hit_id)),
        "metadata": LnurlPayMetadata(json.dumps([["text/plain", "Refund"]])),
        "minSendable": 1 * 1000,
        "maxSendable": card.tx_limit * 1000,
    }
    return json.dumps(pay_response)


@nostrnfcauth_lnurl_router.get(
    "/api/v1/lnurlp/cb/{hit_id}",
    response_class=HTMLResponse,
    name="nostrnfcauth.lnurlp_callback",
)
async def lnurlp_callback(hit_id: str, amount: str = Query(None)):
    hit = await get_hit(hit_id)
    assert hit
    card = await get_card(hit.card_id)
    assert card
    if not hit:
        return {"status": "ERROR", "reason": "LNURL-pay record not found."}

    _, payment_request = await create_invoice(
        wallet_id=card.wallet,
        amount=int(int(amount) / 1000),
        memo=f"Refund {hit_id}",
        unhashed_description=LnurlPayMetadata(
            json.dumps([["text/plain", "Refund"]])
        ).encode(),
        extra={"refund": hit_id},
    )

    pay_response = {"pr": payment_request, "routes": []}

    return json.dumps(pay_response)
