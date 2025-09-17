# import requests
# from datetime import timedelta
# from django.conf import settings
# from django.utils import timezone
# from .models import GspToken


# class GspTokenError(Exception):
#     pass


# def _request_new_token() -> dict:
#     headers = {
#         "gspappid": settings.GSP_APPID,
#         "gspappsecret": settings.GSP_APPSECRET,
#     }
#     resp = requests.post(settings.GSP_TOKEN_URL, headers=headers)
#     try:
#         data = resp.json()
#     except Exception:
#         raise GspTokenError(f"Token endpoint returned non-JSON (HTTP {resp.status_code}).")

#     if resp.status_code != 200:
#         raise GspTokenError(f"Token endpoint error {resp.status_code}: {data}")

#     if "access_token" not in data or "expires_in" not in data:
#         raise GspTokenError(f"Unexpected token payload: {data}")

#     return data


# def _save_token(data: dict) -> GspToken:
#     expires_in = int(data.get("expires_in", 3600))
#     margin = int(getattr(settings, "GSP_TOKEN_REFRESH_MARGIN", 60))
#     expires_at = timezone.now() + timedelta(seconds=max(0, expires_in - margin))

#     token_obj = GspToken.objects.create(
#         access_token=data["access_token"],
#         token_type=data.get("token_type", "Bearer"),
#         expires_at=expires_at,
#         gspappid=settings.GSP_APPID,
#         gspappsecret=settings.GSP_APPSECRET,
#     )
#     return token_obj


# def get_latest_access_token(force_new: bool = False) -> str:
#     """
#     Return the latest token. If force_new=True, fetch a fresh one.
#     Otherwise just use the latest saved by cron.
#     """
#     if not force_new:
#         token = GspToken.objects.first()
#         if token:
#             return token.access_token

#     # fallback if no token in DB or forced refresh
#     data = _request_new_token()
#     token = _save_token(data)
#     return token.access_token



import requests
from datetime import timedelta
from django.conf import settings
from django.db import transaction
from django.utils import timezone
from .models import GspToken


class GspTokenError(Exception):
    pass


def _request_new_token() -> dict:
    """
    Call Adaequare GSP auth endpoint and return token JSON.
    """
    headers = {
        "gspappid": settings.GSP_APPID,
        "gspappsecret": settings.GSP_APPSECRET,
    }
    resp = requests.post(settings.GSP_TOKEN_URL, headers=headers)

    try:
        data = resp.json()
    except Exception:
        raise GspTokenError(f"Token endpoint returned non-JSON (HTTP {resp.status_code}).")

    if resp.status_code != 200:
        raise GspTokenError(f"Token endpoint error {resp.status_code}: {data}")

    if "access_token" not in data or "expires_in" not in data:
        raise GspTokenError(f"Unexpected token payload: {data}")

    return data


def _save_token(data: dict) -> GspToken:
    """
    Save token to DB, keeping only the latest one.
    """
    expires_in = int(data.get("expires_in", 3600))
    margin = int(getattr(settings, "GSP_TOKEN_REFRESH_MARGIN", 60))
    expires_at = timezone.now() + timedelta(seconds=max(0, expires_in - margin))

    with transaction.atomic():
        GspToken.objects.all().delete()
        token_obj = GspToken.objects.create(
            access_token=data["access_token"],
            token_type=data.get("token_type", "Bearer"),
            expires_at=expires_at,
            gspappid=settings.GSP_APPID,
            gspappsecret=settings.GSP_APPSECRET,
        )
    return token_obj


def get_valid_access_token(force_new: bool = False) -> str:
    """
    Returns a valid access token from DB.
    Auto-refreshes if expired or missing.
    """
    if not force_new:
        token = GspToken.objects.first()
        if token and not token.is_expired:
            return token.access_token

    data = _request_new_token()
    token = _save_token(data)
    return token.access_token

