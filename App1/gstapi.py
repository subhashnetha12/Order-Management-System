# import json
# import requests
# from django.conf import settings
# from django.http import JsonResponse
# from django.views.decorators.csrf import csrf_exempt
# from django.views.decorators.http import require_POST
# from .utils import get_valid_access_token, GspTokenError


# @csrf_exempt
# @require_POST
# def generate_gsp_token(request):
#     """
#     Force generate and save a fresh token manually.
#     """
#     try:
#         token = get_valid_access_token(force_new=True)
#         return JsonResponse({
#             "success": True,
#             "message": "Token generated successfully",
#             "token_prefix": token[:20]  # show only first 20 chars
#         })
#     except GspTokenError as e:
#         return JsonResponse({"success": False, "message": str(e)}, status=500)
#     except Exception as e:
#         return JsonResponse({"success": False, "message": f"Unexpected error: {e}"}, status=500)


# @csrf_exempt
# @require_POST
# def gstin_details(request):
#     """
#     Fetch GSTIN details with dynamic token:
#     - If expired, auto-refresh
#     - If 401, retry once with fresh token
#     - Return head office + branch addresses in JSON
#     """
#     try:
#         body = json.loads(request.body or "{}")
#         gstin = body.get("gstin")
#         if not gstin:
#             return JsonResponse({"success": False, "message": "GSTIN is required"}, status=400)

#         def call_api(access_token: str) -> requests.Response:
#             headers = {
#                 "Content-Type": "application/json",
#                 "Authorization": f"Bearer {access_token}",
#             }
#             params = {"action": "TP", "gstin": gstin}
#             return requests.get(settings.GSP_GSTIN_SEARCH_URL, headers=headers, params=params, timeout=30)

#         # Try with current token
#         access_token = get_valid_access_token()
#         resp = call_api(access_token)

#         # Retry if unauthorized
#         if resp.status_code == 401:
#             access_token = get_valid_access_token(force_new=True)
#             resp = call_api(access_token)

#         # Parse response
#         try:
#             data = resp.json()
#             print("✅ GST API Response:", json.dumps(data, indent=2))  # <-- Added print
#         except Exception:
#             print("❌ Non-JSON response from GST API:", resp.text)  # <-- Added print for debugging
#             return JsonResponse(
#                 {"success": False, "message": f"Non-JSON response from GST API (HTTP {resp.status_code})."},
#                 status=resp.status_code or 502,
#             )

#         if resp.status_code == 200 and data.get("success") and data.get("result"):
#             result = data["result"]
#             customer_name = result.get("lgnm", "")
#             business_name = result.get("tradeNam", "")

#             # ---- Main Branch (Head Office) ----
#             pradr = result.get("pradr", {})
#             addr = pradr.get("addr", {})
#             main_branch = {
#                 "is_head_office": True,
#                 "customer_name": customer_name,
#                 "business_name": business_name,
#                 "address_line1": f"{addr.get('bno', '')}, {addr.get('flno', '')}".strip(", "),
#                 "address_line2": f"{addr.get('st', '')}, {addr.get('bnm', '')}, {addr.get('loc', '')}".strip(", "),
#                 "city": result.get("ctj", ""),
#                 "district": addr.get("dst", ""),
#                 "pincode": addr.get("pncd", ""),
#                 "state": addr.get("stcd", ""),
#                 "nature_of_business": pradr.get("ntr", ""),
#                 "latitude": addr.get("lt", ""),
#                 "longitude": addr.get("lg", ""),
#             }
#             print("🏢 Main Branch:", main_branch)  # <-- Print main branch

#             # ---- Other Branches ----
#             branches = []
#             for ad in result.get("adadr", []):
#                 addr = ad.get("addr", {})
#                 branch = {
#                     "is_head_office": False,
#                     "customer_name": customer_name,
#                     "business_name": business_name,
#                     "address_line1": f"{addr.get('bno', '')}, {addr.get('flno', '')}".strip(", "),
#                     "address_line2": f"{addr.get('st', '')}, {addr.get('bnm', '')}, {addr.get('loc', '')}".strip(", "),
#                     "city": addr.get("loc", ""),
#                     "district": addr.get("dst", ""),
#                     "pincode": addr.get("pncd", ""),
#                     "state": addr.get("stcd", ""),
#                     "nature_of_business": ad.get("ntr", ""),
#                     "latitude": addr.get("lt", ""),
#                     "longitude": addr.get("lg", ""),
#                 }
#                 print("🏬 Branch:", branch)  # <-- Print each branch
#                 branches.append(branch)

#             return JsonResponse({
#                 "success": True,
#                 "gstin": gstin,
#                 "main_branch": main_branch,
#                 "branches": branches,
#             })

#         print("⚠ GST API Error Response:", data)  # <-- Print error JSON
#         return JsonResponse(
#             {"success": False, "message": data.get("message", "Unknown error"), "raw": data},
#             status=resp.status_code or 502,
#         )

#     except GspTokenError as e:
#         print("❌ Token Error:", str(e))  # <-- Print token error
#         return JsonResponse({"success": False, "message": f"Token error: {e}"}, status=500)
#     except Exception as e:
#         print("❌ Exception:", str(e))  # <-- Print unexpected error
#         return JsonResponse({"success": False, "message": str(e)}, status=500)

import json
import requests
from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from .utils import get_valid_access_token, GspTokenError


@csrf_exempt
@require_POST
def generate_gsp_token(request):
    """
    Force generate and save a fresh token manually.
    """
    try:
        token = get_valid_access_token(force_new=True)
        return JsonResponse({
            "success": True,
            "message": "Token generated successfully",
            "token_prefix": token[:20]  # show only first 20 chars
        })
    except GspTokenError as e:
        return JsonResponse({"success": False, "message": str(e)}, status=500)
    except Exception as e:
        return JsonResponse({"success": False, "message": f"Unexpected error: {e}"}, status=500)



# utils.py (new file in your app)
import requests, json
from django.conf import settings
from .utils import get_valid_access_token, GspTokenError  # adjust import as per your project

def fetch_gstin_details(gstin: str):
    """
    Call GST API and return structured branch details.
    Returns dict with { success, main_branch, branches }.
    """
    def call_api(access_token: str) -> requests.Response:
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {access_token}",
        }
        params = {"action": "TP", "gstin": gstin}
        return requests.get(settings.GSP_GSTIN_SEARCH_URL, headers=headers, params=params, timeout=30)

    try:
        access_token = get_valid_access_token()
        resp = call_api(access_token)

        if resp.status_code == 401:  # retry with fresh token
            access_token = get_valid_access_token(force_new=True)
            resp = call_api(access_token)

        data = resp.json()
        if resp.status_code != 200 or not data.get("success"):
            return {"success": False, "message": data.get("message", "GST API error"), "raw": data}

        result = data.get("result", {})
        customer_name = result.get("lgnm", "")
        business_name = result.get("tradeNam", "")

        # ---- Main Branch ----
        pradr = result.get("pradr", {})
        addr = pradr.get("addr", {})
        main_branch = {
            "customer_name": customer_name,
            "business_name": business_name,
            "address_line1": f"{addr.get('bno', '')}, {addr.get('flno', '')}".strip(", "),
            "address_line2": f"{addr.get('st', '')}, {addr.get('bnm', '')}, {addr.get('loc', '')}".strip(", "),
            "city": result.get("ctj", ""),
            "district": addr.get("dst", ""),
            "pincode": addr.get("pncd", ""),
            "state": addr.get("stcd", ""),
            "nature_of_business": pradr.get("ntr", ""),
            "latitude": addr.get("lt", ""),
            "longitude": addr.get("lg", ""),
        }

        # ---- Additional Branches ----
        branches = []
        for ad in result.get("adadr", []):
            addr = ad.get("addr", {})
            branches.append({
                "customer_name": customer_name,
                "business_name": business_name,
                "address_line1": f"{addr.get('bno', '')}, {addr.get('flno', '')}".strip(", "),
                "address_line2": f"{addr.get('st', '')}, {addr.get('bnm', '')}, {addr.get('loc', '')}".strip(", "),
                "city": addr.get("loc", ""),
                "district": addr.get("dst", ""),
                "pincode": addr.get("pncd", ""),
                "state": addr.get("stcd", ""),
                "nature_of_business": ad.get("ntr", ""),
                "latitude": addr.get("lt", ""),
                "longitude": addr.get("lg", ""),
            })

        return {"success": True, "main_branch": main_branch, "branches": branches}

    except GspTokenError as e:
        return {"success": False, "message": f"Token error: {e}"}
    except Exception as e:
        return {"success": False, "message": str(e)}

@csrf_exempt
@require_POST
def gstin_details(request):
    body = json.loads(request.body or "{}")
    gstin = body.get("gstin")
    if not gstin:
        return JsonResponse({"success": False, "message": "GSTIN is required"}, status=400)

    data = fetch_gstin_details(gstin)
    return JsonResponse(data, status=200 if data.get("success") else 400)


