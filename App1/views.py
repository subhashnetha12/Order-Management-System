from django.shortcuts import render,redirect,get_object_or_404
from urllib3 import request
from .models import *
from django.contrib import messages
import random
from django.core.mail import send_mail
import random
import datetime
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password


from datetime import datetime as dt
from django.db.models import Sum, Count
from django.utils.timezone import now
from datetime import date
from django.views.decorators.csrf import csrf_exempt
from decimal import Decimal, InvalidOperation
from django.db import transaction
from django.http import JsonResponse
# Create your views here.

from num2words import num2words

from django.utils import timezone
from django.contrib import messages
from django.contrib.auth.hashers import check_password

def login(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        print("Username entered:", username)
        print("Password entered:", password)

        try:
            user = User.objects.get(username=username)
            print("User:", user)

            if check_password(password, user.password):
                # ✅ Save session
                request.session['current_user'] = user.username

                # ✅ Create / update attendance record for today (check-in)
                today = timezone.now().date()
                attendance, created = Attendance.objects.get_or_create(user=user, date=today)
                if not attendance.check_in:  # avoid duplicate check-in
                    attendance.check_in = timezone.now()
                    attendance.save()

                messages.success(request, 'Login Success')
                return redirect('dashboard')  # generic dashboard
            else:
                messages.error(request, 'Invalid username or password')
        except User.DoesNotExist:
            print("User does not exist with username:", username)
            messages.error(request, 'User Does Not exist')

        return redirect('login')

    else:
        if 'current_user' in request.session:
            return redirect('dashboard')
        return render(request, 'login.html')


def logout(request):
    current_user = request.session.get('current_user')

    if current_user:
        try:
            user = User.objects.get(username=current_user)

            # ✅ Update today's attendance with checkout time
            today = timezone.now().date()
            attendance = Attendance.objects.filter(user=user, date=today).first()
            if attendance and not attendance.check_out:
                attendance.check_out = timezone.now()
                attendance.save()

        except User.DoesNotExist:
            pass

    # ✅ Clear session
    request.session.flush()
    return redirect('login')


def attendance(request):
    current_user, role_permission = get_logged_in_user(request)
    if not current_user:
        return redirect('login')

    # ✅ If Admin → show all attendance
    if current_user.role.name.lower() == "admin":
        attendance_records = Attendance.objects.select_related("user").order_by("-date", "-check_in")
    else:
        # ✅ Otherwise → show only current user's attendance
        attendance_records = Attendance.objects.filter(user=current_user).order_by("-date", "-check_in")

    context = {
        'current_user': current_user,
        'role_permission': role_permission,
        'attendance_records': attendance_records,
    }
    return render(request, 'company_admin/attendance.html', context)



def get_logged_in_user(request):
    username = request.session.get('current_user')
    if not username:
        return None, None  # always return a tuple

    try:
        user = User.objects.get(username=username)
        try:
            role_permission = RolePermissions.objects.get(role=user.role)
        except RolePermissions.DoesNotExist:
            role_permission = None
        return user, role_permission
    except User.DoesNotExist:
        return None, None 



def forgot_password(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        try:
            user = User.objects.get(email=email)

            # Generate and store OTP in session
            otp = random.randint(100000, 999999)
            request.session['reset_email'] = email
            request.session['otp'] = otp
            request.session['otp_expiry'] = (
                datetime.datetime.now() + datetime.timedelta(minutes=5)
            ).isoformat()

            # Send email using configured SMTP settings
            send_mail(
                'Your OTP Code',
                f'Your OTP for password reset is {otp}. This OTP is valid for 5 minutes.',
                settings.EMAIL_HOST_USER,
                [email],
                fail_silently=False,
            )

            messages.success(request, 'OTP sent to your email.')
            return redirect('verify_otp')

        except User.DoesNotExist:
            messages.error(request, 'This email is not registered.')

    return render(request, 'forgot_password.html')


def verify_otp(request):
    if request.method == 'POST':
        entered_otp = request.POST.get('otp')
        session_otp = str(request.session.get('otp'))
        otp_expiry_str = request.session.get('otp_expiry')

        # Convert expiry time to datetime object
        if otp_expiry_str:
            try:
                otp_expiry = dt.fromisoformat(otp_expiry_str)
            except ValueError:
                messages.error(request, "Invalid expiry format.")
                return redirect('forgot_password')
        else:
            messages.error(request, "Session expired. Please request OTP again.")
            return redirect('forgot_password')

        if dt.now() > otp_expiry:
            messages.error(request, "OTP has expired. Please request a new OTP.")
            return redirect('resend_otp')

        if entered_otp == session_otp:
            messages.success(request, "OTP verified successfully. You can now reset your password.")
            return redirect('reset_password')
        else:
            messages.error(request, "Invalid OTP. Please try again.")

    return render(request, 'verify_otp.html')


def resend_otp(request):
    email = request.session.get('reset_email')
    if not email:
        messages.error(request, "Session expired. Please start the password reset again.")
        return redirect('forgot_password')

    # Generate a new OTP
    otp = random.randint(100000, 999999)
    request.session['otp'] = otp
    request.session['otp_expiry'] = (
        datetime.datetime.now() + datetime.timedelta(minutes=5)
    ).isoformat()

    # Send the new OTP
    send_mail(
        'Your New OTP Code',
        f'Your new OTP is {otp}. It is valid for 5 minutes.',
        settings.EMAIL_HOST_USER,
        [email],
        fail_silently=False,
    )

    messages.success(request, 'A new OTP has been sent to your email.')
    return redirect('verify_otp')


def reset_password(request):
    if 'reset_email' not in request.session:
        messages.error(request, "Session expired. Please start the process again.")
        return redirect('forgot_password')

    if request.method == 'POST':
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')

        if new_password != confirm_password:
            messages.error(request, "Passwords do not match.")
        else:
            email = request.session['reset_email']
            #User = get_user_model()

            try:
                user = User.objects.get(email=email)
                user.password = make_password(new_password)
                user.save()

                # Clear session values after successful reset
                del request.session['reset_email']
                if 'otp' in request.session:
                    del request.session['otp']
                if 'otp_expiry' in request.session:
                    del request.session['otp_expiry']

                messages.success(request, "Password reset successful. Please log in.")
                return redirect('login')
            except User.DoesNotExist:
                messages.error(request, "User not found.")

    return render(request, 'reset_password.html')


from django.db.models import Sum
from django.db.models.functions import TruncDate

def dashboard(request):
    current_user, role_permission = get_logged_in_user(request)
    if not current_user:
        return redirect('login')

    today = date.today()

    # Product distribution for Pie Chart (total produced per product)
    product_sales_distribution = (
        OrderItem.objects.values('product__name')
        .annotate(total_quantity=Sum('quantity'))
        .order_by('product__name')
    )

    # Daily production data including product names for Line Chart
    daily_production_data = (
        DailyProduction.objects
        .annotate(date_only=TruncDate('date'))
        .values('date_only', 'product__name')
        .annotate(total_quantity=Sum('stock_in'))
        .order_by('date_only', 'product__name')
    )

    customers = Customer.objects.all()
    top_customers = (
        customers.annotate(
            total_revenue=Sum('orders__grand_total'),
            total_orders=Count('orders')
        )
        .order_by('-total_revenue')[:5]
    )
    top_customers_list = [
        {
            "name": c.full_name,
            "revenue": float(c.total_revenue or 0),
            "orders": c.total_orders,
            "shop_name": c.shop_name,
            "shop_city":c.shop_city
        }
        for c in top_customers
    ]

    salesmen = User.objects.filter(role__name__icontains="Salesman")
    top_salesmen = (
        salesmen.annotate(
            revenue=Sum('orders_created__grand_total'),
            orders=Count('orders_created')
        ).order_by('-revenue')[:5]
    )

    top_salesman_list = [

        {
            'first_name': s.first_name,
            'last_name': s.last_name,
            'revenue': float(s.revenue or 0),
            'orders': s.orders
        } for s in top_salesmen
    ]
    context = {
        'current_user': current_user,
        'role_permission':role_permission,
        'today_production': DailyProduction.objects.filter(date__date=today).aggregate(total=Sum('stock_in'))['total'] or 0,
        'total_categories': Category.objects.count(),
        'total_products': Product.objects.count(),
        'total_quantity': DailyProduction.objects.aggregate(total=Sum('stock_in'))['total'] or 0,
        'total_customers': Customer.objects.count(),
        'total_staff': User.objects.count(),
        'pending_deliveries': 0,
        'total_orders': Order.objects.count(),
        'category_distribution': Category.objects.annotate(product_count=Count('product')),
        'product_distribution': list(product_sales_distribution),
        'daily_production_data': list(daily_production_data),
        'top_customers_list':top_customers_list,
        'top_salesman_list':top_salesman_list
    }

    return render(request, 'company_admin/dashboard.html', context)



@csrf_exempt
def profile(request):
    current_user, role_permission = get_logged_in_user(request)
    if not current_user:
        return redirect('login')

    if request.method == 'POST':
        current_user.first_name = request.POST.get('first_name', '').strip()
        current_user.last_name = request.POST.get('last_name', '').strip()
        current_user.email = request.POST.get('email', '').strip()
        current_user.phone_number = request.POST.get('phone_number', '').strip()
        current_user.address = request.POST.get('address', '').strip()
        current_user.city = request.POST.get('city', '').strip()
        current_user.state = request.POST.get('state', '').strip()
        current_user.pincode = request.POST.get('pincode', '').strip()

        if not current_user.first_name or not current_user.last_name or not current_user.email:
            messages.error(request, 'Required fields are missing.')
        else:
            current_user.save()
            messages.success(request, 'Profile updated successfully!')
        return redirect('profile')

    return render(request, 'accounts/profile.html', {'current_user': current_user, 'role_permission':role_permission})


def user_table(request):
    current_user, role_permission = get_logged_in_user(request)
    if not current_user:
        return redirect('login')
    
    users = User.objects.all()
    context = { 'users': users , 'current_user':current_user, 'role_permission':role_permission}
    return render(request,'accounts/user_table.html', context)


from django.core.mail import send_mail
from django.conf import settings

def send_welcome_email(user, password):
    """
    Send a welcome email to a newly registered user with their login details.
    """

    subject = f"Welcome to SOUTH SUTRA, {user.username}!"

    message = (
        f"Dear {user.first_name or user.username},\n\n"
        f"Congratulations and welcome to SOUTH SUTRA! 🎉\n\n"
        f"Your account has been successfully created. Below are your login details:\n\n"
        f"Username: {user.username}\n"
        f"Password: {password}\n\n"

        # f"Please keep this information safe. We recommend changing your password "
        # f"after your first login for security purposes.\n\n"

        # f"You can login here: {settings.WEBSITE_URL if hasattr(settings, 'WEBSITE_URL') else 'https://southsutra.com/login'}\n\n"

        # f"If you face any issues, feel free to reach out to us at "
        # f"{getattr(settings, 'DEFAULT_SUPPORT_EMAIL', 'support@southsutra.com')} "
        # f"or {getattr(settings, 'DEFAULT_SUPPORT_PHONE', '+91-8971607888')}.\n\n"

        # f"We are excited to have you with us!\n\n"
        # f"Best regards,\n"
        # f"SOUTH SUTRA Team\n"
        # f"{getattr(settings, 'COMPANY_CONTACT_INFO', 'Bangalore, India')}"
    )

    recipient_email = user.email
    if recipient_email:
        send_mail(
            subject,
            message,
            settings.EMAIL_HOST_USER,  # From email
            [recipient_email],
            fail_silently=False,
        )



def add_user(request):
    current_user, role_permission = get_logged_in_user(request)
    if not current_user:
        return redirect('login')
    roles = Role.objects.all()
    context = {
        'current_user':current_user,
        'role_permission':role_permission,
        'roles': roles
    }

    if request.method == 'POST':
        role_id = request.POST['role']
        username = request.POST['username']
        password = request.POST['password']
        first_name = request.POST['first_name']
        last_name = request.POST['last_name']
        email = request.POST['email']
        phone_number = request.POST['phone_number']
        address = request.POST['address']
        city = request.POST['city']
        state = request.POST['state']
        pincode = request.POST['pincode']
        is_active = request.POST.get('is_active') == 'true'
        profile_picture = request.FILES.get('profile_picture')

        role = get_object_or_404(Role, id=role_id)

        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already exists.")
            return render(request, 'accounts/add_user.html', context)

        if User.objects.filter(email=email).exists():
            messages.error(request, "Email already exists.")
            return render(request, 'accounts/add_user.html', context)

        if User.objects.filter(phone_number=phone_number).exists():
            messages.error(request, "Phone number already exists.")
            return render(request, 'accounts/add_user.html', context)

        user = User(
            role=role,
            username=username,
            password=make_password(password),
            first_name=first_name,
            last_name=last_name,
            email=email,
            phone_number=phone_number,
            address=address,
            city=city,
            state=state,
            pincode=pincode,
            is_active=is_active,
             profile_picture=profile_picture 
        )
        user.save()
        send_welcome_email(user, password)

        messages.success(request, 'User added successfully.')
        return redirect('user_table')

    return render(request, 'accounts/add_user.html', context)


def edit_user(request, id):
    current_user, role_permission = get_logged_in_user(request)
    if not current_user:
        return redirect('login')

    user = get_object_or_404(User, id=id)
    roles = Role.objects.all()

    context = {
        'current_user':current_user,
        'role_permission':role_permission,
        'edit_user': user,
        'roles': roles
    }

    if request.method == 'POST':
        email = request.POST['email']
        phone_number = request.POST['phone_number']
        username = request.POST['username']

        if User.objects.filter(username=username).exclude(id=user.id).exists():
            messages.error(request, "Username already exists.")
            return render(request, 'accounts/add_user.html', context)

        if User.objects.filter(email=email).exclude(id=user.id).exists():
            messages.error(request, "Email already exists.")
            return render(request, 'accounts/add_user.html', context)

        if User.objects.filter(phone_number=phone_number).exclude(id=user.id).exists():
            messages.error(request, "Phone number already exists.")
            return render(request, 'accounts/add_user.html', context)

        user.username = username
        user.email = email
        user.phone_number = phone_number
        user.first_name = request.POST['first_name']
        user.last_name = request.POST['last_name']
        user.address = request.POST['address']
        user.city = request.POST['city']
        user.state = request.POST['state']
        user.pincode = request.POST['pincode']
        user.is_active = request.POST.get('is_active') == 'true'

        role_id = request.POST.get('role')
        user.role = get_object_or_404(Role, id=role_id)

        if 'profile_picture' in request.FILES:
            user.profile_picture = request.FILES['profile_picture']

        user.save()
        messages.success(request, 'User updated successfully.')
        return redirect('user_table')

    return render(request, 'accounts/add_user.html', context)


def delete_user(request, id):
    current_user = get_logged_in_user(request)
    if not current_user:
        return redirect('login')
    user = get_object_or_404(User, id=id)
    user.delete()
    messages.success(request, 'User deleted successfully.')
    return redirect('user_table')


def customer_table(request):
    current_user, role_permission = get_logged_in_user(request)
    if not current_user:
        return redirect('login')

    if current_user.role.name.lower() == "admin":
        customers = Customer.objects.all()
    else:
        customers = Customer.objects.filter(user=current_user)

    context = {
        'customers': customers,
        'current_user': current_user,
        'role_permission': role_permission
    }
    return render(request, 'accounts/customer_table.html', context)


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




def add_customer(request):
    current_user, role_permission = get_logged_in_user(request)
    if not current_user:
        return redirect('login')

    users = User.objects.exclude(role__name__iexact="Admin")
    context = {"current_user": current_user, "users": users, "role_permission": role_permission}

    if request.method == 'POST':
        # --- Collect form data ---
        user_id = request.POST.get('user')
        full_name = request.POST.get('full_name')
        email = request.POST.get('email') or None
        phone_number = request.POST.get('phone_number') or None
        credit_period = request.POST.get('credit_period')
        shop_name = request.POST.get('shop_name')
        shop_type = request.POST.get('shop_type')
        is_gst_registered = request.POST.get('is_gst_registered') == 'True'
        gst_number = request.POST.get('gst_number', '').strip() if is_gst_registered else ''
        shop_address = request.POST.get('shop_address')
        shop_city = request.POST.get('shop_city')
        shop_district = request.POST.get('shop_district')
        shop_state = request.POST.get('shop_state')
        shop_pincode = request.POST.get('shop_pincode')
        discount = request.POST.get('discount', 0.0)
        is_active = request.POST.get('is_active') == 'true'
        weekday_footfall = request.POST.get('foot_fall_weekdays') or 0
        weekend_footfall = request.POST.get('foot_fall_weekends') or 0

        # --- Validations ---
        if Customer.objects.filter(email=email).exists():
            messages.error(request, "Email already exists.")
            return render(request, 'accounts/add_customer.html', context)
        if Customer.objects.filter(phone_number=phone_number).exists():
            messages.error(request, "Phone number already exists.")
            return render(request, 'accounts/add_customer.html', context)
        if gst_number and Customer.objects.filter(gst_number=gst_number).exists():
            messages.error(request, "GST number already exists.")
            return render(request, 'accounts/add_customer.html', context)

        # --- Save Customer (Head Office goes here) ---
        customer = Customer.objects.create(
            user_id=user_id,
            full_name=full_name,
            email=email,
            phone_number=phone_number,
            credit_period=credit_period,
            shop_name=shop_name,
            shop_type=shop_type,
            is_gst_registered=is_gst_registered,
            gst_number=gst_number,
            shop_address_line1=shop_address,
            shop_city=shop_city,
            shop_district=shop_district,
            shop_state=shop_state,
            shop_pincode=shop_pincode,
            discount=discount,
            is_active=is_active,
            weekday_footfall=int(weekday_footfall),
            weekend_footfall=int(weekend_footfall)
        )

        # --- Save shop images ---
        for image in request.FILES.getlist('shop_images'):
            CustomerShopImage.objects.create(customer=customer, image=image)

        # --- Fetch GSTIN details ---
        if is_gst_registered and gst_number:
            data = fetch_gstin_details(gst_number)
            if data.get("success"):

                # ✅ Update Customer fields from Head Office details (but keep form overrides)
                main = data.get("main_branch")
                if main:
                    customer.customer_name = request.POST.get("main_customer_name", main.get("customer_name", customer.customer_name))
                    customer.shop_name = request.POST.get("main_shop_name", main.get("business_name", customer.shop_name))
                    customer.shop_address_line1 = (
                        request.POST.get("main_address_line1", main.get("address_line1", "")) + ", " +
                        request.POST.get("main_address_line2", main.get("address_line2", ""))
                    )
                    customer.shop_city = request.POST.get("main_city", main.get("city", customer.shop_city))
                    customer.shop_district = request.POST.get("main_district", main.get("district", customer.shop_district))
                    customer.shop_state = request.POST.get("main_state", main.get("state", customer.shop_state))
                    customer.shop_pincode = request.POST.get("main_pincode", main.get("pincode", customer.shop_pincode))
                    customer.nature_of_business = request.POST.get("main_nature_of_business", main.get("nature_of_business", ""))
                    customer.save()

                # ✅ Save branches (only in Branch table)
                for i, br in enumerate(data.get("branches", [])):
                    Branch.objects.create(
                        customer=customer,
                        gstin=request.POST.get(f"branch_{i}_gstin", gst_number),
                        customer_name=request.POST.get(f"branch_{i}_customer_name", br.get("customer_name", "")),
                        business_name=request.POST.get(f"branch_{i}_shop_name", br.get("business_name", "")),
                        address_line1=request.POST.get(f"branch_{i}_address_line1", br.get("address_line1", "")),
                        address_line2=request.POST.get(f"branch_{i}_address_line2", br.get("address_line2", "")),
                        city=request.POST.get(f"branch_{i}_city", br.get("city", "")),
                        district=request.POST.get(f"branch_{i}_district", br.get("district", "")),
                        state=request.POST.get(f"branch_{i}_state", br.get("state", "")),
                        pincode=request.POST.get(f"branch_{i}_pincode", br.get("pincode", "")),
                        is_head_office=False,
                        nature_of_business=request.POST.get(f"branch_{i}_nature_of_business", br.get("nature_of_business", "")),
                        latitude=br.get("latitude", ""),
                        longitude=br.get("longitude", "")
                    )

        messages.success(request, "Customer and branch details added successfully.")
        return redirect('customer_table')

    return render(request, 'accounts/add_customer.html', context)



def add_customer1(request):
    current_user, role_permission = get_logged_in_user(request)
    if not current_user:
        return redirect('login')

    users = User.objects.filter(role__name__iexact="Salesman")
    context = {
        "current_user": current_user,
        "users": users,
        "role_permission": role_permission
    }

    if request.method == 'POST':
        # --- Collect form data ---
        user_id = request.POST['user']
        full_name = request.POST['full_name']
        email = request.POST['email'] or None
        phone_number = request.POST['phone_number'] or None
        credit_period = request.POST.get('credit_period')
        shop_name = request.POST['shop_name']
        shop_type = request.POST.get('shop_type')
        is_gst_registered = request.POST.get('is_gst_registered') == 'True'
        gst_number = request.POST.get('gst_number', '').strip() if is_gst_registered else ''
        shop_address = request.POST['shop_address']
        shop_city = request.POST['shop_city']
        shop_district = request.POST['shop_district']
        shop_state = request.POST['shop_state']
        shop_pincode = request.POST['shop_pincode']
        discount = Decimal(request.POST.get('discount', 0.0))
        is_active = request.POST.get('is_active') == 'true'
        weekday_footfall = int(request.POST.get('foot_fall_weekdays') or 0)
        weekend_footfall = int(request.POST.get('foot_fall_weekends') or 0)
        nature_of_business=request.POST.get('nature_of_business',''),
        latitude=request.POST.get('latitude',''),
        longitude=request.POST.get('longitude','')

        # --- Validations ---
        if email and Customer.objects.filter(email=email).exists():
            messages.error(request, "Email already exists.")
            return render(request, 'accounts/add_customer.html', context)

        if phone_number and Customer.objects.filter(phone_number=phone_number).exists():
            messages.error(request, "Phone number already exists.")
            return render(request, 'accounts/add_customer.html', context)

        # --- Save manually entered customer first ---
        customer = Customer.objects.create(
            user_id=user_id,
            full_name=full_name,
            email=email,
            phone_number=phone_number,
            credit_period=credit_period,
            shop_name=shop_name,
            shop_type=shop_type,
            is_gst_registered=is_gst_registered,
            gst_number=gst_number,
            shop_address=shop_address,
            shop_city=shop_city,
            shop_district=shop_district,
            shop_state=shop_state,
            shop_pincode=shop_pincode,
            discount=discount,
            is_active=is_active,
            weekday_footfall=weekday_footfall,
            weekend_footfall=weekend_footfall,
            latitude=latitude,
            longitude=longitude,
            nature_of_business=nature_of_business
        )

        # --- Save shop images ---
        for image in request.FILES.getlist('shop_images'):
            CustomerShopImage.objects.create(customer=customer, image=image)

        # --- If GST registered, overwrite with GSTIN details ---
        if is_gst_registered and gst_number:
            data = fetch_gstin_details(gst_number)
            if data.get("success"):
                # 🔹 CHANGED: fetch which branch was selected
                selected_branch = request.POST.get("selected_branch", "main")

                branch_data = data.get("main_branch")  # default main

                # 🔹 CHANGED: allow branch selection
                if selected_branch != "main":
                    try:
                        branch_index = int(selected_branch)
                        branches = data.get("branches", [])
                        if 0 <= branch_index < len(branches):
                            branch_data = branches[branch_index]
                    except (ValueError, IndexError):
                        pass  # fallback to main

                if branch_data:
                    customer.customer_name = branch_data.get("customer_name", customer.customer_name)
                    customer.shop_name = branch_data.get("business_name") or customer.shop_name
                    customer.shop_address = f"{branch_data.get('address_line1','')}, {branch_data.get('address_line2','')}".strip(", ") or customer.shop_address
                    customer.shop_city = branch_data.get("city", customer.shop_city)
                    customer.shop_district = branch_data.get("district", customer.shop_district)
                    customer.shop_state = branch_data.get("state", customer.shop_state)
                    customer.shop_pincode = branch_data.get("pincode", customer.shop_pincode)
                    customer.save()

        messages.success(request, "Customer details saved successfully.")
        return redirect('customer_table')

    return render(request, 'accounts/add_customer.html', context)



def edit_customer(request, id):
    current_user, role_permission = get_logged_in_user(request)
    if not current_user:
        return redirect('login')
    customer = get_object_or_404(Customer, id=id)
    users = User.objects.filter(role__name__iexact="Salesman")

    context = {
        'current_user':current_user,
        'edit_customer': customer,
        'users': users,
        'role_permission': role_permission
    }

    if request.method == 'POST':
        try:

            customer.full_name = request.POST.get('full_name')
            customer.email = request.POST.get('email') or None
            customer.phone_number = request.POST.get('phone_number') or None
            customer.credit_period = request.POST.get('credit_period')
            customer.shop_name = request.POST.get('shop_name')
            customer.shop_type = request.POST.get('shop_type')
            # Do not update GST fields
            # customer.is_gst_registered = customer.is_gst_registered
            # customer.gst_number = customer.gst_number
            customer.shop_address_line1 = request.POST.get('shop_address_line1', '').strip()
            customer.shop_address_line1 = request.POST.get('shop_address', customer.shop_address_line1)
            customer.shop_city = request.POST.get('shop_city', customer.shop_city)
            customer.shop_district = request.POST.get('shop_district', customer.shop_district)
            customer.shop_state = request.POST.get('shop_state', customer.shop_state)
            customer.shop_pincode = request.POST.get('shop_pincode', customer.shop_pincode)
            customer.weekday_footfall = int(request.POST.get('foot_fall_weekdays')) if request.POST.get('foot_fall_weekdays') else None
            customer.weekend_footfall = int(request.POST.get('foot_fall_weekends')) if request.POST.get('foot_fall_weekends') else None

            customer.save()

            # Update branch details
            for idx, branch in enumerate(customer.branches.all()):
                prefix = f"branch_{idx}_"
                branch.customer_name = request.POST.get(prefix + "customer_name", branch.customer_name)
                branch.business_name = request.POST.get(prefix + "shop_name", branch.business_name)
                branch.address_line1 = request.POST.get(prefix + "address_line1", branch.address_line1)
                branch.address_line2 = request.POST.get(prefix + "address_line2", branch.address_line2)
                branch.city = request.POST.get(prefix + "city", branch.city)
                branch.district = request.POST.get(prefix + "district", branch.district)
                branch.state = request.POST.get(prefix + "state", branch.state)
                branch.pincode = request.POST.get(prefix + "pincode", branch.pincode)
                branch.nature_of_business = request.POST.get(prefix + "nature_of_business", branch.nature_of_business)
                # GSTIN should not be editable
                branch.save()

            for image in request.FILES.getlist('shop_images'):
                CustomerShopImage.objects.create(customer=customer, image=image)

            removed_images = request.POST.get("removed_images", "")
            if removed_images:
                ids = removed_images.split(",")
                CustomerShopImage.objects.filter(id__in=ids, customer=customer).delete()

            messages.success(request, "Customer updated successfully.")
            return redirect('customer_table')

        except Exception as e:
            messages.error(request, f"Error updating customer: {e}")

    return render(request, 'accounts/edit_customer.html', context)


def delete_customer(request, id):
    current_user = get_logged_in_user(request)
    if not current_user:
        return redirect('login')
    customer = get_object_or_404(Customer, id=id)
    customer.delete()
    messages.success(request, "Customer deleted successfully.")
    return redirect('customer_table')


def role_table(request):
    current_user, role_permission = get_logged_in_user(request)
    if not current_user:
        return redirect('login')
    roles = Role.objects.all()
    context={'roles':roles,'current_user':current_user, 'role_permission': role_permission}
    return render(request, 'accounts/role_table.html',context )


def add_role(request):
    current_user, role_permission = get_logged_in_user(request)
    if not current_user:
        return redirect('login')

    context = {'current_user': current_user, 'role_permission': role_permission}

    if request.method == "POST":
        name = request.POST['name'].strip()

        if Role.objects.filter(name__iexact=name).exists():
            messages.error(request, "This Role already exists.")
            return render(request, 'accounts/add_role.html', context)

        Role.objects.create(name=name)  # permissions auto-handled in save()
        messages.success(request, "Role added successfully.")
        return redirect('role_permissions', role_id=Role.objects.get(name__iexact=name).id)
    
    return render(request, 'accounts/add_role.html', context)


def edit_role(request, id):
    current_user, role_permission = get_logged_in_user(request)
    if not current_user:
        return redirect('login')

    role = get_object_or_404(Role, id=id)

    if request.method == 'POST':
        name = request.POST['name'].strip()

        if Role.objects.filter(name__iexact=name).exclude(id=id).exists():
            messages.error(request, "This Role already exists.")
            return render(request, 'accounts/add_role.html', {
                'edit_role': role,
                'current_user': current_user,
                'role_permission': role_permission
            })

        role.name = name
        role.save()  # permissions auto-updated in save()
        messages.success(request, "The Role has been updated.")
        return redirect('role_table')

    context = {"edit_role": role, 'current_user': current_user, 'role_permission': role_permission}
    return render(request, 'accounts/add_role.html', context)

def delete_role(request, id):
    current_user = get_logged_in_user(request)
    if not current_user:
        return redirect('login')
    role=get_object_or_404(Role, id=id)
    role.delete()
    messages.success(request, "role deleted successfully")
    return redirect('role_table')

def role_permissions(request, role_id):
    current_user, role_permission = get_logged_in_user(request)
    if not current_user:
        return redirect('login')

    role = get_object_or_404(Role, id=role_id)
    permissions, create = RolePermissions.objects.get_or_create(role=role)

    if request.method == 'POST':

        for field in RolePermissions._meta.get_fields():
            if field.name not in ['id', 'role']:
                setattr(permissions, field.name, field.name in request.POST)

        permissions.save()
        messages.success(request, "Permissions updated successfully.")
        return redirect('role_table')

    return render(request, 'accounts/role_permissions.html',{
        'role': role,
        'permissions': permissions,
        'current_user':current_user,
        'role_permission': role_permission
    })

def category_table(request):
    current_user, role_permission = get_logged_in_user(request)
    if not current_user:
        return redirect('login')
    categories = Category.objects.all()
    context = {'categories':categories,'current_user':current_user, 'role_permission': role_permission}
    return render(request, 'company_admin/category_table.html',context)


def add_category(request):
    current_user, role_permission = get_logged_in_user(request)
    if not current_user:
        return redirect('login')
    
    if request.method == 'POST':
        name = request.POST['name']
        if Category.objects.filter(name=name).exists():
            messages.error(request, "This Category already exists.")
            return render(request, 'company_admin/add_category.html', context)
        category = Category(
            name = name
        )
        category.save()
        messages.success(request, "Category added successfully.")
        return redirect('category_table')
    
    context={'current_user':current_user, 'role_permission':role_permission}
    
    return render(request, 'company_admin/add_category.html', context)


def edit_category(request,id):
    current_user, role_permission = get_logged_in_user(request)
    if not current_user:
        return redirect('login')
    
    category = get_object_or_404(Category, id=id)
    if request.method == 'POST':
        category.name = request.POST['name']

        if Category.objects.filter(name=category.name).exclude(id=id).exists():
            messages.error(request, "This Category already exists.")
            return render(request, 'company_admin/add_category.html', context)
        
        category.save()
        messages.success(request, "Category Updated successfully.")
        return redirect('category_table')
    context={'edit_category':category, 'current_user':current_user, 'role_permission': role_permission}
    return render(request, 'company_admin/add_category.html', context)


def delete_category(request,id):
    current_user = get_logged_in_user(request)
    if not current_user:
        return redirect('login')
    
    category = get_object_or_404(Category, id=id)
    category.delete()
    messages.success(request, "Category deleted successfully.")
    return redirect('category_table')
    

def product_table(request):
    current_user, role_permission = get_logged_in_user(request)
    if not current_user:
        return redirect('login')
    products = Product.objects.all()
    context = {'products':products,'current_user':current_user, 'role_permission': role_permission}
    return render(request, 'company_admin/product_table.html',context)


def add_product(request):
    current_user, role_permission = get_logged_in_user(request)
    if not current_user:
        return redirect('login')

    categories = Category.objects.all()

    if request.method == 'POST':
        try:
            name = request.POST['name']
            category_id = request.POST['category']
            description = request.POST['description']
            unit = request.POST['unit']
            hsn_code = request.POST['hsn_code']
            gstpercentage = request.POST['gstpercentage']
            category = Category.objects.get(id=category_id)

            if Product.objects.filter(name__iexact=name).exists():
                messages.error(request, "Product with this name already exists.")
                return render(request, 'company_admin/add_product.html')

            product = Product.objects.create(
                name=name,
                category=category,
                description=description,
                unit=unit,
                hsn_code=hsn_code,
                gstpercentage=gstpercentage
            )


            messages.success(request, 'Product added successfully.')
            return redirect('product_table')

        except Exception as e:
            messages.error(request, f"Error adding product: {e}")

    context = {
        'categories': categories,
        'current_user': current_user,
        'role_permission': role_permission
    }
    return render(request, 'company_admin/add_product.html', context)


def edit_product(request, id):
    current_user, role_permission = get_logged_in_user(request)
    if not current_user:
        return redirect('login')

    product = get_object_or_404(Product, id=id)
    categories = Category.objects.all()

    if request.method == 'POST':
        try:
            product.name = request.POST['name']
            product.description = request.POST['description']
            
            product.unit = request.POST['unit']
            product.hsn_code = request.POST['hsn_code']
            product.gstpercentage = request.POST['gstpercentage']

            product.save()


            messages.success(request, 'Product updated successfully.')
            return redirect('product_table')

        except Exception as e:
            messages.error(request, f"Error updating product: {e}")

    context = {
        'edit_product': product,
        'categories': categories,
        'current_user': current_user,
        'role_permission': role_permission
    }
    return render(request, 'company_admin/add_product.html', context)


def inventory_table(request):
    current_user, role_permission = get_logged_in_user(request)
    if not current_user:
        return redirect('login')

    inventory_list = Inventory.objects.select_related('product')

    context = {
        'inventory_list': inventory_list,
        'current_user': current_user,
        'role_permission': role_permission
    }

    return render(request, 'company_admin/inventory_table.html', context)


def delete_product(request, id):
    current_user, role_permission = get_logged_in_user(request)
    if not current_user:
        return redirect('login')
    product = get_object_or_404(Product, id=id)
    product.delete()
    messages.success(request, 'Product deleted successfully.')
    return redirect('product_table')


def daily_production_table(request):
    current_user, role_permission = get_logged_in_user(request)
    if not current_user:
        return redirect('login')
    daily_productions = DailyProduction.objects.all()
    context = {'daily_productions':daily_productions,'current_user':current_user, 'role_permission': role_permission}
    return render(request, 'company_admin/daily_production_table.html',context)


def add_daily_production(request):
    current_user, role_permission = get_logged_in_user(request)
    if not current_user:
        return redirect('login')

    products = Product.objects.all()

    if request.method == "POST":
        product_id = request.POST.get("product")
        weight_per_packet = request.POST.get("weight")
        manufactured_date = request.POST.get("manufactured_date")
        stock_in = request.POST.get("stock_in")
        batch_number = request.POST.get("batch_number")
        expiry_date = request.POST.get("expiry_date")
        sale_price = request.POST.get("sale_price")
        mrp = request.POST.get("mrp")

        if DailyProduction.objects.filter(batch_number=batch_number).exists():
            messages.error(request, "Batch number already exists.")
            return render(request, 'company_admin/add_daily_production.html', {
                'products': products,
                'current_user': current_user,
                'role_permission': role_permission
            })

        product = Product.objects.get(id=product_id)

        try:
            # convert stock_in to integer
            stock_in = int(stock_in) if stock_in else 0
            weight_per_packet = float(weight_per_packet) if weight_per_packet else 0
            sale_price = float(sale_price) if sale_price else 0
            mrp = float(mrp) if mrp else 0

            production = DailyProduction(
                product=product,
                weight_per_packet=weight_per_packet,
                manufactured_date=manufactured_date,
                stock_in=stock_in,
                batch_number=batch_number,
                expiry_date=expiry_date,
                sale_price=sale_price,
                mrp=mrp
            )

            inventory, _ = Inventory.objects.get_or_create(product=product)
            inventory.stock_in += stock_in  # ✅ safe now
            inventory.update_stock()
            production.save()
            
            messages.success(request, "Daily production added successfully!")
        except ValidationError as e:
            messages.error(request, str(e))  

        return redirect("daily_production_table")

    context = {'products': products, 'current_user': current_user, 'role_permission': role_permission}
    return render(request, 'company_admin/add_daily_production.html', context)


def edit_daily_production(request, id):
    current_user, role_permission = get_logged_in_user(request)
    if not current_user:
        return redirect('login')

    daily_production = get_object_or_404(DailyProduction, id=id)
    products = Product.objects.all()

    if request.method == 'POST':
        try:
            new_product_id = request.POST['product']
            new_stock_in = int(request.POST['stock_in'])
            new_batch_number = request.POST['batch_number']
            new_manufactured_date = request.POST['manufactured_date']
            new_expiry_date = request.POST['expiry_date']
            new_mrp = float(request.POST['mrp'])
            new_sale_price = float(request.POST['sale_price'])
            new_weight = float(request.POST['weight'])

            if DailyProduction.objects.filter(batch_number=new_batch_number).exclude(id=daily_production.id).exists():
                messages.error(request, "Batch number already exists.")
                return render(request, 'company_admin/add_daily_production.html', {
                    'edit_daily_production': daily_production,
                    'products': products,
                    'current_user': current_user,
                    'role_permission': role_permission
                })

            new_product = get_object_or_404(Product, id=new_product_id)

            # ✅ Adjust inventory: remove old stock_in first
            old_inventory, _ = Inventory.objects.get_or_create(product=daily_production.product)
            old_inventory.stock_in -= daily_production.stock_in
            old_inventory.update_stock()

            # ✅ Update production fields
            daily_production.product = new_product
            daily_production.stock_in = new_stock_in
            daily_production.batch_number = new_batch_number
            daily_production.sale_price = new_sale_price
            daily_production.mrp = new_mrp
            daily_production.manufactured_date = new_manufactured_date
            daily_production.expiry_date = new_expiry_date
            daily_production.weight_per_packet = new_weight
            daily_production.save()

            # ✅ Update new inventory with latest stock_in
            new_inventory, _ = Inventory.objects.get_or_create(product=new_product)
            new_inventory.stock_in += new_stock_in
            new_inventory.update_stock()

            messages.success(request, 'Production updated successfully.')
            return redirect('daily_production_table')

        except Exception as e:
            messages.error(request, f"Error updating production: {e}")

    context = {
        'current_user': current_user,
        'edit_daily_production': daily_production,
        'products': products,
        'role_permission': role_permission
    }
    return render(request, 'company_admin/add_daily_production.html', context)


def delete_daily_production(request, id):
    current_user, role_permission = get_logged_in_user(request)
    if not current_user:
        return redirect('login')

    daily_production = get_object_or_404(DailyProduction, id=id)

    try:
        # Update inventory before deleting
        inventory = Inventory.objects.get(product=daily_production.product)
        inventory.stock_in -= daily_production.stock_in
        inventory.update_stock()

        daily_production.delete()
        messages.success(request, 'Production deleted and inventory updated successfully.')
    except Exception as e:
        messages.error(request, f"Error deleting production: {e}")

    return redirect('daily_production_table')


def order_table(request):
    current_user, role_permission = get_logged_in_user(request)
    if not current_user:
        return redirect('login')

    if current_user.role.name.lower() == "admin":
        orders = Order.objects.all()
    else:
        orders = Order.objects.filter(created_by=current_user)

    context = {
        'orders': orders,
        'current_user': current_user,
        'role_permission': role_permission
    }
    return render(request, 'company_admin/order_table.html', context)


def safe_decimal(value, default=Decimal('0.00')):
    try:
        return Decimal(str(value).strip())
    except (InvalidOperation, ValueError, TypeError):
        return default


def get_customer_details(request, customer_id):
    try:
        customer = Customer.objects.get(id=customer_id)
        return JsonResponse({
            'discount': customer.discount,
            'shop_address': customer.shop_address_line1,
            'shop_city': customer.shop_city,
            'shop_district': customer.shop_district,
            'shop_state': customer.shop_state,
            'shop_pincode': customer.shop_pincode,
        })
    except Customer.DoesNotExist:
        return JsonResponse({
            'discount': 0,
            'shop_address': '',
            'shop_city': '',
            'shop_district':'',
            'shop_state': '',
            'shop_pincode': '',
        })
    
from django.db.models import Min

def product_batches(request, product_id):
    batches = (
        DailyProduction.objects.filter(product_id=product_id, stock_in__gt=0)
        .values("weight_per_packet")
        .annotate(first_batch_id=Min("id"))  
        .order_by("weight_per_packet")
    )
    return JsonResponse(list(batches), safe=False)    


def fifo_batch(request, product_id, weight):
    batches = (
        DailyProduction.objects.filter(product_id=product_id, weight_per_packet=weight, stock_in__gt=0)
        .order_by("manufactured_date", "id")  # FIFO order
        .values("id", "batch_number", "manufactured_date", "expiry_date",
                "sale_price", "mrp", "current_stock", "weight_per_packet")
    )
    if not batches:
        return JsonResponse({"error": "No stock available"}, status=404)

    
    total_qty = sum(b["current_stock"] for b in batches)
    first_batch = batches[0]

    return JsonResponse({
        "batches": list(batches),
        "total_quantity": total_qty,
        "weight_per_packet": first_batch["weight_per_packet"],
        "sale_price": float(first_batch["sale_price"]),
        "mrp": float(first_batch["mrp"]),
        "gstpercentage": DailyProduction.objects.filter(product_id=product_id).first().product.gstpercentage,
    })


def send_order_email(order):
    """
    Send confirmation email to customer and assigned salesman when an order is placed.
    """

    subject = f"Order Confirmation - {order.id}"

    # 🔹 Build items list
    order_items = OrderItem.objects.filter(order=order)
    items_list = "\n".join([f"{item.product.name} - {item.quantity} pcs" for item in order_items])

    # 🔹 Email body
    message = (
        f"Dear {order.customer.full_name},\n\n"
        f"Thank you for your order in SOUTH SUTRA! We're excited to let you know that we have successfully "
        f"received your order, and it is now being processed.\n\n"

        f"Order Details:\n\n"
        f"Order ID: {order.id}\n"
        f"Order Date: {order.created_at.strftime('%d-%m-%Y %H:%M') if hasattr(order, 'created_at') else 'N/A'}\n"
        f"Shipping Address: {order.customer.shop_address}\n"
        f"Billing Address: {order.customer.shop_address}\n\n"

        f"Items Ordered:\n\n"
        f"{items_list}\n\n"

        f"Total Amount: ₹{order.grand_total}\n\n"

        f"We will send you another email once your order has been shipped. "
        f"You can track your order status anytime by visiting our website.\n\n"

        f"If you have any questions or need assistance, feel free to reach out to us at "
        f"{settings.DEFAULT_SUPPORT_EMAIL if hasattr(settings, 'DEFAULT_SUPPORT_EMAIL') else 'support@southsutra.com'} "
        f"or {settings.DEFAULT_SUPPORT_PHONE if hasattr(settings, 'DEFAULT_SUPPORT_PHONE') else '+91-8971607888'}.\n\n"

        f"Thank you for shopping with us!\n\n"
        f"Best regards,\n"
        f"SOUTH SUTRA\n"
        f"{settings.COMPANY_CONTACT_INFO if hasattr(settings, 'COMPANY_CONTACT_INFO') else 'Bangalore, India'}\n"
        f"{settings.WEBSITE_URL if hasattr(settings, 'WEBSITE_URL') else 'https://southsutra.com'}"
    )

    # ✅ Emails
    customer_email = order.customer.email
    salesman_email = order.customer.user.email if order.customer.user else None

    recipient_list = [email for email in [customer_email, salesman_email] if email]

    if recipient_list:
        send_mail(
            subject,
            message,
            settings.EMAIL_HOST_USER,  # From email (set in settings.py)
            recipient_list,
            fail_silently=False,
        )

def check_salesman_checked_in(user, request):
    """
    Utility function to check if a salesman has an active check-in.
    Returns:
        - None if checked in
        - Redirect response if not checked in
    """
    if user.role.name.lower() == "salesman":
        active_visit = SalesmanVisit.objects.filter(salesman=user, is_active=True).last()
        if not active_visit:
            messages.warning(request, "You must check in before creating a sales order.")
            return redirect("checkin_checkout_list")
    return None

def add_order(request):
    current_user, role_permission = get_logged_in_user(request)
    if not current_user:
        return redirect('login')
    
    checkin_redirect = check_salesman_checked_in(current_user, request)
    if checkin_redirect:
        return checkin_redirect

    active_visit = SalesmanVisit.objects.filter(salesman=current_user, is_active=True).last()
    preselected_customer_id = active_visit.customer.id if active_visit and active_visit.customer else None    

    if request.method == 'POST':
        customer_id = request.POST.get('customer')
        items = request.POST.getlist('items[]')
        is_free_sample = request.POST.get('is_free_sample') or False

        customer = get_object_or_404(Customer, id=customer_id)
        user = get_object_or_404(User, username=current_user.username)

        # 🔹 Fetch order-level totals
        subtotal = safe_decimal(request.POST.get('subtotal', '0'))
        discount_amount = safe_decimal(request.POST.get('discount_amount', '0'))
        taxable_amount = safe_decimal(request.POST.get('taxable_amount', '0'))
        tax_amount = safe_decimal(request.POST.get('tax_amount', '0'))
        grand_total = safe_decimal(request.POST.get('grand_total', '0'))
        total_paid = safe_decimal(request.POST.get('amount_paid', '0'))

        order_type = request.POST.get('order_type')

        try:
            with transaction.atomic():
                # 1️⃣ Create the Order
                order = Order.objects.create(
                    customer=customer,
                    created_by=user,
                    subtotal=subtotal,
                    discount_amount=discount_amount,
                    taxable_amount=taxable_amount,
                    tax_amount=tax_amount,
                    grand_total=grand_total,
                    total_paid=total_paid if not is_free_sample else Decimal('0.00'),
                    balance_due=(grand_total - total_paid) if not is_free_sample else Decimal('0.00'),
                    payment_status='paid' if is_free_sample else 'pending',
                    delivery_status='processing',
                    is_free_sample=is_free_sample,
                    order_type=order_type,
                )

                # 2️⃣ Process each item (NO FIFO deduction)
                for item_data in items:
                    try:
                        product_id, weight, quantity, price, sub_total, discount_perc, discount_amt, taxable_amt, gst_perc, gst_amt, total = item_data.split(',')
                    except ValueError:
                        raise ValueError(f"Invalid item data: {item_data}")

                    product = get_object_or_404(Product, id=int(product_id))
                    quantity = int(quantity)

                    if is_free_sample:
                        price = sub_total = discount_perc = discount_amt = taxable_amt = gst_perc = gst_amt = total = Decimal('0.00')
                    else:
                        price = safe_decimal(price)
                        sub_total = safe_decimal(sub_total)
                        discount_perc = safe_decimal(discount_perc)
                        discount_amt = safe_decimal(discount_amt)
                        taxable_amt = safe_decimal(taxable_amt)
                        gst_perc = safe_decimal(gst_perc)
                        gst_amt = safe_decimal(gst_amt)
                        total = safe_decimal(total)

                    # ✅ Directly create OrderItem (no stock/batch updates)
                    OrderItem.objects.create(
                        order=order,
                        product=product,
                        weight=weight,
                        quantity=quantity,
                        price=price,
                        sub_total=sub_total,
                        discount_percentage=discount_perc,
                        discount_amount=discount_amt,
                        taxable_amount=taxable_amt,
                        gst_percentage=gst_perc,
                        gst_amount=gst_amt,
                        total=total
                    )

                # 3️⃣ Payment Transaction
                if not is_free_sample and total_paid > 0:
                    PaymentTransaction.objects.create(
                        order=order,
                        received_by=user,
                        amount_paid=total_paid,
                        payment_mode=request.POST.get('payment_mode', 'cash'),
                        remarks=request.POST.get('remarks', '')
                    )

                if not is_free_sample:
                    order.update_payment_status()
                
                send_order_email(order)
                messages.success(request, "Order created successfully.")
                return redirect('order_table')

        except Exception as e:
            messages.error(request, f"Error creating order: {e}")
            print(f"Error details: {e}")
            return redirect('add_order')

    # GET request
    products = Product.objects.all()

    if current_user.role.name.lower() == "admin":
        customers = Customer.objects.all()
    else:
        customers = Customer.objects.filter(user=current_user)

    return render(request, 'company_admin/add_order.html', {
        'products': products,
        'customers': customers,
        'current_user': current_user,
        'role_permission': role_permission,
        'preselected_customer_id': preselected_customer_id,
    })



def delete_order(request, order_id):
    order = get_object_or_404(Order, id=order_id)

    try:
        with transaction.atomic():
            # 1️⃣ Restore stock from order items
            # for item in order.items.all():
            #     # Restore stock to DailyProduction (FIFO batches not tracked here, but you can extend)
            #     inventory, _ = Inventory.objects.get_or_create(product=item.product)
            #     inventory.stock_out -= item.quantity
            #     inventory.update_stock()
            #
            # 2️⃣ Delete the order (cascades to OrderItems, Invoice, Payments)
            order.delete()

            messages.success(request, f"Order #{order_id} deleted successfully.")
    except Exception as e:
        messages.error(request, f"Error deleting order: {e}")

    return redirect('order_table')


def fifo_batch1(request, product_id, weight):
    # Fetch batches in FIFO order
    batches = DailyProduction.objects.filter(
        product_id=product_id,
        weight_per_packet=weight,
        current_stock__gt=0  # Only available stock
    ).order_by("manufactured_date", "id")

    if not batches.exists():
        return JsonResponse({"error": "No stock available"}, status=404)

    # Prepare batch info with available quantity
    batch_list = []
    total_qty = 0
    for b in batches:
        available_qty = b.current_stock  # stock_in - stock_out
        total_qty += available_qty
        batch_list.append({
            "id": b.id,
            "batch_number": b.batch_number,
            "manufactured_date": str(b.manufactured_date),
            "expiry_date": str(b.expiry_date),
            "sale_price": float(b.sale_price),
            "mrp": float(b.mrp),
            "available_qty": available_qty,
            "weight_per_packet": float(b.weight_per_packet),
        })

    # Take first batch for default selection
    first_batch = batch_list[0]

    return JsonResponse({
        "batches": batch_list,
        "total_quantity": total_qty,
        "weight_per_packet": first_batch["weight_per_packet"],
        "sale_price": first_batch["sale_price"],
        "mrp": first_batch["mrp"],
        "gstpercentage": DailyProduction.objects.filter(product_id=product_id).first().product.gstpercentage,
    })


@transaction.atomic
def generate_invoice(request, order_id):
    order = get_object_or_404(Order, id=order_id)

    # ✅ Create or fetch invoice
    invoice, created = Invoice.objects.get_or_create(
        order=order,
        defaults={'created_at': timezone.now()}
    )

    if created:
        invoice.invoice_number = f"INV{invoice.id:03d}-ORD{order.id}"
        invoice.save(update_fields=['invoice_number'])

        # ✅ FIFO deduction (increase stock_out, not decrease stock_in)
        for item in order.items.all():
            required_qty = item.quantity

            fifo_batches = (
                DailyProduction.objects.filter(
                    product=item.product,
                    weight_per_packet=item.weight,
                    current_stock__gt=0
                )
                .order_by("expiry_date", "id")  # FIFO order
            )

            for batch in fifo_batches:
                if required_qty <= 0:
                    break

                available = batch.current_stock
                deduction = min(required_qty, available)

                # Increase stock_out
                batch.stock_out += deduction
                batch.save(update_fields=["stock_out", "current_stock"])

                required_qty -= deduction

            if required_qty > 0:
                raise ValueError(
                    f"Not enough stock for product {item.product.name} "
                    f"(needed {item.quantity}, missing {required_qty})"
                )

    # ✅ Redirect to invoice/receipt page
    return redirect('view_receipt', order_id=order.id)



def pay_remaining_amount(request, order_id):
    current_user, role_permission = get_logged_in_user(request)
    if not current_user:
        return redirect('login')

    order = get_object_or_404(Order, id=order_id)
    user = get_object_or_404(User, username=current_user.username)

    if request.method == 'POST':
        try:
            amount_paid = Decimal(request.POST.get('amount_paid', '0'))
            payment_mode = request.POST.get('payment_mode', 'cash')
            remarks = request.POST.get('remarks', '')

            if amount_paid <= 0:
                messages.error(request, "Amount must be greater than 0.")
                return redirect('pay_remaining_amount', order_id=order_id)

            if amount_paid > order.balance_due:
                messages.error(request, f"Payment exceeds remaining balance (₹{order.balance_due}).")
                return redirect('pay_remaining_amount', order_id=order_id)

            PaymentTransaction.objects.create(
                order=order,
                received_by=user,
                amount_paid=amount_paid,
                payment_mode=payment_mode,
                remarks=remarks
            )

            # Update order payment status
            order.update_payment_status()

            messages.success(request, f"₹{amount_paid} received successfully.")
            return redirect('order_table')  # or any order detail view

        except Exception as e:
            messages.error(request, f"Error processing payment: {e}")
            return redirect('pay_remaining_amount', order_id=order_id)

    return render(request, 'company_admin/pay_order.html', {
        'order': order,
        'current_user': current_user,
        'role_permission':role_permission
    })


def view_customer(request, customer_id):
    current_user, role_permission= get_logged_in_user(request)
    if not current_user:
        return redirect('login')
    
    customer = get_object_or_404(Customer, id=customer_id)
    shop_images = customer.shop_images.all()
    branches = customer.branches.all()
    context = {
        'current_user': current_user,
        'role_permission': role_permission,
        'customer': customer,
        'shop_images': shop_images,
        'branches': branches
    }
    return render(request, 'accounts/view_customer.html', context)


def view_user(request, user_id):
    current_user, role_permission = get_logged_in_user(request)
    if not current_user:
        return redirect('login')
    
    user = get_object_or_404(User, id=user_id)
    context = {
        'user': user,
        'current_user': current_user,
        'role_permission': role_permission
    }
    return render(request, 'accounts/view_user.html', context)


def view_product(request, product_id):
    current_user, role_permission = get_logged_in_user(request)
    if not current_user:
        return redirect('login')
    
    product = get_object_or_404(Product, id=product_id)
    daily_productions = product.productions.all().order_by('-date')[:10]  # Last 10 production entries
    
    context = {
        'current_user': current_user,
        'product': product,
        'daily_productions': daily_productions,
        'role_permission': role_permission
    }
    return render(request, 'company_admin/view_product.html', context)


def view_receipt(request, order_id):
    current_user, role_permission = get_logged_in_user(request)
    if not current_user:
        return redirect('login')

    orders = get_object_or_404(Order, id=order_id)
    orderitems = OrderItem.objects.filter(order=order_id).select_related('product')

    amount_in_words = num2words(orders.grand_total, to='currency', lang='en').replace('euro', 'Rupees').replace('cents', 'Paise').title()

    invoice = Invoice.objects.get(order=orders)
    # Add computed GST fields to each item
    for item in orderitems:
        if orders.customer.shop_state == "Karnataka":
            item.cgst_percent = item.gst_percentage / 2
            item.sgst_percent = item.gst_percentage / 2
            item.cgst_amount = item.gst_amount / 2
            item.sgst_amount = item.gst_amount / 2
            item.igst_percent = None
            item.igst_amount = None
        else:
            item.cgst_percent = None
            item.sgst_percent = None
            item.cgst_amount = None
            item.sgst_amount = None
            item.igst_percent = item.gst_percentage
            item.igst_amount = item.gst_amount

    # Also handle totals
    if orders.customer.shop_state == "Karnataka":
        orders.cgst_total = orders.tax_amount / 2
        orders.sgst_total = orders.tax_amount / 2
        orders.igst_total = None
    else:
        orders.cgst_total = None
        orders.sgst_total = None
        orders.igst_total = orders.tax_amount

    context = {
        'current_user': current_user,
        'orders': orders,
        'orderitems': orderitems,
        'amount_in_words': amount_in_words,
        'role_permission': role_permission,
        'invoice': invoice
    }
    return render(request, 'company_admin/invoice.html', context)


def order_reports_view(request):
    current_user, role_permission = get_logged_in_user(request)
    if not current_user:
        return redirect('login')

    orders = Order.objects.select_related('customer').prefetch_related('items__product')
    salespersons = User.objects.filter(role__name__icontains="sales")
    customers = Customer.objects.all()
    unique_shops = Customer.objects.values('shop_name').distinct()

    cities = customers.values_list('shop_city', flat=True).distinct()

    total_orders = orders.count()
    paid_orders = orders.filter(payment_status='paid').count()
    pending_orders = orders.filter(payment_status='pending').count()
    partial_orders = orders.filter(payment_status='partial').count()

    start_id = request.GET.get('start_id')
    end_id = request.GET.get('end_id')
    if start_id and end_id:
        orders = orders.filter(id__gte=start_id, id__lte=end_id)

    order_rows = []
    for order in orders:
        order_rows.append({
        'salesman': order.customer.user.username,
        'order_date': order.order_date,
        'order_id': order.id,
        'is_free_sample':order.is_free_sample,
        'customer_name': order.customer.full_name,
        'customer_phone': order.customer.phone_number,
        'shop_name': order.customer.shop_name,
        'shop_city': order.customer.shop_city,
        'shop_type': order.customer.shop_type,
        'delivery_status': order.delivery_status,
        'payment_status': order.payment_status,
        'total_amount': order.grand_total,
        # convert items to JSON-safe string
        'items_json': json.dumps([
            {
                'product': item.product.name,
                'weight': float(item.weight),
                'quantity': item.quantity,
                'price': float(item.price),
                'sub_total': float(item.sub_total),
                'discount_percentage':float(item.discount_percentage),
                'discount_amount':float(item.discount_amount),
                'taxable_amount': float(item.taxable_amount),
                'gst_percentage': float(item.gst_percentage),
                'gst_amount': float(item.gst_amount),
                'total': float(item.total),
            }
            for item in order.items.all()
        ])
    })


    context = {
        'current_user': current_user,
        'order_rows': order_rows,
        'total_orders': total_orders,
        'paid_orders': paid_orders,
        'pending_orders': pending_orders,
        'partial_orders': partial_orders,
        'role_permission': role_permission,
        "salespersons": salespersons,
        "customers": customers,
        "cities": cities, 
        'unique_shops': unique_shops,
    }
    return render(request, 'company_admin/order_reports.html', context)


def customer_reports(request):
    current_user, role_permission = get_logged_in_user(request)
    if not current_user:
        return redirect('login')

    customers = Customer.objects.all()

    # 🔹 Summary Cards
    total_customers = customers.count()
    active_customers = customers.filter(is_active=True).count()
    total_orders = Order.objects.count()
    total_revenue = Order.objects.aggregate(total=Sum('grand_total'))['total'] or 0
    pending_balance = Order.objects.aggregate(balance=Sum('balance_due'))['balance'] or 0

    # 🔹 Top Customers by Revenue (include order count)
    top_customers = (
        customers.annotate(
            total_revenue=Sum('orders__grand_total'),
            total_orders=Count('orders')
        )
        .order_by('-total_revenue')[:5]
    )
    top_customers_list = [
        {
            "name": c.full_name,
            "revenue": float(c.total_revenue or 0),
            "orders": c.total_orders,
            "shop_name": c.shop_name,
            "shop_city":c.shop_city
        }
        for c in top_customers
    ]

    context = {
        'current_user': current_user,
        'role_permission': role_permission,
        'customers': customers,

        # Summary
        'total_customers': total_customers,
        'active_customers': active_customers,
        'total_orders': total_orders,
        'total_revenue': total_revenue,
        'pending_balance': pending_balance,

        # Top Customers
        'top_customers_list': top_customers_list,
    }

    return render(request, 'company_admin/customer_reports.html', context)


def customer_report_view(request, customer_id):
    current_user, role_permission = get_logged_in_user(request)
    if not current_user:
        return redirect('login')

    # ✅ Get customer
    customer = get_object_or_404(Customer, id=customer_id)

    # ✅ Orders of this customer
    orders = Order.objects.filter(customer=customer)

    # ✅ Order Summary
    order_summary = orders.aggregate(
        total_orders=Count("id"),
        total_sales=Sum("grand_total"),
        total_paid=Sum("total_paid"),
        total_balance=Sum("balance_due"),
    )

    # ✅ Product-wise sales
    product_sales = (
        OrderItem.objects.filter(order__customer=customer)
        .values("product__id", "product__name")
        .annotate(total_qty=Sum("quantity"), total_sales=Sum("total"))
        .order_by("-total_sales")
    )

    # ✅ Prepare chart data
    product_labels = [p["product__name"] for p in product_sales]
    product_values = [float(p["total_sales"]) for p in product_sales]
    product_qty = [int(p["total_qty"]) for p in product_sales]

    context = {
        "current_user": current_user,
        "role_permission": role_permission,
        "customer": customer,
        "orders": orders,
        "order_summary": order_summary,
        "product_sales": list(product_sales),
        "product_labels": json.dumps(product_labels),
        "product_values": json.dumps(product_values),
        "product_qty":json.dumps(product_qty),
    }
    return render(request, "company_admin/customer_report_view.html", context)


def salesman_reports(request):
    current_user, role_permission = get_logged_in_user(request)
    if not current_user:
        return redirect('login')

    # 🔹 All salesmen
    salesmen = User.objects.filter(role__name__icontains="Salesman")

    # 🔹 Summary cards
    total_salesman = salesmen.count()
    active_salesman = salesmen.filter(is_active=True).count()
    total_revenue = Order.objects.aggregate(total=Sum('grand_total'))['total'] or 0
    pending_balance = Order.objects.aggregate(balance=Sum('balance_due'))['balance'] or 0

    # 🔹 Top 5 Salesmen by Revenue (with order count)  
    top_salesmen = (
        salesmen.annotate(
            revenue=Sum('orders_created__grand_total'),
            orders=Count('orders_created')
        ).order_by('-revenue')[:5]
    )

    top_salesman_list = [

        {
            'first_name': s.first_name,
            'last_name': s.last_name,
            'revenue': float(s.revenue or 0),
            'orders': s.orders
        } for s in top_salesmen
    ]

    context = {
        'current_user': current_user,
        'role_permission': role_permission,
        'salesmen': salesmen,
        'total_salesman': total_salesman,
        'active_salesman': active_salesman,
        'total_revenue': total_revenue,
        'pending_balance': pending_balance,
        'top_salesman_list': top_salesman_list,
    }

    return render(request, 'company_admin/salesman_reports.html', context)


import json
def salesman_report_view(request, salesman_id):
    current_user, role_permission = get_logged_in_user(request)
    if not current_user:
        return redirect('login')

    # ✅ Get salesman
    salesman = get_object_or_404(User, id=salesman_id, role__name="Salesman")

    # ✅ Customers handled by this salesman
    customers = Customer.objects.filter(user=salesman)
    customer_count = customers.count()

    # ✅ Orders under this salesman’s customers
    orders = Order.objects.filter(customer__in=customers)

    # ✅ Order Summary
    order_summary = orders.aggregate(
        total_orders=Count("id"),
        total_sales=Sum("grand_total"),
        total_paid=Sum("total_paid"),
        total_balance=Sum("balance_due"),
    )

    # ✅ Product-wise Sales
    product_sales = (
        OrderItem.objects.filter(order__in=orders)
        .values("product__id", "product__name")
        .annotate(total_qty=Sum("quantity"), total_sales=Sum("total"))
        .order_by("-total_sales")
    )

    # ✅ Prepare chart data
    product_labels = [p["product__name"] for p in product_sales]
    product_values = [float(p["total_sales"]) for p in product_sales]
    product_qty = [int(p["total_qty"]) for p in product_sales]
    context = {
        "current_user": current_user,
        "role_permission": role_permission,
        "salesman": salesman,
        "customers": customers,
        "customer_count": customer_count,
        "orders": orders,
        "order_summary": order_summary,
        "product_sales": list(product_sales),
        "product_labels": json.dumps(product_labels),
        "product_values": json.dumps(product_values),
        "product_qty":json.dumps(product_qty),
    }
    return render(request, "company_admin/salesman_report_view.html", context)



# your existing session helper
def get_address_from_latlng(lat, lng):
    """Reverse geocode using Google Maps API"""
    try:
        api_key = settings.GOOGLE_MAPS_API_KEY
        url = f"https://maps.googleapis.com/maps/api/geocode/json?latlng={lat},{lng}&key={api_key}"
        response = requests.get(url)
        data = response.json()

        if data.get("status") == "OK" and data.get("results"):
            return data["results"][0]["formatted_address"]
        return None
    except Exception as e:
        print("❌ Geocoding error:", e)
        return None


def checkin_checkout_list(request):
    current_user, role_permission = get_logged_in_user(request)
    if not current_user:
        return redirect("login")

    if request.method == "POST":
        action = request.POST.get("action")

        if action == "checkin":
            customer_id = request.POST.get("customer")
            lat = request.POST.get("latitude")
            lng = request.POST.get("longitude")

            if not lat or not lng:
                messages.error(request, "Location is required for check-in.")
                return redirect("checkin_checkout_list")

            try:
                lat = float(lat)
                lng = float(lng)
            except ValueError:
                messages.error(request, "Invalid location values received.")
                return redirect("checkin_checkout_list")

            customer = Customer.objects.filter(id=customer_id).first()
            address = get_address_from_latlng(lat, lng)

            # End any previous active visit
            SalesmanVisit.objects.filter(salesman=current_user, is_active=True).update(
                is_active=False, check_out_time=timezone.now()
            )

            # Create new visit
            SalesmanVisit.objects.create(
                salesman=current_user,
                customer=customer,
                latitude=lat,
                longitude=lng,
                location_address=address,
                check_in_time=timezone.now(),
                is_active=True,
            )

            messages.success(request, "✅ Check-in successful!")
            # 🔹 redirect to add_order with customer preselected
            return redirect("add_order")  # <-- change here

        elif action == "checkout":
            visit = SalesmanVisit.objects.filter(salesman=current_user, is_active=True).last()
            if visit:
                visit.check_out_time = timezone.now()
                visit.visit_description = request.POST.get("visit_description", "")
                visit.is_active = False
                visit.save()
                messages.success(request, "✅ Checked out successfully!")
            else:
                messages.error(request, "❌ No active visit found to checkout.")

            return redirect("dashboard")  # <-- redirect to dashboard after checkout

    # GET request
    active_visit = SalesmanVisit.objects.filter(salesman=current_user, is_active=True).last()
    visits = SalesmanVisit.objects.filter(salesman=current_user).order_by("-check_in_time")
    customers = Customer.objects.filter(user=current_user)

    return render(request, "accounts/checkin_checkout.html", {
        "visits": visits,
        "customers": customers,
        "current_user": current_user,
        "role_permission": role_permission,
        "is_active": bool(active_visit),
    })


def salesman_visit_list(request): 
    current_user, role_permission = get_logged_in_user(request)
    if not current_user:
        return redirect("login")

    visits = SalesmanVisit.objects.all()
    salesmen = User.objects.filter(role__name__icontains="Salesman")
    customers = Customer.objects.all() 

    context = {
        "current_user": current_user,
        "role_permission": role_permission,
        "visits": visits,
        "salesmen":salesmen,
        "customers":customers
    }

    return render(request, "accounts/salesman_active_check.html", context)









