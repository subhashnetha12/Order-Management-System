import os
from django.db import models
from django.contrib.auth.hashers import make_password, check_password
from django.utils import timezone

from django.db import transaction
from django.core.exceptions import ValidationError

class Role(models.Model):
    name = models.CharField(max_length=255, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs) 

        role_permissions, _ = RolePermissions.objects.get_or_create(role=self)

        if self.name.lower() == "admin":
            for field in RolePermissions._meta.fields:
                if isinstance(field, models.BooleanField):
                    setattr(role_permissions, field.name, True)
        else:
            role_permissions.dashboard_v = True
            role_permissions.accounts_v = True
            role_permissions.customer_v = True
            role_permissions.customer_a = True
            role_permissions.orders_v = True
            role_permissions.orders_a = True

        role_permissions.save()

    def __str__(self):
        return f"{self.name}"


class RolePermissions(models.Model):  
    role = models.ForeignKey(Role, on_delete=models.CASCADE, related_name='permissions')

    dashboard_v = models.BooleanField(default=False)

    accounts_v = models.BooleanField(default=False)
    accounts_a = models.BooleanField(default=False)
    accounts_e = models.BooleanField(default=False)
    accounts_d = models.BooleanField(default=False)

    roles_v = models.BooleanField(default=False)
    roles_a = models.BooleanField(default=False)
    roles_e = models.BooleanField(default=False)
    roles_d = models.BooleanField(default=False)
    
    users_v = models.BooleanField(default=False)
    users_a = models.BooleanField(default=False)
    users_e = models.BooleanField(default=False)
    users_d = models.BooleanField(default=False)

    customer_v = models.BooleanField(default=False)
    customer_a = models.BooleanField(default=False)
    customer_e = models.BooleanField(default=False)
    customer_d = models.BooleanField(default=False)

    products_v = models.BooleanField(default=False)
    products_a = models.BooleanField(default=False)
    products_e = models.BooleanField(default=False)
    products_d = models.BooleanField(default=False)

    category_v = models.BooleanField(default=False)
    category_a = models.BooleanField(default=False)
    category_e = models.BooleanField(default=False)
    category_d = models.BooleanField(default=False)

    all_products_v = models.BooleanField(default=False)
    all_products_a = models.BooleanField(default=False)
    all_products_e = models.BooleanField(default=False)
    all_products_d = models.BooleanField(default=False)

    daily_production_v = models.BooleanField(default=False)
    daily_production_a = models.BooleanField(default=False)
    daily_production_e = models.BooleanField(default=False)
    daily_production_d = models.BooleanField(default=False)

    inventory_v = models.BooleanField(default=False)
    inventory_a = models.BooleanField(default=False)
    inventory_e = models.BooleanField(default=False)
    inventory_d = models.BooleanField(default=False)

    orders_v = models.BooleanField(default=False)
    orders_a = models.BooleanField(default=False)
    orders_e = models.BooleanField(default=False)
    orders_d = models.BooleanField(default=False)

    reports_v = models.BooleanField(default=False)
    s_reports_v = models.BooleanField(default=False)
    c_reports_v = models.BooleanField(default=False)

    def __str__(self):
        return f"Permissions for {self.role.name}"
    

class User(models.Model):
    role = models.ForeignKey(Role,on_delete=models.SET_NULL, null=True, related_name="role")
    username = models.CharField(max_length=255, unique=True)
    password = models.CharField(max_length=255)
    first_name = models.CharField(max_length=255)
    last_name = models.CharField(max_length=255)
    email = models.EmailField(unique=True)
    phone_number = models.CharField(max_length=15, unique=True)
    address = models.TextField()
    city = models.CharField(max_length=255)
    state = models.CharField(max_length=255)
    pincode = models.CharField(max_length=10)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    profile_picture = models.ImageField(upload_to='profile_pictures/', null=True, blank=True)

    def __str__(self):
        return f"{self.username} - {self.role}"

    def save(self, *args, **kwargs):
        if self.password and not self.password.startswith('pbkdf2_'):
            self.password = make_password(self.password)
        super().save(*args, **kwargs)

    def check_password(self, raw_password):
        return check_password(raw_password, self.password)
    

    

class Customer(models.Model):
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='customers')
    customer_name = models.CharField(max_length=255,null=True,blank=True)
    full_name = models.CharField(max_length=255,null=True,blank=True)
    email = models.EmailField(unique=True, null=True,blank=True)
    phone_number = models.CharField(unique=True, max_length=50, null=True,blank=True)
    shop_type = models.CharField(
        max_length=50,
        choices=[
            ('NMT', 'National Modern Trade'),
            ('MT', 'Modern Trade'),
            ('SMT', 'Semi Modern Trade'),
            ('SPECIAL', 'Speciality Store'),
            ('GT', 'General Trade'),
        ],
        blank=True, null=True
    )
    gst_number = models.CharField(max_length=100,null=True,blank=True)
    shop_name = models.CharField(max_length=255)
    shop_address = models.TextField()
    shop_city = models.CharField(max_length=255)
    shop_district = models.CharField(max_length=255)
    shop_pincode = models.CharField(max_length=50)
    shop_state = models.CharField(max_length=255)
    discount = models.DecimalField(max_digits=5, decimal_places=2, default=0.00)
    is_active = models.BooleanField(default=True)
    is_new = models.BooleanField(default=True)
    is_gst_registered = models.BooleanField(default=False, help_text="Is the customer GST registered?")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    weekday_footfall = models.PositiveIntegerField(help_text="Average number of visitors during weekdays",null=True,blank=True)
    weekend_footfall = models.PositiveIntegerField(help_text="Average number of visitors during weekends",null=True,blank=True)
    credit_period = models.CharField(max_length=100,help_text="Credit period in No of Days", null=True, blank=True)
    nature_of_business = models.TextField(blank=True, null=True)  
    latitude = models.CharField(max_length=50, blank=True, null=True)
    longitude = models.CharField(max_length=50, blank=True, null=True)

    def __str__(self):
        return f"{self.shop_name} ({self.full_name})"
    


def shop_image_upload_path(instance, filename):
    return os.path.join(str(instance.customer.id),  filename)

class CustomerShopImage(models.Model):
    customer = models.ForeignKey(Customer, on_delete=models.CASCADE, related_name='shop_images')
    image = models.ImageField(upload_to=shop_image_upload_path)
    description = models.CharField(max_length=255, blank=True, null=True)  # optional: e.g., "Front view", etc.

    def __str__(self):
        return f"{self.customer.full_name} ({self.customer.shop_name})"
    

class Branch(models.Model):
    customer = models.ForeignKey("Customer", on_delete=models.CASCADE, related_name="branches")  # ✅ link to Customer
    gstin = models.CharField(max_length=15, db_index=True)   
    customer_name = models.CharField(max_length=255)         
    business_name = models.CharField(max_length=255, blank=True, null=True)  
    address_line1 = models.TextField()
    address_line2 = models.TextField(blank=True, null=True)
    city = models.CharField(max_length=255, blank=True, null=True)
    district = models.CharField(max_length=255, blank=True, null=True)
    pincode = models.CharField(max_length=10, blank=True, null=True)
    state = models.CharField(max_length=255, blank=True, null=True)
    is_head_office = models.BooleanField(default=False)      
    nature_of_business = models.TextField(blank=True, null=True)  
    latitude = models.CharField(max_length=50, blank=True, null=True)
    longitude = models.CharField(max_length=50, blank=True, null=True)

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.business_name or self.customer_name} - {'Head Office' if self.is_head_office else 'Branch'}"


class Category(models.Model):
    name = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    def __str__(self):
        return f"{self.name}"

class Product(models.Model):
    name = models.CharField(max_length=255)
    category = models.ForeignKey(Category, on_delete=models.CASCADE)
    unit = models.CharField(max_length=50,choices=[('packets', 'Packet')],default='packets')
    description = models.TextField(blank=True)
    hsn_code = models.CharField(max_length=20)
    gstpercentage = models.DecimalField(max_digits=5, decimal_places=2)

    def __str__(self):
        return self.name 


class DailyProduction(models.Model):
    product = models.ForeignKey(Product, on_delete=models.CASCADE, related_name='productions')
    date = models.DateTimeField(auto_now_add=True)
    stock_in = models.PositiveIntegerField(default=0)
    stock_out = models.PositiveIntegerField(default=0)
    current_stock = models.IntegerField(default=0)
    weight_per_packet = models.DecimalField(max_digits=6, decimal_places=2, help_text="Weight in grams")
    batch_number = models.CharField(max_length=100)
    manufactured_date = models.DateField()
    expiry_date = models.DateField()
    sale_price = models.DecimalField(max_digits=10, decimal_places=2)
    mrp = models.DecimalField(max_digits=10, decimal_places=2)

    def save(self, *args, **kwargs):
        # Always calculate current_stock before saving
        self.current_stock = self.stock_in - self.stock_out

        if not self.pk:  # Only check uniqueness on create
            exists = DailyProduction.objects.filter(
                product=self.product,
                weight_per_packet=self.weight_per_packet,
                manufactured_date=self.manufactured_date
            ).exists()
            if exists:
                raise ValidationError(
                    f"Daily production already exists for {self.product.name}, "
                    f"{self.weight_per_packet}g on {self.manufactured_date}"
                )

        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.product.name} - {self.weight_per_packet}g - {self.manufactured_date}"

class Inventory(models.Model):
    product = models.ForeignKey(Product, on_delete=models.CASCADE, related_name='inventories')
    opening_stock = models.PositiveIntegerField(default=0)
    stock_in = models.PositiveIntegerField(default=0)
    stock_out = models.PositiveIntegerField(default=0)
    current_stock = models.IntegerField(default=0)
    last_updated = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.product.name} - {self.current_stock}"

    def update_stock(self):
        self.current_stock = self.opening_stock + self.stock_in - self.stock_out
        self.save()




class Ledger(models.Model):
    customer = models.ForeignKey('Customer', on_delete=models.CASCADE, related_name='ledger_entries')
    date = models.DateTimeField(auto_now_add=True)
    description = models.CharField(max_length=255)
    debit = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    credit = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    balance = models.DecimalField(max_digits=10, decimal_places=2, editable=False, default=0.00)

    class Meta:
        ordering = ['date']

    def __str__(self):
        return f"{self.customer.full_name} - {self.date.date()}"

    def save(self, *args, **kwargs):
        last_entry = Ledger.objects.filter(customer=self.customer).order_by('-date').first()
        previous_balance = last_entry.balance if last_entry else 0
        self.balance = previous_balance + self.credit - self.debit
        super().save(*args, **kwargs)


class Order(models.Model):
    ORDER_TYPE_CHOICES = [
        ('telephone', 'Telephone'),
        ('location', 'Location'),
        ('email', 'Email'),
    ]

    PAYMENT_STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('partial', 'Partial'),
        ('paid', 'Paid'),
    ]

    DELIVERY_STATUS_CHOICES = [
        ('processing', 'Processing'),
        ('shipped', 'Shipped'),
        ('delivered', 'Delivered'),
    ]

    customer = models.ForeignKey('Customer', on_delete=models.CASCADE, related_name='orders')
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='orders_created')
    order_date = models.DateTimeField(auto_now_add=True)
    is_free_sample = models.BooleanField(default=False)

    order_type = models.CharField(max_length=20, choices=ORDER_TYPE_CHOICES, default='telephone')

    # 🔹 Frontend terminology fields
    subtotal = models.DecimalField(max_digits=12, decimal_places=2, default=0.00)
    discount_amount = models.DecimalField(max_digits=12, decimal_places=2, default=0.00)
    taxable_amount = models.DecimalField(max_digits=12, decimal_places=2, default=0.00)
    tax_amount = models.DecimalField(max_digits=12, decimal_places=2, default=0.00)
    grand_total = models.DecimalField(max_digits=12, decimal_places=2, default=0.00)

    total_paid = models.DecimalField(max_digits=12, decimal_places=2, default=0.00)
    balance_due = models.DecimalField(max_digits=12, decimal_places=2, default=0.00)

    payment_status = models.CharField(max_length=50, choices=PAYMENT_STATUS_CHOICES, default='pending')
    delivery_status = models.CharField(max_length=50, choices=DELIVERY_STATUS_CHOICES, default='processing')

    def update_payment_status(self):
        self.total_paid = sum(t.amount_paid for t in self.transactions.all())
        self.balance_due = self.grand_total - self.total_paid

        if self.total_paid == 0:
            self.payment_status = 'pending'
        elif self.total_paid < self.grand_total:
            self.payment_status = 'partial'
        else:
            self.payment_status = 'paid'

        self.save(update_fields=['total_paid', 'balance_due', 'payment_status'])

    def __str__(self):
        return f"Order #{self.id} - {self.customer.shop_name}"




class OrderItem(models.Model):
    order = models.ForeignKey(Order, on_delete=models.CASCADE, related_name='items')
    product = models.ForeignKey('Product', on_delete=models.CASCADE)
    weight = models.DecimalField(max_digits=12, decimal_places=2)
    quantity = models.PositiveIntegerField()
    price = models.DecimalField(max_digits=12, decimal_places=2)
    sub_total = models.DecimalField(max_digits=12, decimal_places=2)
    discount_percentage = models.DecimalField(max_digits=5, decimal_places=2, default=0.00)
    discount_amount = models.DecimalField(max_digits=12, decimal_places=2, default=0.00)
    taxable_amount = models.DecimalField(max_digits=12, decimal_places=2)
    gst_percentage = models.DecimalField(max_digits=5, decimal_places=2, default=0.00)
    gst_amount = models.DecimalField(max_digits=12, decimal_places=2)
    total = models.DecimalField(max_digits=12, decimal_places=2)





class VoucherNumber(models.Model):
    name = models.CharField(max_length=100, unique=True)  # e.g., "Payment Voucher"
    prefix = models.CharField(max_length=10)              # e.g., "PAY"
    start_from = models.PositiveIntegerField(default=1)
    current_number = models.PositiveIntegerField(default=0)  # Auto-incremented

    def get_next_voucher(self):
        self.current_number += 1
        self.save(update_fields=['current_number'])
        return f"{self.prefix}{str(self.current_number).zfill(4)}"  # e.g., PAY0001

    def __str__(self):
        return f"{self.name} ({self.prefix})"

class PaymentTransaction(models.Model):
    order = models.ForeignKey(Order, on_delete=models.CASCADE, related_name='transactions')
    received_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='received_payments')
    payment_date = models.DateTimeField(auto_now_add=True)
    amount_paid = models.DecimalField(max_digits=12, decimal_places=2)
    payment_mode = models.CharField(
        max_length=50,
        choices=[
            ('cash', 'Cash'),
            ('upi', 'UPI'),
            ('bank_transfer', 'Bank Transfer'),
            ('cheque', 'Cheque'),
            ('other', 'Other')
        ]
    )
    remarks = models.TextField(blank=True, null=True)

    def __str__(self):
        return f"Payment {self.id} - ₹{self.amount_paid}"
    

class Invoice(models.Model):
    order = models.ForeignKey('Order', on_delete=models.CASCADE, related_name='invoices')
    invoice_number = models.CharField(max_length=50, unique=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        if not self.invoice_number:
            super().save(*args, **kwargs)  # Save first to get ID
            self.invoice_number = f"INV{self.id:03d}-ORD{self.order.id}"
            return super().save(update_fields=['invoice_number'])
        return super().save(*args, **kwargs)

    def __str__(self):
        return f"Invoice {self.invoice_number}"


from django.db import models
from django.utils import timezone
from datetime import timedelta

class Attendance(models.Model):
    user = models.ForeignKey("User", on_delete=models.CASCADE, related_name="attendances")
    check_in = models.DateTimeField(null=True, blank=True)
    check_out = models.DateTimeField(null=True, blank=True)
    date = models.DateField(default=timezone.now)
    working_hours = models.DurationField(null=True, blank=True)  # store time difference

    def save(self, *args, **kwargs):
        # ✅ Auto-calculate working hours if check_out exists
        if self.check_in and self.check_out:
            self.working_hours = self.check_out - self.check_in
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.user.username} - {self.date} ({self.working_hours or 'Not calculated'})"

from django.db import models
from django.utils import timezone

class GspToken(models.Model):
    access_token = models.TextField()
    token_type = models.CharField(max_length=30, default="Bearer")
    expires_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    gspappid = models.CharField(max_length=100)
    gspappsecret = models.CharField(max_length=100)

    class Meta:
        ordering = ["-created_at"]  # always latest first

    @property
    def is_expired(self) -> bool:
        return timezone.now() >= self.expires_at



class SalesmanVisit(models.Model):
    salesman = models.ForeignKey(User, on_delete=models.CASCADE)
    customer = models.ForeignKey(Customer, on_delete=models.CASCADE, blank=True, null=True)

    check_in_time = models.DateTimeField(default=timezone.now)
    check_out_time = models.DateTimeField(blank=True, null=True)

    latitude = models.DecimalField(max_digits=9, decimal_places=6, blank=True, null=True)
    longitude = models.DecimalField(max_digits=9, decimal_places=6, blank=True, null=True)
    location_address = models.CharField(max_length=255, blank=True, null=True)
    
    visit_description = models.TextField(blank=True, null=True)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return f"{self.salesman.username} - {self.customer} ({self.check_in_time})"