from django import views
from django.urls import path
from .views import *
from .gstapi import *

urlpatterns = [
    path('',login,name='login'),
    path('logout/',logout,name="logout"),
    path('forgot-password/', forgot_password, name='forgot_password'),
    path('verify-otp/', verify_otp, name='verify_otp'),
    path('resend-otp/', resend_otp, name='resend_otp'),
    path('reset-password/', reset_password, name='reset_password'),
    path('attendance/',attendance,name='attendance'),
   
    # admin
    path('dashboard/',dashboard,name='dashboard'),
    path('profile/',profile,name='profile'),

    path('role/table/', role_table, name='role_table'),
    path('add/role/', add_role, name='add_role'),
    path('role/edit/<int:id>/', edit_role, name='edit_role'),
    path('role/delete/<int:id>/', delete_role, name='delete_role'),
    path('role_permissions/<int:role_id>/', role_permissions, name='role_permissions'),

    path('user/table/', user_table, name='user_table'),
    path('add/user/', add_user, name='add_user'),
    path('user/edit/<int:id>/', edit_user, name='edit_user'),
    path('view/user/<int:user_id>/', view_user, name='view_user'),
    path('user/delete/<int:id>/', delete_user, name='delete_user'),
    
    path('customers/', customer_table, name='customer_table'),
    path('add/customer/', add_customer, name='add_customer'),
    path('customer/view/<int:customer_id>/', view_customer, name='view_customer'),
    
    path('customer/edit/<int:id>/', edit_customer, name='edit_customer'),
    path('customer/delete/<int:id>/', delete_customer, name='delete_customer'),

    path('inventory/', inventory_table, name='inventory_table'),
    
    path('products/', product_table, name='product_table'),
    path('add/product/', add_product, name='add_product'),
    path('product/edit/<int:id>/', edit_product, name='edit_product'),
    path('product/view/<int:product_id>/', view_product, name='view_product'),
    path('product/delete/<int:id>/', delete_product, name='delete_product'),

    path('categories/', category_table, name='category_table'),
    path('add/category/', add_category, name='add_category'),
    path('edit/category/<int:id>/', edit_category, name='edit_category'),
    path('delete/category/<int:id>/', delete_category, name='delete_category'),

    
    path('daily/productions/', daily_production_table, name='daily_production_table'),
    path('add/daily-production/', add_daily_production, name='add_daily_production'),
    path('production/edit/<int:id>/', edit_daily_production, name='edit_daily_production'),
    path('production/delete/<int:id>/', delete_daily_production, name='delete_daily_production'),

    path('order/', order_table, name='order_table'),
    path('add/order/', add_order, name='add_order'),
    path('generate_invoice/<int:order_id>/', generate_invoice, name='generate_invoice'),
    path('receipt/<int:order_id>/', view_receipt, name='view_receipt'),
    path('orders/<int:order_id>/pay/', pay_remaining_amount, name='pay_remaining_amount'),
    path('orders/delete/<int:order_id>/', delete_order, name='delete_order'),



    path("product-batches/<int:product_id>/", product_batches, name="product_batches"),
    path("fifo-batch/<int:product_id>/<str:weight>/", fifo_batch, name="fifo_batch"),



    path('get-customer-details/<int:customer_id>/', get_customer_details, name='get_customer_details'),

    path("checkin-checkout/", checkin_checkout_list, name="checkin_checkout_list"),
    path("salesman/visits/", salesman_visit_list, name="salesman_visit_list"),

    
    #salesperson
    path('gstin-details/', gstin_details, name='gstin_details'),

    path('reports/orders/', order_reports_view, name='order_reports'),
    path('reports/customers/', customer_reports , name='customer_reports'),
    path("customer/<int:customer_id>/report/", customer_report_view, name="customer_report"),
    path('reports/salespersons/', salesman_reports, name='salesman_reports'),
    path("salesman/<int:salesman_id>/report/", salesman_report_view, name="salesman_report"),

]