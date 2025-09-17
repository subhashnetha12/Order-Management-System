import threading
import time
from datetime import date, timedelta
from django.utils import timezone
from .models import Customer


def update_is_new_status():
    while True:
        try:
            today = timezone.now()
            customers = Customer.objects.filter(is_new=True)

            for customer in customers:
                if customer.created_at + timedelta(days=30) <= today:
                # ✅ For testing: change is_new to False after 10 seconds
                # if customer.created_at + timedelta(seconds=10) <= today:
                    customer.is_new = False
                    customer.save(update_fields=['is_new'])
                    print(f"[{today.date()}] Customer {customer.id} marked as not new.")

        except Exception as e:
            print(f"[{date.today()}] Error in update_is_new_status: {e}")

        time.sleep(86400)  # Sleep for 24 hours
        # time.sleep(5)  # For testing every 10 seconds


def start_customer_thread():
    print("Customer is_new status update thread starting...")
    thread = threading.Thread(target=update_is_new_status)
    thread.daemon = True  # Daemon thread will close when main thread exits
    thread.start()
