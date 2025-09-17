from django.apps import AppConfig
from django.apps import AppConfig
import sys
import os


# class App1Config(AppConfig):
#     default_auto_field = 'django.db.models.BigAutoField'
#     name = 'App1'


class YourAppConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'App1'

    # def ready(self):
    #     from .thread_customer import start_customer_thread
    #     start_customer_thread()

    
    # apps.py
    def ready(self):
        #if 'runserver' in sys.argv:
        if os.environ.get('RUN_MAIN') == 'true':
            print("🔥 Starting meeting reminder thread")
            from .thread_customer import start_customer_thread
            start_customer_thread()