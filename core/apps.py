import os

from django.apps import AppConfig


class CoreConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'core'

    def ready(self):
        from core.runtime import initialize

        initialize(start_monitoring=os.getenv('START_MONITORING') == '1')
