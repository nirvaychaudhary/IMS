from django.apps import AppConfig
from django.db.models.signals import post_migrate


class AccountsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'accounts'

    def ready(self):
        import accounts.signals #--form normal signal use
        
        # ---------------using this way assists to create group directly without error---------------
        from .signals import populate_models
        post_migrate.connect(populate_models, sender=self)



