# validators.py in your Django app

from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _

class CustomPasswordValidator:
    def validate(self, password, user=None):
        conditions = [
            any(char.isdigit() for char in password),
            any(char.islower() for char in password),
            any(char.isupper() for char in password),
            any(char in "!@#$%^&*()_+-=[]{}|;':,.<>?/" for char in password)
        ]

        if not all(conditions):
            raise ValidationError(
                _("Password must include at least one lowercase letter, one uppercase letter, one digit, and one symbol."),
                code='password_complexity'
            )

    def get_help_text(self):
        return _(
            "Your password must contain at least one lowercase letter, one uppercase letter, one digit, and one symbol."
        )
