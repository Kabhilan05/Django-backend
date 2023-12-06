from django.db import models
from django.contrib.auth.models import AbstractUser
# Create your models here.


class CustomUser(AbstractUser):
    dob = models.DateField(blank=True,null=True)

    def __str__(self):
        return self.email