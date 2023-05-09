from django.db import models
from django.contrib.auth.models import  User


# Create your models here.

class Donor(models.Model):
    user = models.ForeignKey(User,on_delete=models.CASCADE)
    contact = models.CharField(max_length=30,null=True)
    address = models.CharField(max_length=300,null=True)
    regdate = models.DateTimeField(auto_now_add=True)
    def __str__(self):
        return self.User.Username


class Accommodation(models.Model):
    user = models.ForeignKey(User,on_delete=models.CASCADE)
    contact = models.CharField(max_length=30,null=True)
    address = models.CharField(max_length=300,null=True)
    photo_ID =models.FileField(null=True)
    regdate = models.DateTimeField(auto_now_add=True)
    def __str__(self):
        return self.User.Username

class Donation(models.Model):
    user = models.ForeignKey(User,on_delete=models.CASCADE)
    category = models.CharField(max_length=30,null=True)
    type = models.CharField(max_length=30,null=True)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
   
    def __str__(self):
        return self.user.username
    


class User(models.Model):
    username = models.CharField(max_length=50)
    email = models.EmailField(max_length=100)
    password = models.CharField(max_length=100)
    date_created = models.DateTimeField(auto_now_add=True)
