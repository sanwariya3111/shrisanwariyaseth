from django.db import models
from django.contrib.auth.models import  User

from django.db import models
from django.contrib.auth.models import User
from django.forms import DateField
from django.utils import timezone
from django_serializable_model import SerializableModel

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


from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone

# Create your models here.

class PasswordResetToken(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    token = models.CharField(max_length=100)
    created_at = models.DateTimeField(default=timezone.now)

class Active(models.TextChoices):
    YES = 'Yes'
    NO = 'No'


class Sections(models.TextChoices):
    General = 'General'
    SpecialEvent = 'SpecialEvent'

# declare a new model with a name "GeeksModel"


class UploadFileDetails(SerializableModel):
    # fields of the model
    id = models.AutoField(primary_key=True)
    filename = models.CharField(null=True,max_length=200)
    uid = models.CharField(null=True,max_length=200)
    uname = models.CharField(null=True,max_length=200)
    file_type = models.CharField(null=True, max_length=200)
    event_name = models.CharField(null=True, max_length=200)
    event_id = models.IntegerField(null=True, default=0)
    section_id = models.IntegerField(
        null=True, default=0)
    section_name = models.CharField(
        null=True, max_length=200)
    created_by = models.CharField(null=True, max_length=200)
    modified_by = models.CharField(null=True, max_length=200)
    created_time = models.DateTimeField(auto_now_add=True, null=False)
    last_modified = models.DateTimeField(auto_now_add=True, null=False)
    # folder = models.ImageField(upload_to = "templedata/")
    path = models.CharField(null=True,max_length=500)
    active = models.CharField(
        max_length=10, choices=Active.choices, default=Active.YES)
    deleted = models.CharField(
        max_length=10, choices=Active.choices, default=Active.NO)
    # whitelisted fields that are allowed to be seen
    WHITELISTED_FIELDS = set([
        'id', 'uid', 'uname', 'section_name', 'event_name', 'event_id','file_type'
    ])

    def serialize(self, *args, **kwargs):
        """Override serialize method to only serialize whitelisted fields"""
        fields = kwargs.pop('fields', self.WHITELISTED_FIELDS)
        return super(UploadFileDetails, self).serialize(*args, fields=fields)


class UserProfile(models.Model):
  username = models.CharField(null=False,unique=True,max_length=200)
  role = models.CharField(null=False,max_length=50)
  createddatetime = models.DateTimeField(auto_now_add=True, null=False)
  modifieddatetime = models.DateTimeField(null=True)
  active = models.CharField(
        max_length=10, choices=Active.choices, default=Active.YES)
  

class UserLog(models.Model):
  username = models.CharField(null=True,max_length=200)
  role = models.CharField(null=True,max_length=50)
  logindatetime = models.DateTimeField(auto_now_add=True, null=True)
  logoutdatetime = models.DateTimeField(null=True)
  userip = models.CharField(null=True,max_length=200)
  usercity = models.CharField(null=True,max_length=200)
  userstate = models.CharField(null=True,max_length=200)
  usercountry = models.CharField(null=True,max_length=200)
  userlocation = models.CharField(null=True,max_length=200)
  pagename = models.CharField(null=True,max_length=200)
  pageid = models.CharField(null=True,max_length=200)
  useragent = models.CharField(null=True,max_length=200)

class PaymentResponse(models.Model):
    id = models.AutoField(primary_key=True)
    orderid=models.BigIntegerField(null=False)
    tracking_id = models.BigIntegerField(null=True)
    bankrefnumber = models.BigIntegerField(null=True)
    orderstatus = models.CharField(max_length=30,null=True)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    paymentmode = models.CharField(max_length=30,null=True)
    statuscode = models.CharField(max_length=30,null=True)
    statusmessage = models.CharField(max_length=100,null=True)
    currency = models.CharField(max_length=100,null=True)
    trans_date = models.DateTimeField(null=True, blank=True)
    merchantamount = models.DecimalField(max_digits=10, decimal_places=2)
    responsecode =  models.CharField(max_length=30,null=True)
    cardname = models.CharField(max_length=30,null=True)
    retry = models.CharField(max_length=30,null=True)
    ecivalue = models.CharField(max_length=30,null=True)
    username = models.CharField(max_length=30,null=True)
    email = models.CharField(max_length=100,null=True)
    billing_notes=models.CharField(max_length=100,null=True)
