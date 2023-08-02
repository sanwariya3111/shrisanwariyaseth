from django.shortcuts import render, redirect,HttpResponseRedirect
from django.http import HttpResponse,JsonResponse
from django.core.files.storage import FileSystemStorage
from django.contrib.auth.models import User,auth
from django.contrib import messages
from django.core.mail import EmailMessage, send_mail
from requests import Request
from donationpage import settings
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import force_bytes, force_str
from . tokens import generate_token
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import UserCreationForm
from django import forms
from .models import  PaymentResponse, UploadFileDetails,UserProfile,UserLog
import uuid
import datetime
from donationapp.ccavutil import decrypt, encrypt
#from django.views.decorators.clickjacking import xframe_options_exempt
from string import Template
from django.views.decorators.csrf import csrf_exempt
# ***************************************************************


from django.contrib.auth import authenticate, login, logout, update_session_auth_hash 
from django.contrib.auth.forms import UserCreationForm, UserChangeForm, PasswordChangeForm
from django.contrib import messages 
from .forms import SignUpForm, EditProfileForm 

from django.shortcuts import render, redirect, get_object_or_404

from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.views import PasswordResetView, PasswordResetConfirmView
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.template.loader import render_to_string
from django.contrib.sites.shortcuts import get_current_site
from django.contrib.auth.models import User
from django.contrib.auth.tokens import default_token_generator
from django.shortcuts import redirect, resolve_url
from django.urls import reverse_lazy
from django.core.mail import send_mail
from django.contrib import messages
import re
import geocoder
# ***************************************************************

#Utility functions
def validate_email(email):
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    if re.match(pattern, email):
        return True
    else:
        return False

def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        try:
            ip = x_forwarded_for.split(',')[0]
        except:
            print("Error")
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

# Create your views here.

def home(request):
    request.session["url"] = request.path
    loguser(request,'home')
    livevideo = UploadFileDetails.objects.filter(deleted='No',active='Yes',section_id = 4).order_by('-id') .first()
    return render(request,'home.html',{'livevideo':livevideo})

def loguser(request,page):
    ip = get_client_ip(request)
    ip_location = geocoder.ip(f"{ip}")
    city = ip_location.city
    username = ''
    role = ''
    if request.user.is_authenticated:
       print(request.session.get('email'))
       print(request.session.get('role'))
       username = request.session['email']
       role = request.session['role']
    else:
        username = 'guest'
    data = UserLog(username=username,role=role,userip=ip,usercity=city,pagename=page)
    data.save()



def home_hin(request):
    return render(request,'home-hin.html')

class RegisterForm(UserCreationForm):
    class Meta:
        model = User
        fields = ['username', 'first_name',
                  'last_name', 'password1', 'password2']
        labels = {
            'username': 'Email',
            'first_name': 'First Name',
            'last_name': 'Last Name'
        }
        error_messages = {
            'username': {
                'unique': 'This Email you entered already exists',
            },
        }
    first_name = forms.CharField(max_length=50) 
    last_name = forms.CharField(max_length=50)


def register(request):
    if request.method == 'GET':
        form = RegisterForm()
        return render(request, 'register.html', {'form': form})
    
    if request.method == "POST":
        form = RegisterForm(request.POST)
        try:
            if form.is_valid() and validate_email(request.POST['username']):
                user = form.save(commit=False)
                user.username = user.username.lower()
                user.email = user.username
                user.is_active = False
                user.save()
                messages.success(request, "Your Account has been created succesfully!! Please check your email to confirm your email address in order to activate your account.")
                # Welcome Email
                subject = "Welcome to Sanwariya Temple!!"
                message = "Hello " + user.first_name + "!! \n" + "Welcome to Sanwariya Seth!! \nThank you for visiting our website.\n We have also sent you a confirmation email, please confirm your email address. \n\nThanking You\n Sanwariya Team"        
                from_email = settings.EMAIL_HOST_USER
                to_list = [user.email]
                send_mail(subject, message, from_email, to_list, fail_silently=True)
                
                # Email Address Confirmation Email
                current_site = get_current_site(request)
                email_subject = "Confirm your Email -Sanwariya Temple Login!!"
                message2 = render_to_string('email_confirmation.html',{
                    
                    'name': user.first_name,
                    'domain': current_site.domain,
                    'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                    'token': generate_token.make_token(user)
                })
                email = EmailMessage(
                email_subject,
                message2,
                settings.EMAIL_HOST_USER,
                [request.POST['username']],
                )
                email.fail_silently = True
                email.send()
                #return redirect('register-success/')
                #add space to flash message
                return redirect('login')
            else:
                if not validate_email(request.POST['username']):
                    messages.error(request, 'Enter Valid EmailAddress')
            return render(request, 'register.html', {'form': form}) 
        except Exception as e:
             return redirect('login')
            
    # return render(request,  "register.html")

def register_success(request):
    return render(request, 'register-success.html')


def activate(request,uidb64,token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        myuser = User.objects.get(pk=uid)
    except (TypeError,ValueError,OverflowError,User.DoesNotExist):
        myuser = None

    if myuser is not None and generate_token.check_token(myuser,token):
        myuser.is_active = True
        # user.profile.signup_confirmation = True
        myuser.save()
        # login(request,myuser)
        messages.success(request, "Your Account has been activated!!")
        return redirect('login')
    else:
        return render(request,'activation_failed.html')


@csrf_exempt
def signin(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        
        user = auth.authenticate(username=username, password=password)
        
        if user is not None:
            auth.login(request, user)
            request.session['username'] = user.first_name + " " + user.last_name
            request.session['email'] = user.email
            fname = user.first_name
            print(fname)
            #Get user role and check if admin ans store it in session
            role = UserProfile.objects.filter(username=user.username).first()
            if role is not None:
               request.session['role'] = role.role
            else:
               request.session['role'] = ''
            # messages.success(request, "Logged In Sucessfully!!")
            #return redirect("home")
            #return redirect("donations")
            
            return redirect(request.session.get('url', '/'))
        else:
            messages.error(request, "Bad Credentials!!")
            return redirect('login')
    
    return render(request, "login.html")



def logoutuser(request):
    logout(request)
    #messages.success(request, "Logged Out Successfully!!")
    return redirect('home')
# ***************************************************************
def edit_profile(request):
	if request.method =='POST':
		form = EditProfileForm(request.POST, instance= request.user)
		if form.is_valid():
			form.save()
			messages.success(request, ('You have edited your profile'))
			return redirect('home')
	else: 		#passes in user information 
		form = EditProfileForm(instance= request.user) 

	context = {'form': form}
	return render(request, 'authenticate/edit_profile.html', context)
	#return render(request, 'authenticate/edit_profile.html',{})



def change_password(request):
	if request.method =='POST':
		form = PasswordChangeForm(data=request.POST, user= request.user)
		if form.is_valid():
			form.save()
			update_session_auth_hash(request, form.user)
			messages.success(request, ('You have edited your password'))
			return redirect('home')
	else: 		#passes in user information 
		form = PasswordChangeForm(user= request.user) 

	context = {'form': form}
	return render(request, 'authenticate/change_password.html', context)

#*************************We don't use this logic now *******#

# class CustomPasswordResetView(PasswordResetView):
#     email_template_name = 'reset_password_sent.html'
#     subject_template_name = 'registration/password_reset_subject.txt'
#     success_url = reverse_lazy('password_reset_done')

#     def form_valid(self, form):
#         user_email = form.cleaned_data['email']
#         user = User.objects.filter(email=user_email).first()
#         if user:
#             token = default_token_generator.make_token(user)
#             uid = urlsafe_base64_encode(str(user.pk).encode())
#             reset_url = reverse_lazy('password_reset_confirm', kwargs={'uidb64': uid, 'token': token})
#             reset_url = self.request.build_absolute_uri(reset_url)
#             send_mail(
#                 subject=self.get_email_subject(),
#                 message='',
#                 from_email=None,
#                 recipient_list=[user.email],
#                 fail_silently=True,
#                 html_message=render_to_string(
#                     self.email_template_name,
#                     {
#                         'user': user,
#                         'reset_url': reset_url,
#                         'domain': get_current_site(self.request),
#                         'uid': uid,
#                         'token': token,
#                     },
#                 ),
#             )
#             messages.success(self.request, 'Password reset email has been sent.')
#         else:
#             messages.error(self.request, 'No user with that email address exists.')
#             redirect(self)
#         #return redirect(self.get_success_url())


# class CustomPasswordResetConfirmView(PasswordResetConfirmView):
#     template_name = 'registration/password_reset_confirm.html'
#     success_url = reverse_lazy('password_reset_complete')

#     def form_valid(self, form):
#         uidb64 = self.kwargs['uidb64']
#         token = self.kwargs['token']
#         try:
#             uid = urlsafe_base64_decode(uidb64).decode()
#             user = User.objects.get(pk=uid)
#         except (TypeError, ValueError, OverflowError, User.DoesNotExist):
#             user = None

#         if user is not None and default_token_generator.check_token(user, token):
#             # Reset the user's password
#             new_password = form.cleaned_data['new_password1']
#             user.set_password(new_password)
#             user.save()
#             messages.success(self.request, 'Your password has been reset successfully.')
#             return super().form_valid(form)

#         messages.error(self.request, 'The password reset link is invalid or has expired.')
#         return redirect(self.get_success_url())
    
#***************Ends Here ************#


# ***************************************************************
# def login(request):
#     return render(request,'login.html')

def donor_login(request):
    return render(request,'donor_login.html')

def accommodation(request):
    request.session["url"] = request.path
    images = UploadFileDetails.objects.filter(deleted='No',active='Yes',section_id = 3).all().order_by('-id') 
    return render(request, 'accommodation.html', {'images': images})

def accommodation_hin(request):
    return render(request,'accommodation-hin.html')


def darsan_booking(request):
    return render(request,'darsan_booking.html')

def contact_us(request):
    return render(request,'contact-us.html')

def donation(request):
    return render(request,'donation.html')

def donations(request):
    if request.user.is_authenticated:
        return render(request,'donations.html')
    else:
        request.session["url"] = request.path
        return redirect('login')
    

def aboutus(request):
    return render(request,'aboutus.html')

def history(request):
    return render(request,'history.html')

def history_hin(request):
    return render(request,'history-hin.html')

def header(request):
    return render(request,'header.html')

def worktenure(request):
    return render(request,'work-tenure.html')

def dailyprogram(request):
    return render(request,'daily-program.html')

def dailyprogram_hin(request):
    return render(request,'daily-program-hin.html')

def festivals(request):
    return render(request,'festivals.html')

def festivals_hin(request):
    return render(request,'festivals-hin.html')


def how_reach_sanwariya(request):
    return render(request,'how-to-reach-sanwariya-ji.html')

def how_reach_sanwariya_hin(request):
    return render(request,'how-to-reach-sanwariya-ji-hin.html')


def places_to_visit(request):
    return render(request,'places-to-visit.html')

def places_to_visit_hin(request):
    return render(request,'places-to-visit-hin.html')



def vendor_registration(request):
    return render(request,'vendor-registration.html')


def board_regulations(request):
    return render(request,'board-regulations.html')

def gallery(request):
    request.session["url"] = request.path
    images = UploadFileDetails.objects.filter(deleted='No',active='Yes',section_id = 1).all().order_by('-id') 
    videos = UploadFileDetails.objects.filter(deleted='No',active='Yes',section_id = 2).all().order_by('-id') 
    return render(request, 'gallery.html', {'images': images,'videos':videos})

def aboutus_hin(request):
    return render(request,'aboutus-hin.html')


def work_tenure_hin(request):
    return render(request,'work-tenure-hin.html')

def board_regulations_hin(request):
    return render(request,'board-regulations-hin.html')

def upload_file(request):
    try:
        
        if request.method == "POST" and (request.session['role'] == 'admin' or  request.session['role'] == 'superadmin'):
            sectionid = request.POST["sectionid"]
           
            #if request.FILES["file"] is not None:
            if request.FILES.get('file', False):
               file = request.FILES["file"]
               filename = file.name
               ext = str.split(filename, '.')[1]
               path = settings.MEDIA_ROOT
               fs = FileSystemStorage(location=path)  # defaults to   MEDIA_ROOT
               uid = str(uuid.uuid4())
               new_filename = uid+'.'+ext
               fs.save(new_filename, file)
               data = UploadFileDetails(
                filename=filename, uid=uid, uname=new_filename, file_type=ext, section_id=sectionid, path=path)
             
            if request.POST["videolink"] != "":
               videolink = request.POST["videolink"]
               data = UploadFileDetails(
                filename=videolink,uid=videolink ,uname=videolink, file_type='video', section_id=sectionid)
               
            # Save the file details to DB.
            
            data.save()
            # Return a JSON response indicating success
            return JsonResponse({"message": "File uploaded successfully.","uname":data.uname,"event_id":"","section_name":"","section_id":sectionid,"id":data.id,"file_type":data.file_type})
    except Exception as e:
        # Return a JSON response indicating failure
        return JsonResponse({"message": "File upload failed."})


# @login_required(login_url="login")
def getGalleryData(request):
    if request.method == "GET":
        qs = UploadFileDetails.objects.filter(
            active='Yes', deleted='No').all().order_by('-id') 
        return HttpResponse(qs.serialize(), content_type="application/json")

def getGalleryData(request, id, sectionid):
    if request.method == "GET":
        if id == "0":
            qs = UploadFileDetails.objects.filter(section_id=sectionid).all().order_by('-id') 
        if id == "0" and sectionid != "0":
            qs = UploadFileDetails.objects.filter(deleted='No',active='Yes').all().order_by('-id') 
        if id != "0" and sectionid != "0":
            qs = UploadFileDetails.objects.filter(
                id=id, section_id=sectionid).all().order_by('-id') 
        return HttpResponse(qs.serialize(), content_type="application/json")
    
def filterGalleryData(request,sectionid):
    if request.method == "POST":
        if sectionid != 0:
            qs = UploadFileDetails.objects.filter(deleted='No',active='Yes',section_id=sectionid).all().order_by('-id') 
        if sectionid == 0:
            qs = UploadFileDetails.objects.filter(deleted='No',active='Yes').all().order_by('-id') 
        return JsonResponse(qs.serialize(), content_type="application/json",safe=False)
        

def edit_Gallery(request):
    try:
        if request.session['role'] == 'admin' or  request.session['role'] == 'superadmin':
            data = UploadFileDetails.objects.filter(deleted='No',active='Yes').all().order_by('-id') 
            return render(request, 'edit_gallery.html', {'data': {}})
    except Exception as e:
        return redirect('login')


def deleteGalleryData(request, id): 
    if request.method == "GET" and (request.session['role'] == 'admin' or  request.session['role'] == 'superadmin'):
        try :
            UploadFileDetails.objects.filter(id=id).update(deleted='Yes',active='No')
            return JsonResponse({'result':'success'}, content_type="application/json")
        except Exception as e:
        # Return a JSON response indicating failure
            return JsonResponse({"result":"fail","message": "File upload failed."})
       

def adminusers(request):
    data = UserProfile.objects.all().order_by('-id') 
    return render(request, 'manage_admin.html', {'data': data})


def add_admin(request):
    if  request.method == "POST" and request.session['role'] == 'superadmin':
        username = request.POST["adminuser"]
        #UserProfile.objects.filter(username=username).delete()
        if  User.objects.filter(username=username).all().exists():
            if UserProfile.objects.filter(username=username).all().exists():
               return JsonResponse({"result":"0","message":"User already exists in admin group" })
            else:
                data = UserProfile(username=username,role ='admin',active='Yes')
                data.save()
                html = render_to_string('manage_admin_add.html', {'data': data,"action":"create"})
                return JsonResponse({"result":"1","html":html,"message":"User added successfully" })
        else:
            return JsonResponse({"result":"0","message":"User Does not exist" })
        
def modify_admin(request):
    if  request.method == "POST" and request.session['role'] == 'superadmin':
        username = request.POST["adminuser"]
        active = request.POST["active"]
        if UserProfile.objects.filter(username=username).all().exists():
            if active == 'Yes' :
              UserProfile.objects.filter(username=username).update(active='No',modifieddatetime=datetime.datetime.now())
            else:
                UserProfile.objects.filter(username=username).update(active='Yes',modifieddatetime=datetime.datetime.now())
            data =  UserProfile.objects.filter(username=username).all()
            html = render_to_string('manage_admin_add.html', {'data': data,"action":"update"})
            return JsonResponse({"result":"1","html":html,"message":"User updated successfully"})
        else:
            return JsonResponse({"result":"0","message":"User Does not exist" })



#@xframe_options_exempt     
@csrf_exempt
def handlePayment(request):
    print(request.session.get('email'))
    if request.method== "POST":
   
        try :
            p_merchant_id = settings.BOB_MERCHANT_ID
           # p_merchant_id = request.form['merchant_id']
            p_order_id = request.POST['order_id']
            p_currency = request.POST['currency']
            p_amount = request.POST['amount']
            p_redirect_url = get_current_host(request)+'responseHandler'
            p_cancel_url =  get_current_host(request)+'responseHandler'
            p_language = request.POST['language']
            p_billing_name = request.POST['billing_name']
            p_billing_address = request.POST['billing_address']
            p_billing_city = request.POST['billing_city']
            p_billing_state = request.POST['billing_state']
            p_billing_zip = request.POST['billing_zip']
            p_billing_country = request.POST['billing_country']
            p_billing_tel = request.POST['billing_tel']
            p_billing_email = request.POST['billing_email']
            p_delivery_name = request.POST['delivery_name']
            p_delivery_address = request.POST['delivery_address']
            p_delivery_city = request.POST['delivery_city']
            p_delivery_state = request.POST['delivery_state']
            p_delivery_zip = request.POST['delivery_zip']
            p_delivery_country = request.POST['delivery_country']
            p_delivery_tel = request.POST['delivery_tel']
            p_merchant_param1 = request.session.get('username') #request.POST['merchant_param1']
            p_merchant_param2 = request.session.get('email')
            p_merchant_param3 = request.POST['merchant_param3']
            p_merchant_param4 = request.POST['merchant_param4']
            p_merchant_param5 = request.POST['merchant_param5']
            p_integration_type = request.POST['integration_type']
            p_promo_code = request.POST['promo_code']
            p_customer_identifier = request.POST['customer_identifier']
            merchant_data='merchant_id='+str(p_merchant_id)+'&'+'order_id='+str(p_order_id) + '&' + "currency=" + str(p_currency) + '&' + 'amount=' + p_amount+'&'+'redirect_url='+p_redirect_url+'&'+'cancel_url='+p_cancel_url+'&'+'language='+p_language+'&'+'integration_type='+p_integration_type+'&'+'merchant_param1='+p_merchant_param1+'&'+'merchant_param2='+p_merchant_param2+'&'
            #+'billing_name='+p_billing_name+'&'+'billing_address='+p_billing_address+'&'+'billing_city='+p_billing_city+'&'+'billing_state='+p_billing_state+'&'+'billing_zip='+p_billing_zip+'&'+'billing_country='+p_billing_country+'&'+'billing_tel='+p_billing_tel+'&'+'billing_email='+p_billing_email+'&'+'integration_type='+p_integration_type+'&'
            
            encryption = encrypt(merchant_data,settings.BOB_WORKING_KEY)
           
            
            html = '''\
	<html>
	<head>
	<title>Sub-merchant checkout page</title>
	<script src="http://ajax.googleapis.com/ajax/libs/jquery/1.10.2/jquery.min.js"></script>
	</head>.
	<body>
	<center>
	<!-- width required mininmum 482px -->
	<iframe width="482" height="500" scrolling="No" frameborder="0"  id="paymentFrame" src="https://test.ccavenue.com/transaction/transaction.do?command=initiateTransaction&merchant_id=$mid&encRequest=$encReq&access_code=$xscode">
	</iframe>
	</center>

	<script type="text/javascript">
	$(document).ready(function(){
	$('iframe#paymentFrame').load(function() {
	window.addEventListener('message', function(e) {
	$("#paymentFrame").css("height",e.data['newHeight']+'px'); 	 
	}, false);
	}); 
	});
	</script>
	</body>
	</html>
	'''
            fin = Template(html).safe_substitute(mid=p_merchant_id,encReq=encryption,xscode=settings.BOB_ACCESS_CODE)
           # return render(request, 'payment.html')
            return HttpResponse(fin)
        except Exception as e:
            print(e)
            return JsonResponse({"result":"fail","message": "File upload failed."}) 
        
@csrf_exempt
def responseHandler(encResp): 
        '''
        Please put in the 32 bit alphanumeric key in quotes provided by CCAvenues.
        '''
        #workingKey = '05E669F8996EEFEA2AA7A6F9E470A8A5'
       # print(encResp.session['username'])
        #print(encResp.session.get('email'))
        #print(encResp.POST)
        decResp = decrypt(encResp.POST['encResp'],settings.BOB_WORKING_KEY)
        respDict = {}
        for decObj in decResp.split('&'):
            respDict[decObj.split('=')[0]]=decObj.split('=')[1]
      
        isRespAlreadyExists = PaymentResponse.objects.filter(bankrefnumber=respDict['bank_ref_no']).first()
       
        if isRespAlreadyExists is None:         
            data = PaymentResponse(orderid=respDict['b\'order_id'],bankrefnumber =int(respDict['bank_ref_no']),orderstatus=respDict['order_status'],tracking_id=int(respDict['tracking_id']),amount = respDict['amount'],paymentmode=respDict['payment_mode'],statuscode=respDict['status_code'] ,statusmessage= respDict['status_message'],currency=respDict['currency'],trans_date=datetime.datetime.strptime(respDict['trans_date'], '%d/%m/%Y %H:%M:%S').strftime('%Y-%m-%d %H:%M:%S'),merchantamount=respDict['mer_amount'],responsecode=respDict['response_code'],cardname=respDict['card_name'],billing_notes=respDict['billing_notes'],retry=respDict['retry'],ecivalue=respDict['eci_value'],username=respDict['merchant_param1'],email=respDict['merchant_param2'])
            data.save()
        if respDict['status_message'] == 'Y':
           return render(encResp, 'response-handler.html',{'transactionrefnumber':respDict['bank_ref_no'],'transactiondate':datetime.datetime.strptime(respDict['trans_date'], '%d/%m/%Y %H:%M:%S').strftime('%Y-%m-%d %H:%M:%S'),'amount':respDict['amount'],'name':respDict['merchant_param1'],'currency':respDict['currency']})        
        return render(encResp, 'payment-failed.html',{'reason': respDict['failure_message'],'transactionrefnumber':respDict['bank_ref_no']})
def get_current_host(request: Request) -> str:
    scheme = request.is_secure() and "https" or "http"
    return f'{scheme}://{request.get_host()}/'