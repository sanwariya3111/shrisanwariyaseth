from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib.auth.models import User,auth
from django.contrib import messages
from django.core.mail import EmailMessage, send_mail
from donationpage import settings
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import force_bytes, force_str
from . tokens import generate_token
from django.contrib.auth import authenticate, login, logout

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

# ***************************************************************


# Create your views here.
def home(request):
    return render(request,'home.html')

def home_hin(request):
    return render(request,'home-hin.html')


def register(request):
    if request.method == "POST":
        username = request.POST['username']
        fname = request.POST['fname']
        lname = request.POST['lname']
        email = request.POST['email']
        password = request.POST['pass1']
        pass1 = request.POST['pass2']
        
        if User.objects.filter(username=username):
            print('***************************************username*****************************************')
            messages.error(request, "Username already exist! Please try some other username.")
            return redirect('register')
        
        if User.objects.filter(email=email).exists():
            print('***********************************email************************************************')
            messages.error(request, "Email Already Registered!!")
            return redirect('register')
        
        if len(username)>20:
            print('*************************************length*******************************************')
            messages.error(request, "Username must be under 20 charcters!!")
            return redirect('register')
        
        if password != pass1:
            print('*************************************password*******************************************')
            messages.error(request, "Passwords didn't matched!!")
            return redirect('register')
        
        if not username.isalnum():
            print('**********************************invalid input*************************************************')
            messages.error(request, "Username must be Alpha-Numeric!!")
            return redirect('register')
        
        myuser = User.objects.create_user(username, email, pass1)
        myuser.fname = fname
        myuser.lname = lname
        # myuser.is_active = False
        myuser.is_active = False
        myuser.save()
        messages.success(request, "Your Account has been created succesfully!! Please check your email to confirm your email address in order to activate your account.")
        
        # Welcome Email
        subject = "Welcome to GFG- Django Login!!"
        message = "Hello " + myuser.first_name + "!! \n" + "Welcome to GFG!! \nThank you for visiting our website\n. We have also sent you a confirmation email, please confirm your email address. \n\nThanking You\nAnubhav Madhav"        
        from_email = settings.EMAIL_HOST_USER
        to_list = [myuser.email]
        send_mail(subject, message, from_email, to_list, fail_silently=True)
        
        # Email Address Confirmation Email
        current_site = get_current_site(request)
        email_subject = "Confirm your Email @ GFG - Django Login!!"
        message2 = render_to_string('email_confirmation.html',{
            
            'name': myuser.first_name,
            'domain': current_site.domain,
            'uid': urlsafe_base64_encode(force_bytes(myuser.pk)),
            'token': generate_token.make_token(myuser)
        })
        email = EmailMessage(
        email_subject,
        message2,
        settings.EMAIL_HOST_USER,
        [myuser.email],
        )
        email.fail_silently = True
        email.send()
        
        return redirect('login')
        
        
    return render(request,  "register.html")


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



def signin(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        
        user = auth.authenticate(username=username, password=password)
        
        if user is not None:
            auth.login(request, user)
            fname = user.first_name
             # messages.success(request, "Logged In Sucessfully!!")
            return redirect("donations")
        else:
            messages.error(request, "Bad Credentials!!")
            return redirect('login')
    
    return render(request, "login.html")



def signout(request):
    signout(request)
    messages.success(request, "Logged Out Successfully!!")
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


class CustomPasswordResetView(PasswordResetView):
    email_template_name = 'registration/password_reset_email.html'
    subject_template_name = 'registration/password_reset_subject.txt'
    success_url = reverse_lazy('password_reset_done')

    def form_valid(self, form):
        user_email = form.cleaned_data['email']
        user = User.objects.filter(email=user_email).first()
        if user:
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(str(user.pk).encode())
            reset_url = reverse_lazy('password_reset_confirm', kwargs={'uidb64': uid, 'token': token})
            reset_url = self.request.build_absolute_uri(reset_url)
            send_mail(
                subject=self.get_email_subject(),
                message='',
                from_email=None,
                recipient_list=[user.email],
                fail_silently=True,
                html_message=render_to_string(
                    self.email_template_name,
                    {
                        'user': user,
                        'reset_url': reset_url,
                        'domain': get_current_site(self.request),
                        'uid': uid,
                        'token': token,
                    },
                ),
            )
            messages.success(self.request, 'Password reset email has been sent.')
        else:
            messages.error(self.request, 'No user with that email address exists.')
        return redirect(self.get_success_url())


class CustomPasswordResetConfirmView(PasswordResetConfirmView):
    template_name = 'registration/password_reset_confirm.html'
    success_url = reverse_lazy('password_reset_complete')

    def form_valid(self, form):
        uidb64 = self.kwargs['uidb64']
        token = self.kwargs['token']
        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None

        if user is not None and default_token_generator.check_token(user, token):
            # Reset the user's password
            new_password = form.cleaned_data['new_password1']
            user.set_password(new_password)
            user.save()
            messages.success(self.request, 'Your password has been reset successfully.')
            return super().form_valid(form)

        messages.error(self.request, 'The password reset link is invalid or has expired.')
        return redirect(self.get_success_url())
    



# ***************************************************************
# def login(request):
#     return render(request,'login.html')

def donor_login(request):
    return render(request,'donor_login.html')

def accommodation(request):
    return render(request,'accommodation.html')

def accommodation_hin(request):
    return render(request,'accommodation-hin.html')


def darsan_booking(request):
    return render(request,'darsan_booking.html')


def donation(request):
    return render(request,'donation.html')

def donations(request):
    return render(request,'donations.html')

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
    return render(request,'gallery.html')

def aboutus_hin(request):
    return render(request,'aboutus-hin.html')


def work_tenure_hin(request):
    return render(request,'work-tenure-hin.html')

def board_regulations_hin(request):
    return render(request,'board-regulations-hin.html')





