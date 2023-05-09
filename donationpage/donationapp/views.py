from django.shortcuts import render,redirect
from .models import *
from django.contrib.auth.models import auth,User
from django.contrib import messages


# Create your views here.
def home(request):
    return render(request,'home.html')

def home_hin(request):
    return render(request,'home-hin.html')

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










def login(request):
    if request.method == 'POST':
        
        username = request.POST['username']
        password = request.POST['password']

        user = auth.authenticate(username=username, password=password)

        if user is not None:
            auth.login(request, user)
            # return render(request, 'donation.html')
            return redirect('donations')
        else:
            messages.info(request, 'Invalid credentials')
            return render(request,'login.html')
    else:
        return render(request, 'login.html')



def register(request):
        if request.method == 'POST':
            first_name = request.POST['first_name']
            last_name = request.POST['last_name']
            username = request.POST['username']
            password1 = request.POST['password1']
            password2 = request.POST['password2']
            email = request.POST['email']

            if password1 == password2:
                if User.objects.filter(username=username).exists():
                    messages.info(request, 'Username is already exist')
                    return render(request, 'register.html')
                elif User.objects.filter(email=email).exists():
                    messages.info(request, 'Email is already exist')
                    return render(request, 'register.html')
                else:

                    # save data in db
                    user = User.objects.create_user(username=username, password=password1, email=email,
                                                    first_name=first_name, last_name=last_name)
                    user.save();
                    print('user created')
                    return redirect('login')

            else:
                messages.info(request, 'Invalid Credentials')
                return render(request, 'register.html')
            return redirect('/')
        else:
            return render(request, 'register.html')


