from django.urls import path
from . import views
from django.contrib import admin


urlpatterns =[
    path('', views.home,name='home'),
    path('home-hin', views.home_hin,name='home-hin'),
    path('login', views.login,name='login'),
    path('donor_login', views.donor_login,name='donor_login'),
    path('accommodation', views.accommodation,name='accommodation'),
    path('accommodation-hin', views.accommodation_hin,name='accommodation-hin'),
    path('darsan_booking', views.darsan_booking,name='darsan_booking'),
    path('register', views.register,name='register'),
    path('donation', views.donation,name='donation'),
     path('donations', views.donations,name='donations'),
    path('aboutus', views.aboutus,name='aboutus'),
    path('history', views.history,name='history'),
    path('history-hin', views.history_hin,name='history-hin'),
    path('header', views.header,name='header'),
    path('work-tenure', views.worktenure,name='work-tenure'),
    path('daily-program', views.dailyprogram,name='daily-program'),
    path('daily-program-hin', views.dailyprogram_hin,name='daily-program-hin'),
    path('festivals', views.festivals,name='festivals'),
    path('festivals-hin', views.festivals_hin,name='festivals-hin'),
    path('how-to-reach-sanwariya-ji', views.how_reach_sanwariya,name='how-to-reach-sanwariya-ji'),
    path('how-to-reach-sanwariya-ji-hin', views.how_reach_sanwariya_hin,name='how-to-reach-sanwariya-ji-hin'),
    path('places-to-visit', views.places_to_visit,name='places-to-visit'),
     path('places-to-visit-hin', views.places_to_visit_hin,name='places-to-visit-hin'),
    path('vendor-registration', views.vendor_registration,name='vendor-registration'),
    path('board-regulations', views.board_regulations,name='board-regulations'),
    path('gallery', views.gallery,name='gallery'),
    path('aboutus-hin', views.aboutus_hin,name='aboutus-hin'),
    path('work-tenure-hin', views.work_tenure_hin,name='work-tenure-hin'),
    path('board-regulations-hin', views.board_regulations_hin,name='board-regulations-hin'),
]
