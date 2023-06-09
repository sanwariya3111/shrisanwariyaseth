from django.urls import path
from donationapp import views
from django.contrib import admin


from django.urls import path
from . import views
from django.urls import path
from django.contrib.auth import views as auth_views
from donationapp.views import CustomPasswordResetView, CustomPasswordResetConfirmView


# from django.urls import path
# from django.contrib.auth.views import (
#     PasswordResetDoneView,
#     PasswordResetCompleteView
# )



urlpatterns =[
    path('', views.home,name='home'),
    path('home-hin', views.home_hin,name='home-hin'),
    path('activate/<uidb64>/<token>', views.activate, name='activate'),
    path('signout', views.signout, name='signout'),
    path('login', views.signin, name='login'),
    path('register', views.register, name='register'),

    # path('change_password', views.change_password, name='change_password'),
    # path('password_reset', views.password_reset, name='password_reset'),
    # path('password_reset/done', views.password_reset_done, name='password_reset_done'),
    # path('reset/<uidb64>/<token>/', views.password_reset_confirm, name='password_reset_confirm'),


    # path('change_password/', ChangePassword.as_view(), name='change_password'),
    # path('password_reset/', SendEmailToResetPassword.as_view(), name='password_reset'),
    # path('password_reset/done/', PasswordResetDoneView.as_view(template_name='account/password_reset_done.html'), name='password_reset_done'),
    # path('reset/<uidb64>/<token>/', ResetPasswordConfirm.as_view(), name='password_reset_confirm'),


    # path('login', views.login,name='login'),
    path('donor_login', views.donor_login,name='donor_login'),
    path('accommodation', views.accommodation,name='accommodation'),
    path('accommodation-hin', views.accommodation_hin,name='accommodation-hin'),
    path('darsan_booking', views.darsan_booking,name='darsan_booking'),
    # path('register', views.register,name='register'),
    path('donation', views.donation,name='donation'),
     path('donations', views.donations,name='donations'),
    path('aboutus', views.aboutus,name='aboutus'),
    path('contact-us', views.contact_us,name='contact-us'),
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

    path('edit_profile/', views.edit_profile,name='edit_profile'),
    path('change_password/', views.change_password, name='change_password'),
    path('password_reset/', CustomPasswordResetView.as_view(), name='password_reset'),
    path('password_reset/confirm/<uidb64>/<token>/', CustomPasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('password_reset/done/', auth_views.PasswordResetDoneView.as_view(), name='password_reset_done'),
    path('password_reset/complete/', auth_views.PasswordResetCompleteView.as_view(), name='password_reset_complete'),
 ]

