"""internallogservice URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path

from django.contrib import admin
from django.urls import path
from .core.views import login, sample_api, email_alert, edit_email_alert, delete_email_alert, get_from_gmc, \
    add_country_to_allowed_or_denied, add_or_delete_to_whitelist_and_blacklist


urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/login', login),
    path('api/sampleapi', sample_api),
    path('api/emailalert', email_alert),
    path('api/editemailalert', edit_email_alert),
    path('api/deleteemailalert', delete_email_alert),
    path('api/getfromgmc', get_from_gmc),
    path('api/countryallowordeny', add_country_to_allowed_or_denied),
    path('api/ipupdatewhiteandblacklist', add_or_delete_to_whitelist_and_blacklist)
]
