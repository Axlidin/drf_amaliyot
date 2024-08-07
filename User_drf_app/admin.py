from django.contrib import admin
from .models import User_drf_amaliyot, UserConfirmation_drf_amaliyot

@admin.register(User_drf_amaliyot)
class UserModelAdmin(admin.ModelAdmin):
    list_display = ['id', 'username', 'email']
#
# @admin.register(UserConfirmation)
# class UserConfirmationAdmin(admin.ModelAdmin):
#     # list_display = ['user', 'verify_type']
admin.site.register(UserConfirmation_drf_amaliyot)