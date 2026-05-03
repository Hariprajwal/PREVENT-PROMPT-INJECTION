from django.contrib import admin
from .models import ChatbotUser, UserProfile, RequestLog

admin.site.register(ChatbotUser)
admin.site.register(UserProfile)
admin.site.register(RequestLog)
