from django.contrib import admin

from .models import *


class KeyPairAdmin(admin.ModelAdmin):
    list_display = ['uuid', 'release_date', 'status',]


class MessageAdmin(admin.ModelAdmin):
    list_display = ['uuid', 'keypair', 'message_type', 'from_trustee', 'to_trustee']


admin.site.register(UserProfile)
admin.site.register(Trustee)
admin.site.register(KeyPair, KeyPairAdmin)
admin.site.register(Message, MessageAdmin)