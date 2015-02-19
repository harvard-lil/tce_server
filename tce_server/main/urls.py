from django.conf.urls import patterns, url

urlpatterns = patterns('main.views',
    url(r'^get_messages/$', 'get_messages', name='get_messages'),
    url(r'^send_message/$', 'send_message', name='send_message'),

    url(r'^key/(?P<key_id>\d+)/public/$', 'public_key_file', name='public_key_file'),
    url(r'^key/(?P<key_id>\d+)/private/$', 'private_key_file', name='private_key_file'),
    url(r'^$', 'index', name='index'),
)
