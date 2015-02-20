# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
import main.models
from django.conf import settings


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='KeyPair',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('uuid', main.models.UUIDField(unique=True, max_length=36)),
                ('status', models.CharField(default=b'generating', max_length=20, choices=[(b'generating', b'generating'), (b'public_key_failed', b'public_key_failed'), (b'have_public_key', b'have_public_key'), (b'have_private_key', b'have_private_key')])),
                ('status_detail', models.TextField(blank=True)),
                ('created_date', models.DateTimeField(auto_now_add=True)),
                ('recovery_threshold', models.SmallIntegerField(default=2)),
                ('release_date', models.DateTimeField()),
                ('p', main.models.BigIntField(default=921355984572641311672343424898410239406765173564481049529310998437412969038866770004018133863821119723063474210217706973316313378613043770818780115988652746380714841456142639704626352778746695851788302212813071729066781855064705915608677688092341542568424482925462180633889723579377448564293509252435087477281161286147259728549498972138533165527662691306617571151999644107722686129055657829181973528055808318168063541650472028439642172128232391355303186171522887793994216888734434516097403106470551045418225907760866937899119453358993949368302899196593348587781289829114461181435009345801458736138423284445935647778071510107564961338155282235194713303681529865383261800265733083885319259454542964149249843475773904339566680218460878240048849309064731923166303421897726591880342754670170435647389065546266133258192653962148274540863521430747245658342533592543361748499215018089153994702237916350245910933537662925365405565771274120172582583500547352310022433066022690275959677696743489993411404619219133001998952984404232404962367594198986426803887303895347014868878166590277345633941382072502883955197749732581385414098128645307956625290745193548601504669931868639779915942610143766629826114677053173092959998726060927521195420788443L)),
                ('g', main.models.BigIntField(default=663967539726681103144465862624023347327698702596964472546454820612078529024826511081834885051391640561027926017836691699314236534541923660174228237481359399239083180745492344196240271583191901030943363158476402690866816165544413727642448467281613902744460740068022342814226536910981053149313200570584734433264322026211121298776746854224456594445267601706025601843269197307467696022013820314999017250076524215045953776140607347805724914635970896016787967508383404799474484032431598064588430204717282130624030236791313438685820994454800688074168393190968240421774957367364475227967115216643497513476439355774507681852727818225180294894690159121962082595832983558603527661891598029737473340045490056765931576922756721299050664825278351270156746074608877854067592917025359654086073944428436312956493450184334004168961635631284623451494433780460973694438069529748624269922713354688628667211254835640052369781611093104976907294716270650398203701503416097526621503515524050090620184511166507246300606992283420185768295268028274863932225993620378369739945955786054094149373142999987843559918951091147136538232655389152381266513956594698580925978254637104203194517867999160375927926123576218934330517623079023322032849247628255803444186962170L)),
                ('x', main.models.BigIntField(null=True, blank=True)),
                ('y', main.models.BigIntField(null=True, blank=True)),
                ('public_key_file', models.TextField(blank=True)),
                ('temp_private_key_file', models.TextField(blank=True)),
                ('private_key_file', models.TextField(blank=True)),
            ],
            options={
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='Message',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('uuid', main.models.UUIDField(unique=True, max_length=36)),
                ('timestamp', models.DateTimeField()),
                ('message_type', models.CharField(max_length=20, choices=[(b'generate_key', b'generate_key'), (b'public_key', b'public_key'), (b'store_share', b'store_share'), (b'confirm_share', b'confirm_share'), (b'release_key', b'release_key')])),
                ('content', models.TextField()),
                ('signed_message', models.TextField()),
            ],
            options={
                'ordering': ['-timestamp'],
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='Trustee',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('nickname', models.CharField(max_length=255)),
                ('this_server', models.BooleanField(default=False)),
                ('key', models.TextField()),
                ('fingerprint', models.CharField(max_length=255)),
            ],
            options={
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='UserProfile',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('api_key', models.CharField(max_length=255, unique=True, null=True, blank=True)),
                ('trustee', models.ForeignKey(related_name='user_profiles', blank=True, to='main.Trustee', null=True)),
                ('user', models.OneToOneField(related_name='profile', to=settings.AUTH_USER_MODEL)),
            ],
            options={
            },
            bases=(models.Model,),
        ),
        migrations.AddField(
            model_name='message',
            name='from_trustee',
            field=models.ForeignKey(related_name='messages_sent', blank=True, to='main.Trustee', null=True),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='message',
            name='keypair',
            field=models.ForeignKey(related_name='messages', to='main.KeyPair'),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='message',
            name='to_trustee',
            field=models.ForeignKey(related_name='messages_received', blank=True, to='main.Trustee', null=True),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='keypair',
            name='trustees',
            field=models.ManyToManyField(to='main.Trustee'),
            preserve_default=True,
        ),
    ]
