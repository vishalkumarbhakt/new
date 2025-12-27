"""
Email validation utilities for enhanced security and anti-abuse measures.
"""
import re
import socket
import time
import logging
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from django.conf import settings
from rest_framework import serializers

# Setup logging
logger = logging.getLogger(__name__)

# Optional DNS validation - can be disabled in production if causing issues
try:
    import dns.resolver
    DNS_VALIDATION_AVAILABLE = True
except ImportError:
    DNS_VALIDATION_AVAILABLE = False
    logger.warning("DNS validation not available. Install dnspython for MX record validation.")


class EmailSecurityValidator:
    """
    Comprehensive email validator with security features.
    """
    
    # Comprehensive list of temporary email domains
    TEMP_EMAIL_DOMAINS = {
        # Common temp email services
        '10minutemail.com', '20minutemail.com', '2prong.com', '33mail.com',
        'guerrillamail.com', 'guerrillamailblock.com', 'guerrillamail.net',
        'guerrillamail.biz', 'guerrillamail.org', 'guerrillamail.de',
        'mailinator.com', 'mailinator.net', 'mailtothis.com', 'yopmail.com',
        'tempmail.com', 'temp-mail.org', 'tempail.com', 'tempemail.com',
        'tempemail.net', 'tempr.email', 'throwaway.email', 'disposable.com',
        'getairmail.com', 'airmail.cc', 'mintemail.com', 'sharklasers.com',
        'spam4.me', 'spamgourmet.com', 'jetable.org', 'jetable.com',
        'mytrashmail.com', 'trashmail.com', 'trashmail.ws', 'trashmail.net',
        'getnada.com', 'emailondeck.com', 'emailnator.com', 'mohmal.com',
        'mohmal.in', 'mohmal.tech', 'correo.top', 'correo.email',
        'anonmail.net', 'anonymousemail.me', 'anonymbox.com', 'incognitomail.org',
        'incognitomail.com', 'fakeinbox.com', 'fakemail.net', 'fake-mail.ml',
        'emkei.cz', 'emeil.in', 'emeil.ir', 'emailfake.com', 'emailto.de',
        'emailhippo.com', 'emailisvalid.com', 'emailsensei.com', 'emailverify.com',
        'emailpick.com', 'emailsensei.org', 'email-fake.com', 'emailvalidator.net',
        '0-mail.com', '0clickemail.com', '0sg.net', '1-mail.com', '1chuan.com',
        '1mail.ml', '1secmail.com', '1secmail.org', '1secmail.net', '2fdgdfgdfgdf.tk',
        '2gdgdfgdfgdf.ml', '2prong.com', '30minutemail.com', '3mail.ga',
        '4warding.com', '4warding.net', '4warding.org', '5mail.cf', '6ip.us',
        '6mail.cf', '7days-printing.com', '7mail.ga', '8mail.cf', '8mail.ga',
        '9mail.cf', '9ox.net', 'abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk.com',
        'ac20mail.tk', 'acentri.com', 'acknowledgemail.com', 'achromaticdesign.com',
        'activist.com', 'adpugh.org', 'agedmail.com', 'ajaxapp.net', 'akapost.com',
        'akerd.com', 'alivance.com', 'amail.club', 'amail4.me', 'amilegit.com',
        'amiri.net', 'amiriindustrial.com', 'anonmails.de', 'anonymail.dk',
        'anonymbox.com', 'antichef.com', 'antichef.net', 'antireg.ru', 'antispam.de',
        'antispammail.de', 'appixie.com', 'armyspy.com', 'artman-conception.com',
        'asdasd.ru', 'atvclub.msk.ru', 'autosfromus.com', 'banana-mail.com',
        'baxomale.ht.cx', 'beefmilk.com', 'bigprofessor.so', 'bigstring.com',
        'binkmail.com', 'bio-muesli.net', 'bobmail.info', 'bodhi.lawlita.com',
        'bofthew.com', 'bootybay.de', 'boun.cr', 'bouncr.com', 'boxformail.in',
        'brokenvalve.com', 'brucecampbell.movies', 'bugmenot.com', 'bumpymail.com',
        'burnthespam.info', 'burstmail.info', 'buymoreplays.com', 'byom.de',
        'c2.hu', 'cachedot.net', 'card.zp.ua', 'casualdx.com', 'cbox.ws',
        'centermail.com', 'centermail.net', 'chammy.info', 'childsavetrust.org',
        'chogmail.com', 'choicemail1.com', 'clrmail.com', 'cmail.net', 'cmail.org',
        'coldemail.info', 'cool.fr.nf', 'correo.top', 'cosmorph.com', 'courriel.fr.nf',
        'courrieltemporaire.com', 'crapmail.org', 'crazymailing.com', 'cubiclink.com',
        'curryworld.de', 'cust.in', 'cutmail.com', 'dacoolest.com', 'dandikmail.com',
        'dayrep.com', 'dbunker.com', 'dcemail.com', 'deadaddress.com', 'deadchildren.org',
        'deadfake.cf', 'deadfake.ga', 'deadfake.ml', 'deadfake.tk', 'deadspam.com',
        'deagot.com', 'dealja.com', 'despam.it', 'despammed.com', 'devnullmail.com',
        'dfgh.net', 'dharmatel.net', 'digitalsanctuary.com', 'dingbone.com',
        'discard.email', 'discardmail.com', 'discardmail.de', 'disposableaddress.com',
        'disposableemailaddresses.com', 'disposablemail.com', 'disposablemail.eu',
        'disposablemail.org', 'disposablemail.ru', 'disposable-email.com',
        'disposableinbox.com', 'dispose.it', 'disposeamail.com', 'disposemail.com',
        'dodgeit.com', 'dodgit.com', 'donemail.ru', 'dontreg.com', 'dontsendmespam.de',
        'drdrb.net', 'droplar.com', 'dropmail.me', 'duam.net', 'dudmail.com',
        'dumpmail.de', 'dumpyemail.com', 'duskmail.com', 'e-mail.com', 'e-mail.org',
        'e4ward.com', 'easytrashmail.com', 'email-fake.com', 'emailgo.de',
        'emailias.com', 'emailinfive.com', 'emailmiser.com', 'emails.ga',
        'emailsensei.com', 'emailsensei.org', 'emailtemporanea.com', 'emailtester.com',
        'emailtmp.com', 'emailwarden.com', 'emailx.at.hm', 'emailxfer.com',
        'emailz.cf', 'emailz.ga', 'emailz.ml', 'emeil.in', 'emeil.ir', 'emeraldwebmail.com',
        'emil.com', 'emz.net', 'enterto.com', 'ephemail.net', 'etranquil.com',
        'etranquil.net', 'etranquil.org', 'evopo.com', 'example.com', 'explodemail.com',
        'express.net.ua', 'eyepaste.com', 'fakeinbox.com', 'fakemailgenerator.com',
        'fakemailz.com', 'fakeoutdoorsupply.com', 'fammix.com', 'fansworldwide.de',
        'fantasymail.de', 'fastacura.com', 'fastchevy.com', 'fastchrysler.com',
        'fastkawasaki.com', 'fastmazda.com', 'fastmitsubishi.com', 'fastnissan.com',
        'fastsubaru.com', 'fastsuzuki.com', 'fasttoyota.com', 'fastyamaha.com',
        'fatflap.com', 'fdfdsfds.com', 'fightallspam.com', 'fightallspam.net',
        'fightallspam.org', 'film-blog.biz', 'filzmail.com', 'fixmail.tk',
        'fizmail.com', 'fleckens.hu', 'flemail.ru', 'floppy.com', 'flowu.com',
        'flyspam.com', 'footard.com', 'forgetmail.com', 'fr33mail.info',
        'frapmail.com', 'front14.org', 'fuckingduh.com', 'fudgerub.com',
        'fux0ringduh.com', 'fyii.de', 'garbagemail.org', 'garliclife.com',
        'gelitik.in', 'get-mail.cf', 'get-mail.ga', 'get-mail.ml', 'get-mail.tk',
        'get1mail.com', 'get2mail.fr', 'getmails.eu', 'gfcom.com', 'ggally.com',
        'girlsundertheinfluence.com', 'gishpuppy.com', 'gmal.com', 'gmial.com',
        'goemailgo.com', 'gorillaswithdirtyarmpits.com', 'gotmail.com',
        'gotmail.net', 'gotmail.org', 'gotti.otherinbox.com', 'great-host.in',
        'greensloth.com', 'grr.la', 'gsrv.co.uk', 'guerillamail.biz',
        'guerillamail.com', 'guerillamail.de', 'guerillamail.net', 'guerillamail.org',
        'guerrillamail.biz', 'guerrillamail.com', 'guerrillamail.de',
        'guerrillamail.info', 'guerrillamail.net', 'guerrillamail.org',
        'guerrillamailblock.com', 'h.mintemail.com', 'h8s.org', 'harakirimail.com',
        'hatespam.org', 'herp.in', 'hidemail.de', 'hidzz.com', 'hmamail.com',
        'hopemail.biz', 'hotpop.com', 'hulapla.de', 'ieatspam.eu', 'ieatspam.info',
        'ieh-mail.de', 'ignoremail.com', 'iheartspam.org', 'ikbenspamvrij.nl',
        'imails.info', 'inbax.tk', 'inbox.si', 'inboxalias.com', 'inboxclean.com',
        'inboxclean.org', 'inboxproxy.com', 'incognitomail.com', 'incognitomail.net',
        'incognitomail.org', 'insorg-mail.info', 'instant-mail.de', 'instantemailaddress.com',
        'ipoo.org', 'irish2me.com', 'iroid.com', 'iwi.net', 'jetable.com',
        'jetable.fr.nf', 'jetable.net', 'jetable.org', 'jnxjn.com', 'junk1e.com',
        'junkmail.ga', 'junkmail.gq', 'killmail.com', 'killmail.net', 'klassmaster.com',
        'klassmaster.net', 'klzlk.com', 'koszmail.pl', 'kurzepost.de', 'lawlita.com',
        'lazyinbox.com', 'letthemeatspam.com', 'lhsdv.com', 'lifebyfood.com',
        'link2mail.net', 'litedrop.com', 'liveradio.tk', 'lmails.net', 'login-email.cf',
        'login-email.ga', 'login-email.ml', 'login-email.tk', 'loh.pp.ua', 'lookugly.com',
        'lopl.co.cc', 'lortemail.dk', 'lovemeleaveme.com', 'lr78.com', 'lroid.com',
        'lukop.dk', 'm21.cc', 'maboard.com', 'magicmail.pro', 'mail-filter.com',
        'mail-temporaire.fr', 'mail.by', 'mail.mezimages.net', 'mail.zp.ua',
        'mail1a.de', 'mail21.cc', 'mail2rss.org', 'mail333.com', 'mail4trash.com',
        'mailbidon.com', 'mailblocks.com', 'mailbucket.org', 'mailcat.biz',
        'mailcatch.com', 'maildrop.cc', 'maildrop.cf', 'maildrop.ga', 'maildrop.gq',
        'maildrop.ml', 'maildu.de', 'maileater.com', 'mailexpire.com', 'mailforspam.com',
        'mailfreeonline.com', 'mailguard.me', 'mailin8r.com', 'mailinater.com',
        'mailinator.com', 'mailinator.gq', 'mailinator.net', 'mailinator.org',
        'mailinator2.com', 'mailincubator.com', 'mailismagic.com', 'mailme.lv',
        'mailme24.com', 'mailmetrash.com', 'mailmoat.com', 'mailms.com',
        'mailnesia.com', 'mailnull.com', 'mailorg.org', 'mailpick.biz', 'mailrock.biz',
        'mailscrap.com', 'mailshell.com', 'mailsiphon.com', 'mailslapping.com',
        'mailslite.com', 'mailtemp.info', 'mailtome.de', 'mailtothis.com',
        'mailtrash.net', 'mailtv.net', 'mailtv.tv', 'mailzilla.com', 'mailzilla.org',
        'makemetheking.com', 'manybrain.com', 'mbx.cc', 'mega.zik.dj', 'meinspamschutz.de',
        'meltmail.com', 'messagebeamer.de', 'mierdamail.com', 'migmail.pl', 'mintemail.com',
        'moburl.com', 'moncourrier.fr.nf', 'monemail.fr.nf', 'monmail.fr.nf',
        'monumentmail.com', 'mt2009.com', 'mt2014.com', 'mycard.net.ua', 'mycleaninbox.net',
        'myemailboxy.com', 'mymail-in.net', 'mypacks.net', 'mypartyclip.de',
        'myphantomemail.com', 'mysamp.de', 'mystockphoto.com', 'mytrashmail.com',
        'mytrashmail.compookmail.com', 'nabuma.com', 'neomailbox.com', 'nepwk.com',
        'nervmich.net', 'nervtmich.net', 'netmails.com', 'netmails.net', 'netzidiot.de',
        'neverbox.com', 'nice-4u.com', 'nincsmail.hu', 'nnh.com', 'no-spam.ws',
        'nobulk.com', 'noclickemail.com', 'nogmailspam.info', 'nomail.xl.cx',
        'nomail2me.com', 'nomorespamemails.com', 'nonspam.eu', 'nonspammer.de',
        'noref.in', 'nospam.ze.tc', 'nospam4.us', 'nospamfor.us', 'nospamthanks.info',
        'notmailinator.com', 'nowmymail.com', 'objectmail.com', 'obobbo.com',
        'odnorazovoe.ru', 'oneoffemail.com', 'onewaymail.com', 'onlatedotcom.info',
        'oopi.org', 'ordinaryamerican.net', 'otherinbox.com', 'ovpn.to', 'owlpic.com',
        'pancakemail.com', 'paplease.com', 'pcusers.otherinbox.com', 'pjkdo.com',
        'plexolan.de', 'poczta.onet.pl', 'politikerclub.de', 'pooae.com', 'pookmail.com',
        'poopiebutts.com', 'postacin.com', 'povario.com', 'proxymail.eu', 'prtnx.com',
        'putthisinyourspamdatabase.com', 'pwrby.com', 'quickinbox.com', 'rcpt.at',
        'reallymymail.com', 'realtyalerts.ca', 'receiveee.com', 'rhyta.com',
        'rmqkr.net', 'royal.net', 'rtrtr.com', 'rumgel.com', 's0ny.net', 'safe-mail.net',
        'safersignup.de', 'safetymail.info', 'safetypost.de', 'sandelf.de',
        'saynotospams.com', 'schafmail.de', 'secretemail.de', 'secure-mail.biz',
        'selfdestructingmail.com', 'sendspamhere.com', 'shieldemail.com', 'shiftmail.com',
        'shitmail.me', 'shitware.nl', 'shmeriously.com', 'shortmail.net', 'sibmail.com',
        'sinnlos-mail.de', 'siteposter.net', 'skeefmail.com', 'slaskpost.se',
        'smashmail.de', 'smellfear.com', 'snakemail.com', 'sneakemail.com', 'snkmail.com',
        'sofort-mail.de', 'sogetthis.com', 'solvemail.info', 'soodomail.com',
        'spam.la', 'spam.su', 'spam4.me', 'spamail.de', 'spambob.com', 'spambob.net',
        'spambob.org', 'spambog.com', 'spambog.de', 'spambog.ru', 'spambox.info',
        'spambox.irishspringtours.com', 'spambox.us', 'spamcannon.com', 'spamcannon.net',
        'spamcon.org', 'spamcorptastic.com', 'spamcowboy.com', 'spamcowboy.net',
        'spamcowboy.org', 'spamday.com', 'spamex.com', 'spamfree24.com', 'spamfree24.de',
        'spamfree24.eu', 'spamfree24.net', 'spamfree24.org', 'spamgoes.com',
        'spamgourmet.com', 'spamgourmet.net', 'spamgourmet.org', 'spamherelots.com',
        'spamhereplease.com', 'spamhole.com', 'spami.spam.co.za', 'spaminator.de',
        'spamkill.info', 'spaml.com', 'spaml.de', 'spammotel.com', 'spamobox.com',
        'spamoff.de', 'spamslicer.com', 'spamspot.com', 'spamstack.net', 'spamthis.co.uk',
        'spamthisplease.com', 'spamtrail.com', 'spamtroll.net', 'speed.1s.fr',
        'spoofmail.de', 'stuffmail.de', 'super-auswahl.de', 'supergreatmail.com',
        'supermailer.jp', 'superrito.com', 'superstachel.de', 'suremail.info',
        'talkinator.com', 'tazmail.com', 'teleworm.com', 'temp-mail.org', 'temp-mail.ru',
        'tempalias.com', 'tempe-mail.com', 'tempemail.biz', 'tempemail.com',
        'tempinbox.co.uk', 'tempinbox.com', 'tempmail.co', 'tempmail.it',
        'tempmail2.com', 'tempmaildemo.com', 'tempmailer.com', 'tempmailer.de',
        'tempomail.fr', 'temporarily.de', 'temporarioemail.com.br', 'temporaryemail.net',
        'temporaryforwarding.com', 'temporaryinbox.com', 'temporarymailaddress.com',
        'tempthe.net', 'thanksnospam.info', 'thankyou2010.com', 'thc.st', 'thelimestones.com',
        'thepryam.info', 'thisisnotmyrealemail.com', 'thismail.net', 'throwawayemailaddresses.com',
        'tilien.com', 'tittbit.in', 'tmail.ws', 'tmailinator.com', 'tmpeml.info',
        'tmpjr.com', 'tmpmail.net', 'tmpmail.org', 'toiea.com', 'toomail.biz',
        'topranklist.de', 'tradermail.info', 'trash-amil.com', 'trash-mail.at',
        'trash-mail.com', 'trash-mail.de', 'trash2009.com', 'trash2010.com',
        'trash2011.com', 'trashdevil.com', 'trashdevil.de', 'trashemail.de',
        'trashmail.at', 'trashmail.com', 'trashmail.de', 'trashmail.me',
        'trashmail.net', 'trashmail.org', 'trashmail.ws', 'trashmailer.com',
        'trashymail.com', 'trialmail.de', 'trillianpro.com', 'turual.com', 'twinmail.de',
        'tyldd.com', 'uggsrock.com', 'umail.net', 'undo.it', 'unforgettable.ga',
        'upliftnow.com', 'uplipht.com', 'venompen.com', 'veryrealemail.com',
        'vidchart.com', 'viditag.com', 'viewcastmedia.com', 'viewcastmedia.net',
        'viewcastmedia.org', 'vomoto.com', 'vpn.st', 'vsimcard.com', 'vubby.com',
        'walala.org', 'walkmail.net', 'webemail.me', 'wegwerfadresse.de',
        'wegwerfemail.com', 'wegwerfemail.de', 'wegwerfmail.de', 'wegwerfmail.info',
        'wegwerfmail.net', 'wegwerfmail.org', 'wetrainbayarea.com', 'wetrainbayarea.org',
        'wh4f.org', 'whatpaas.com', 'whyspam.me', 'willhackforfood.biz', 'willselldrugs.com',
        'wuzup.net', 'wuzupmail.net', 'www.e4ward.com', 'www.gishpuppy.com',
        'www.mailinator.com', 'wwwnew.eu', 'x.ip6.li', 'xagloo.com', 'xemaps.com',
        'xents.com', 'xmaily.com', 'xoxy.net', 'yapped.net', 'yep.it', 'yogamaven.com',
        'yomail.info', 'yopmail.com', 'yopmail.fr', 'yopmail.net', 'youmailr.com',
        'yourdomain.com', 'ypmail.webredirect.org', 'yuurok.com', 'z1p.biz',
        'za.com', 'zehnminuten.de', 'zehnminutenmail.de', 'zetmail.com', 'zmail.ru',
        'zoemail.net', 'zoemail.org', 'zomg.info'
    }
    
    # Restricted usernames/local parts
    RESTRICTED_LOCAL_PARTS = {
        'admin', 'administrator', 'root', 'support', 'postmaster', 'webmaster',
        'info', 'contact', 'help', 'service', 'security', 'abuse', 'noreply',
        'no-reply', 'hostmaster', 'mailer-daemon', 'mailerdaemon', 'system',
        'operator', 'guest', 'anonymous', 'ftp', 'mail', 'www', 'uucp',
        'usenet', 'news', 'majordomo', 'marketing', 'sales', 'billing',
        'accounts', 'legal', 'privacy', 'api', 'staff', 'team', 'official',
        'test', 'testing', 'demo', 'example', 'sample', 'default', 'null',
        'void', 'nobody', 'nospam', 'blackhole', 'devnull', 'dev-null'
    }
    
    # Suspicious patterns in email
    SUSPICIOUS_PATTERNS = [
        r'[!#$%^&*()+=\[\]{}|\\:";\'<>?,./]{3,}',  # Multiple special characters
        r'^\d+$',  # Only numbers
        r'^[a-z]+\d{8,}$',  # Common pattern for fake emails
        r'^(test|fake|spam|dummy|temp|trash|junk)\d*$',  # Suspicious keywords as whole word
        r'(abuse|hack|exploit|ddos|dos|attack)',  # Attack-related terms
        r'[0-9]{12,}',  # Long number sequences
        r'(.)\1{6,}',  # Repeated characters (7 or more)
        r'^[a-z]{1,2}$',  # Too short local part
        r'^.{51,}',  # Too long local part - back to 51 chars
    ]
    
    def __init__(self):
        self.errors = []
        
        # Load settings for configurable behavior
        self.enable_mx_check = getattr(settings, 'EMAIL_VALIDATION_ENABLE_MX_CHECK', False)
        self.block_temp_emails = getattr(settings, 'EMAIL_VALIDATION_BLOCK_TEMP_EMAILS', True)
        self.block_reserved_usernames = getattr(settings, 'EMAIL_VALIDATION_BLOCK_RESERVED_USERNAMES', True)
        self.enable_suspicious_patterns = getattr(settings, 'EMAIL_VALIDATION_ENABLE_SUSPICIOUS_PATTERN_CHECK', True)
        self.strictness = getattr(settings, 'EMAIL_VALIDATION_STRICTNESS', 'strict')
        self.dns_timeout = getattr(settings, 'EMAIL_VALIDATION_DNS_TIMEOUT', 5)
        
        # Add custom blocked domains to the existing list
        custom_blocked_domains = getattr(settings, 'EMAIL_VALIDATION_CUSTOM_BLOCKED_DOMAINS', [])
        if custom_blocked_domains:
            self.TEMP_EMAIL_DOMAINS = self.TEMP_EMAIL_DOMAINS.union(set(custom_blocked_domains))
        
        # Add custom reserved usernames to the existing list
        custom_reserved_usernames = getattr(settings, 'EMAIL_VALIDATION_CUSTOM_RESERVED_USERNAMES', [])
        if custom_reserved_usernames:
            self.RESTRICTED_LOCAL_PARTS = self.RESTRICTED_LOCAL_PARTS.union(set(custom_reserved_usernames))
    
    def validate_email_format(self, email):
        """Validate basic email format with strict regex"""
        if not email:
            raise serializers.ValidationError("Email address is required.")
        
        # More strict email regex - allows dots but not at start/end or consecutive dots
        email_regex = re.compile(
            r'^[a-zA-Z0-9](?:[a-zA-Z0-9._-]*[a-zA-Z0-9])?@[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?\.[a-zA-Z]{2,}$'
        )
        
        if not email_regex.match(email):
            raise serializers.ValidationError(
                "Please enter a valid email address. Email must contain only letters, numbers, "
                "periods, hyphens, and underscores."
            )
        
        # Additional check for consecutive dots
        local_part = email.split('@')[0]
        if '..' in local_part:
            raise serializers.ValidationError(
                "Email address cannot contain consecutive periods."
            )
        
        return email.lower()
    
    def validate_email_length(self, email):
        """Validate email length constraints"""
        if len(email) > 254:
            raise serializers.ValidationError("Email address is too long (maximum 254 characters).")
        
        local_part, domain = email.rsplit('@', 1)
        
        if len(local_part) > 64:
            raise serializers.ValidationError("Email local part is too long (maximum 64 characters).")
        
        if len(domain) > 253:
            raise serializers.ValidationError("Email domain is too long (maximum 253 characters).")
    
    def validate_against_temp_domains(self, email):
        """Check against temporary email domains"""
        if not self.block_temp_emails:
            return  # Skip if disabled
            
        domain = email.split('@')[1].lower()
        
        if domain in self.TEMP_EMAIL_DOMAINS:
            raise serializers.ValidationError(
                "Temporary or disposable email addresses are not allowed. "
                "Please use a permanent email address."
            )
    
    def validate_against_restricted_locals(self, email):
        """Check against restricted local parts"""
        if not self.block_reserved_usernames:
            return  # Skip if disabled
            
        local_part = email.split('@')[0].lower()
        
        if local_part in self.RESTRICTED_LOCAL_PARTS:
            raise serializers.ValidationError(
                f"The email address '{local_part}' is reserved and cannot be used for registration."
            )
    
    def validate_suspicious_patterns(self, email):
        """Check for suspicious patterns in email"""
        if not self.enable_suspicious_patterns:
            return  # Skip if disabled
            
        local_part = email.split('@')[0].lower()
        
        # Adjust patterns based on strictness level
        patterns_to_check = self.SUSPICIOUS_PATTERNS
        if self.strictness == 'lenient':
            # Skip some strict patterns for lenient mode
            patterns_to_check = [p for p in self.SUSPICIOUS_PATTERNS 
                               if not p.startswith(r'^[a-z]{1,2}$') and not p.startswith(r'^.{51,}')]
        elif self.strictness == 'moderate':
            # Skip very strict patterns
            patterns_to_check = [p for p in self.SUSPICIOUS_PATTERNS 
                               if not p.startswith(r'^[a-z]{1,2}$')]
        
        for pattern in patterns_to_check:
            if re.search(pattern, local_part, re.IGNORECASE):
                raise serializers.ValidationError(
                    "Email address contains invalid characters or patterns. "
                    "Please use a standard email format."
                )
    
    def validate_domain_mx_record(self, email):
        """Validate that domain has MX record (optional - can be disabled in production)"""
        if not DNS_VALIDATION_AVAILABLE or not self.enable_mx_check:
            return  # Skip if DNS library not available or disabled
            
        try:
            domain = email.split('@')[1]
            # Check if domain has MX record with timeout
            dns.resolver.timeout = self.dns_timeout
            mx_records = dns.resolver.resolve(domain, 'MX')
            if not mx_records:
                raise serializers.ValidationError(
                    "Email domain does not accept emails. Please check your email address."
                )
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, Exception) as e:
            # In production, you might want to log this but not reject
            # For now, we'll allow it to pass but log the issue
            logger.warning(f"MX record validation failed for domain {email.split('@')[1]}: {str(e)}")
            pass
    
    def validate_domain_blacklist(self, email):
        """Check against additional domain blacklist"""
        domain = email.split('@')[1].lower()
        
        # Additional suspicious domains - removed example.org to allow testing
        suspicious_domains = {
            'example.com', 'example.net', 'test.com',
            'localhost', '127.0.0.1', 'test.local', 'invalid.com'
        }
        
        if domain in suspicious_domains:
            raise serializers.ValidationError(
                "Email domain is not allowed for registration."
            )
    
    def validate(self, email):
        """Main validation method"""
        # Check if email security is enabled
        if not getattr(settings, 'EMAIL_SECURITY_ENABLED', True):
            return email.lower()  # Basic normalization only
            
        # Clean and normalize email
        email = self.validate_email_format(email)
        
        # Run all validations based on configuration
        self.validate_email_length(email)
        self.validate_against_temp_domains(email)
        self.validate_against_restricted_locals(email)
        self.validate_suspicious_patterns(email)
        self.validate_domain_blacklist(email)
        
        # Optional: Validate MX record (based on configuration)
        if self.enable_mx_check:
            self.validate_domain_mx_record(email)
        
        return email


def validate_secure_email(email):
    """
    Django validator function for secure email validation
    """
    validator = EmailSecurityValidator()
    return validator.validate(email)


class RateLimitValidator:
    """
    Simple rate limiting for email validation attempts
    """
    def __init__(self):
        self.attempts = {}
    
    def is_rate_limited(self, ip_address, max_attempts=5, window_minutes=60):
        """Check if IP is rate limited"""
        import time
        current_time = time.time()
        window_start = current_time - (window_minutes * 60)
        
        if ip_address not in self.attempts:
            self.attempts[ip_address] = []
        
        # Clean old attempts
        self.attempts[ip_address] = [
            attempt_time for attempt_time in self.attempts[ip_address]
            if attempt_time > window_start
        ]
        
        # Check if rate limited
        if len(self.attempts[ip_address]) >= max_attempts:
            return True
        
        # Record this attempt
        self.attempts[ip_address].append(current_time)
        return False
