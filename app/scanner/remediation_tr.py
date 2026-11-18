"""Turkish translations of impact + fix text. Keys are the exact rule patterns in remediation.RULES.

Configuration snippets stay as-is (they are code); only the explanations are translated.
"""
from __future__ import annotations

_REMOVE_FILE_TR = (
    "1. Dosyayı web kök dizininden silin.\n"
    "2. Bu tür yolları web sunucusunda engelleyin, örn. nginx:\n"
    "     location ~ /\\.(?!well-known) { deny all; }\n"
    "   Apache:\n"
    "     <FilesMatch \"^\\.\">\n       Require all denied\n     </FilesMatch>\n"
    "3. İçindeki her şeyi ele geçirilmiş sayın: parolaları, API anahtarlarını ve token'ları yenileyin.\n"
    "4. Dağıtımı temiz tutun (web kökünde yalnızca derlenmiş dosyalar olsun; repo verisi ve yedek bulunmasın)."
)

TR: dict[str, tuple[str, str]] = {
    # ---- new rules ----
    r"Session cookie": (
        "Tahmin edilebilir oturum kimlikleri, saldırganın başka kullanıcıların oturumunu ele geçirmesine yol açar.",
        "1. Oturum kimliklerini CSPRNG ile üretin (en az 128 bit), sayaç veya zaman damgası kullanmayın.\n"
        "2. Özel kimlik üretmek yerine framework'ün oturum yönetimini kullanın.\n"
        "3. Çerezi __Host- öneki ile adlandırın: Set-Cookie: __Host-sid=...; Secure; HttpOnly; Path=/"),
    r"Missing SPF|SPF allows|SPF uses": (
        "Saldırganlar alan adınızdan geliyormuş gibi görünen e-posta gönderebilir (oltalama, dolandırıcılık).",
        "1. Tüm yetkili gönderenleri tek bir TXT kaydında listeleyin, örn.\n"
        "   example.com. TXT \"v=spf1 include:_spf.google.com ip4:203.0.113.5 -all\"\n"
        "2. Liste tamamlanınca -all (reddet) ile bitirin; alan adı başına yalnızca bir SPF kaydı olmalı."),
    r"DMARC": (
        "Zorunlu bir DMARC politikası yoksa, alan adınızı taklit eden e-postalar teslim edilir.",
        "1. Yayınlayın: _dmarc.example.com. TXT \"v=DMARC1; p=none; rua=mailto:dmarc@example.com\"\n"
        "2. Birkaç hafta raporları izleyin, meşru gönderenleri düzeltin.\n"
        "3. Sırayla p=quarantine, sonra p=reject değerine geçin."),
    r"DKIM": (
        "E-postanın gerçekten alan adınızdan geldiği kriptografik olarak doğrulanamaz.",
        "E-posta sağlayıcınızda DKIM imzalamayı açın ve selector kaydını yayınlayın, örn. "
        "selector1._domainkey.example.com TXT \"v=DKIM1; k=rsa; p=...\"."),
    r"Missing CAA": (
        "Herhangi bir CA alan adınız için sertifika verebilir; ele geçirilmiş bir CA riski büyütür.",
        "Ekleyin: example.com. CAA 0 issue \"letsencrypt.org\"  (kendi CA'nızı yazın); isteğe bağlı iodef kaydı da ekleyin."),
    r"subdomain takeover": (
        "Saldırgan boşta kalan kaynağı sahiplenip alt alan adınız üzerinden içerik sunabilir (oltalama, çerez hırsızlığı).",
        "1. Artık kullanmadığınız servislere işaret eden DNS (CNAME) kayıtlarını silin.\n"
        "2. Ya da kaynağı sağlayıcıda yeniden oluşturup sahiplenin.\n3. DNS kayıtlarını düzenli denetleyin."),
    r"secret in JavaScript": (
        "İstemci kodunu herkes okuyabilir; sızan anahtar, ilgili servise doğrudan erişim verir.",
        "1. Sızan sırrı hemen iptal edip yenileyin.\n"
        "2. Gizli işlemleri sunucuya taşıyın; özel anahtar/token'ı JS içine koymayın.\n"
        "3. Herkese açık anahtarları (örn. Google Maps) sağlayıcı panelinde referrer/API ile kısıtlayın.\n"
        "4. CI'ya gizli anahtar taraması ekleyin (gitleaks, trufflehog)."),
    r"Outdated JavaScript library": (
        "Eski kütüphanelerdeki bilinen açıklar istismar edilebilir (XSS, prototype pollution, ReDoS).",
        "1. En güncel desteklenen sürüme yükseltin (npm update / CDN adresini değiştirin).\n"
        "2. Eski paketleri izlemek için 'npm audit' veya Dependabot/Renovate kullanın.\n"
        "3. Yükseltmeden sonra siteyi yeniden test edin."),
    r"Known CVEs": (
        "Herkesçe bilinen açıklar sunucunun ele geçirilmesine yol açabilir (sürüm tabanlı eşleşme).",
        "1. Gerçek sürümü doğrulayın (dağıtımlar düzeltmeleri geri taşır: paket changelog'una bakın).\n"
        "2. Yamalı sürüme güncelleyin: apt update && apt upgrade / yum update.\n3. Üreticinin güvenlik duyurularına abone olun."),
    r"No rate limiting": (
        "Hız sınırı olmaması parola deneme saldırısına, veri kazımaya ve hizmet engellemeye imkân verir.",
        "nginx:  limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;  ve  limit_req zone=login burst=10;\n"
        "Ayrıca girişte hesap kilitleme/CAPTCHA ekleyin ve API'lerde anahtar başına limit uygulayın."),
    r"Weak certificate key|weak signature": (
        "Zayıf anahtar veya özet algoritması sertifikanın sahte üretilmesine ya da kırılmasına izin verir.",
        "Sertifikayı RSA 2048+ (veya ECDSA P-256) ve SHA-256 imza ile yeniden oluşturun, sunucuda değiştirin."),
    r"WAF/CDN detected": (
        "Bilgilendirme: sonuçlar kaynak sunucuyu değil, ön taraftaki servisi yansıtıyor olabilir.",
        "1. WAF'ı engelleme modunda tutun, kural setlerini güncelleyin.\n"
        "2. Kaynak sunucunun güvenlik duvarında yalnızca CDN IP aralıklarına izin verin; böylece WAF atlatılamaz."),
    r"Supported TLS protocols|TLS 1\.3 not supported": (
        "Bilgilendirme: TLS yapılandırma verisi.",
        "Yalnızca TLS 1.2 ve 1.3'ü etkinleştirin. nginx: ssl_protocols TLSv1.2 TLSv1.3;"),
    r"security\.txt missing Expires|security\.txt has expired": (
        "Güncel olmayan güvenlik iletişim dosyaları araştırmacıları geçersiz adreslere yönlendirebilir.",
        "/.well-known/security.txt içine 'Expires: 2027-01-01T00:00:00.000Z' ekleyin veya yenileyin (RFC 9116)."),
    r"HTTP protocol info": (
        "Bilgilendirme amaçlı HTTP protokol sürümü verisi.",
        "Web sunucusunda veya CDN üzerinde HTTP/2 (ve destekleniyorsa HTTP/3) etkinleştirin."),
    r"Cache-Control: no-store|Sensitive page may be cached": (
        "Paylaşılan önbellekler veya tarayıcı geçmişi hassas sayfaları ya da oturum verilerini saklayabilir.",
        "Giriş/oturum sayfalarında şu başlığı gönderin: Cache-Control: no-store, private"),
    r"scoped to entire parent domain": (
        "Ele geçirilen herhangi bir alt alan adı, üst alan adına tanımlı çerezleri okuyabilir veya üzerine yazabilir.",
        "Oturum çerezlerinde Domain özniteliğini kaldırın (yalnızca ilgili host) veya __Host- önekini kullanın."),
    r"JWT uses 'alg: none'|JWT token has no expiration": (
        "İmzasız veya süresiz JWT'ler saldırganın sahte token üretmesine ya da çalınan token'ı süresiz kullanmasına yol açar.",
        "1. İzin verilen algoritmaları açıkça sınırlayın (RS256/ES256) ve 'none' algoritmasını reddedin.\n"
        "2. Her zaman kısa süreli bir 'exp' alanı ekleyin ve her istekte doğrulayın."),
    r"Cloud storage bucket reference": (
        "Sayfada referans verilen bulut depolama kovasında herkese açık listeleme/yazma varsa veri sızabilir veya değiştirilebilir.",
        "S3 Block Public Access / GCS tek tip erişim / Azure özel konteyner ayarlarını etkinleştirin."),
    r"GraphQL introspection enabled": (
        "Introspection tüm API şemasını açığa çıkararak saldırganların gizli sorgu/mutasyonları keşfetmesini kolaylaştırır.",
        "Canlı ortamda kimliği doğrulanmamış kullanıcılar için introspection'ı kapatın (Apollo: introspection: false)."),
    r"OpenAPI spec at .* declares no security": (
        "Kimlik doğrulama şeması tanımlanmamış uç noktalar yanlışlıkla korumasız bırakılmış olabilir.",
        "OpenAPI içinde securitySchemes tanımlayın ve herkese açık olmayan tüm rotalarda kimlik doğrulama zorunlu kılın."),
    r"Vulnerable dependencies in exposed manifest": (
        "Bilinen açıklara sahip bağımlılıklar istismar edilebilir; manifest dosyasının açık olması sürümleri ilan eder.",
        "1. Web sunucusunda package.json / composer.json erişimini engelleyin.\n"
        "2. npm audit / composer audit çalıştırıp etkilenen paketleri güncelleyin."),
    r"Domain expiration": (
        "Alan adı süresi dolarsa saldırgan alan adını yeniden kaydedip trafiği ve e-postayı ele geçirebilir.",
        "Alan adını yenileyin ve kayıt kuruluşunda otomatik yenileme + transfer kilidini açın."),
    r"Change detected:": (
        "Açık port, güvenlik başlığı, sertifika veya yazılımdaki beklenmeyen değişiklikler yapılandırma kaymasına işaret edebilir.",
        "Değişikliğin yetkili olup olmadığını doğrulayın; istenmeyen güvenlik duvarı/başlık/sunucu değişikliklerini geri alın."),
    # ---- original rules ----
    r"Strict-Transport-Security|HSTS": (
        "Kullanıcılar güvenilmeyen ağlarda HTTP'ye düşürülebilir (SSL-stripping) ve oturumları çalınabilir.",
        "1. Sitenin tamamının HTTPS üzerinden çalıştığından emin olun.\n2. Başlığı ekleyin:\n"
        "   nginx:  add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;\n"
        "   Apache: Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\"\n"
        "3. Testlerden sonra 'preload' ekleyip hstspreload.org'a başvurmayı düşünün."),
    r"Content-Security-Policy|CSP": (
        "CSP yoksa bir XSS açığı veya ele geçirilmiş üçüncü taraf script'i tarayıcıda kısıtsız çalışabilir.",
        "1. Neyin bozulacağını görmek için önce rapor modunda başlayın:\n"
        "   Content-Security-Policy-Report-Only: default-src 'self'; report-uri /csp-report\n"
        "2. Satır içi script/stilleri dosyaya taşıyın veya 'unsafe-inline' yerine nonce/hash kullanın.\n"
        "3. Zorunlu kılın, örn. nginx:\n"
        "   add_header Content-Security-Policy \"default-src 'self'; img-src 'self' data:; "
        "object-src 'none'; base-uri 'self'; frame-ancestors 'none'\" always;"),
    r"clickjacking|X-Frame-Options": (
        "Saldırganlar siteyi görünmez bir çerçeveye gömüp kullanıcıları düğmelere tıklamaya kandırabilir.",
        "Şunlardan birini ekleyin:\n   nginx:  add_header X-Frame-Options \"DENY\" always;\n"
        "   Apache: Header always set X-Frame-Options \"DENY\"\n"
        "Tercihen ayrıca CSP: frame-ancestors 'none' ekleyin (kendi sayfalarınızı çerçeveliyorsanız 'self')."),
    r"X-Content-Type-Options": (
        "Tarayıcılar sunulan dosyaları script olarak yorumlayabilir (MIME sniffing) ve XSS'e yol açabilir.",
        "nginx:  add_header X-Content-Type-Options \"nosniff\" always;\n"
        "Apache: Header always set X-Content-Type-Options \"nosniff\"\n"
        "Ayrıca her yanıtın doğru Content-Type taşıdığından emin olun."),
    r"X-XSS-Protection": (
        "Eski tarayıcı filtresi; kendisi de açık yaratabilir. Doğrudan risk düşük.",
        "Güçlü bir CSP tercih edin. İsterseniz eski filtreyi kapatmak için 'X-XSS-Protection: 0' gönderin."),
    r"Referrer-Policy": (
        "Tam URL'ler (token veya kimlik içerebilir) Referer başlığıyla üçüncü taraf sitelere sızabilir.",
        "nginx: add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;"),
    r"Permissions-Policy": (
        "Gömülü içerik için tarayıcı özellikleri (kamera, konum vb.) kısıtlanmamış.",
        "nginx: add_header Permissions-Policy \"camera=(), microphone=(), geolocation=()\" always;"),
    r"Cookie '": (
        "Secure/HttpOnly/SameSite olmayan çerezler XSS veya ağ dinleme ile çalınabilir ve siteler arası isteklerde gönderilir (CSRF).",
        "Oturum çerezlerinde üç özelliği de ayarlayın:\n"
        "   Set-Cookie: sid=...; Secure; HttpOnly; SameSite=Lax; Path=/\n"
        "PHP: session.cookie_secure=1, session.cookie_httponly=1, session.cookie_samesite=Lax\n"
        "Express: app.use(session({cookie:{secure:true,httpOnly:true,sameSite:'lax'}}))"),
    r"plain HTTP|not redirected to HTTPS": (
        "Tüm trafik (girişler, çerezler, içerik) ağ yolundaki herkes tarafından okunabilir veya değiştirilebilir.",
        "1. TLS sertifikası kurun (ücretsiz: Let's Encrypt / certbot).\n"
        "2. HTTP'yi HTTPS'e yönlendirin, nginx:\n"
        "   server { listen 80; server_name example.com; return 301 https://$host$request_uri; }\n"
        "3. Ardından HSTS'i etkinleştirin."),
    r"certificate failed validation|certificate expired|expiring soon": (
        "Tarayıcılar uyarı gösterir; kullanıcılar uyarıyı geçmeye alışır ve ortadaki adam saldırısı mümkün olur.",
        "1. Tam ana makine adını (SAN) kapsayan, güvenilir bir CA'dan sertifika alın.\n"
        "2. Tam zinciri (sertifika + ara sertifikalar) kurun.\n"
        "3. Yenilemeyi otomatikleştirin (certbot renew timer / ACME istemcisi) ve son kullanma tarihini izleyin."),
    r"Outdated TLS": (
        "Eski protokollerin bilinen zayıflıkları vardır (POODLE, BEAST) ve uyumluluğu bozar (PCI DSS).",
        "nginx:  ssl_protocols TLSv1.2 TLSv1.3;\nApache: SSLProtocol -all +TLSv1.2 +TLSv1.3\n"
        "Cipher'lar için Mozilla SSL Configuration Generator'ı kullanın."),
    r"Technology disclosed": (
        "Tam yazılım sürümleri saldırganın uygun herkese açık exploit'leri seçmesine yardım eder.",
        "nginx:  server_tokens off;\nApache: ServerTokens Prod  ve  ServerSignature Off\n"
        "PHP:    expose_php = Off\nASP.NET: <httpRuntime enableVersionHeader=\"false\"/> ve X-Powered-By'ı kaldırın\n"
        "En önemlisi yazılımı güncel tutun - sürümü gizlemek yalnızca küçük bir engeldir."),
    r"\.git|\.svn": (
        "Saldırganlar tüm kaynak kod geçmişini indirip sırları bulabilir ve başka açıkları keşfedebilir.",
        _REMOVE_FILE_TR),
    r"\.env|\.htpasswd|credentials|id_rsa|\.npmrc|bash_history": (
        "Parola, API anahtarı veya özel anahtarın doğrudan sızması tam ele geçirmeye yol açar.",
        _REMOVE_FILE_TR),
    r"Backup|Database dump|backup": (
        "Yedekler kaynak kod ve veri içerir; saldırgan kimlik doğrulamadan indirebilir.",
        _REMOVE_FILE_TR + "\n5. Yedekleri web sunucusu dışında, erişimi kısıtlı bir yerde saklayın."),
    r"phpinfo|server-status|server-info|actuator|Werkzeug|console|Adminer|elmah": (
        "Hata ayıklama/durum sayfaları yapılandırmayı, yolları, ortam değişkenlerini ve bazen uzaktan kod çalıştırmayı açığa çıkarır.",
        "1. Hata ayıklama uç noktalarını canlı ortamdan kaldırın.\n2. Gerekliyse IP ve kimlik doğrulama ile kısıtlayın:\n"
        "   nginx:  location /server-status { allow 10.0.0.0/8; deny all; }\n"
        "   Spring: management.endpoints.web.exposure.include=health\n3. Debug modunu kapatın (Flask/Django DEBUG=False)."),
    r"phpMyAdmin|Admin panel|wp-login|admin": (
        "Herkese açık yönetim panelleri kaba kuvvet ve kimlik bilgisi doldurma saldırılarının hedefidir.",
        "1. IP / VPN ile kısıtlayın veya ek HTTP kimlik doğrulamasının arkasına alın.\n"
        "2. Güçlü parola + çok faktörlü doğrulama uygulayın.\n3. Hız sınırı / fail2ban ekleyin.\n"
        "4. Uygulamayı güncel tutun."),
    r"web\.config|config|appsettings|application\.yml|composer|package": (
        "Yapılandırma ve bağımlılık dosyaları iç yapıyı ve çoğu zaman kimlik bilgilerini açığa çıkarır.",
        _REMOVE_FILE_TR),
    r"Directory listing": (
        "Saldırganlar dizindeki her dosyaya göz atıp indirebilir (istenmeyenler dahil).",
        "nginx:  autoindex off;\nApache: Options -Indexes\nIIS: 'Directory Browsing' özelliğini kapatın.\n"
        "Herkese açık olmayan dosyaları web kökünün dışına taşıyın."),
    r"robots\.txt|sitemap|security\.txt": (
        "Bilgilendirme. robots.txt gizli yolları gösterebilir; erişim kontrolü değildir.",
        "Gizli yolları robots.txt'te listelemeyin; kimlik doğrulama ile koruyun. "
        "Araştırmacıların bildirim yapabilmesi için security.txt (RFC 9116) yayınlamayı düşünün."),
    r"Reflected XSS|Possible reflected XSS|reflected \(encoded\)|Input reflected": (
        "Saldırgan hazırlanmış bir bağlantıyla kurbanın oturumunda JavaScript çalıştırabilir (çerez hırsızlığı, hesap ele geçirme).",
        "1. Çıktıyı bağlamına göre kodlayın (HTML, öznitelik, JS, URL) - şablon motorunun otomatik kaçışını kullanın "
        "(Jinja2 autoescape, React JSX, Twig, Razor); girdiyi asla HTML'e birleştirmeyin.\n"
        "2. Mümkünse girdiyi izin listesine göre doğrulayın.\n"
        "3. Derinlemesine savunma için sıkı CSP ve HttpOnly çerez ekleyin.\n"
        "4. Kullanıcı verisiyle innerHTML / document.write kullanmayın."),
    r"SQL injection": (
        "Saldırgan veritabanı içeriğini okuyabilir, değiştirebilir, silebilir; girişi atlayabilir, bazı durumlarda komut çalıştırabilir.",
        "1. Her yerde parametreli sorgu / hazır ifade kullanın:\n"
        "   Python: cur.execute(\"SELECT * FROM t WHERE id = %s\", (user_id,))\n"
        "   PHP PDO: $s = $pdo->prepare('SELECT * FROM t WHERE id = ?'); $s->execute([$id]);\n"
        "2. ORM'i doğru kullanın (ham string birleştirme yok).\n"
        "3. Veritabanı hesabına en az yetki verin.\n"
        "4. Canlıda ayrıntılı veritabanı hatalarını kapatın, sunucu tarafında loglayın."),
    r"Open redirect": (
        "Oltalama: güvenilir alan adındaki bağlantı kurbanı saldırganın sitesine yönlendirir.",
        "Yalnızca bilinen yollar/alan adları için izin listesi kullanın veya hedefleri sunucuda kimlikle eşleştirin; "
        "kullanıcı girdisindeki mutlak URL'leri reddedin."),
    r"CORS": (
        "Herhangi bir web sitesi, kurbanın tarayıcısında API'nizin kimlik doğrulamalı yanıtlarını okuyabilir.",
        "1. Origin başlığını körü körüne yansıtmayın; izin listesiyle karşılaştırın.\n"
        "2. Access-Control-Allow-Origin: * değerini asla kimlik bilgileriyle birleştirmeyin.\n"
        "3. Yalnızca gereken metot/başlıklara izin verin."),
    r"HTTP method|TRACE": (
        "TRACE siteler arası izlemeye yardım edebilir; korunmayan PUT/DELETE değişikliğe izin verebilir.",
        "nginx:  if ($request_method !~ ^(GET|HEAD|POST)$) { return 405; }\n"
        "Apache: TraceEnable off  ve  <LimitExcept GET POST HEAD> Require all denied </LimitExcept>"),
    r"Stack trace|Verbose error": (
        "Hata sayfaları kod yollarını, kütüphane sürümlerini ve sorguları açığa çıkarıp hedefli saldırıları kolaylaştırır.",
        "1. Canlıda debug modunu kapatın.\n2. Genel özel hata sayfaları ayarlayın (nginx error_page, "
        "Apache ErrorDocument, ASP.NET customErrors=On).\n3. Ayrıntıları yalnızca sunucuda loglayın."),
    r"Subresource Integrity|SRI": (
        "CDN ele geçirilirse sayfalarınızda kötü amaçlı JavaScript çalışır.",
        "integrity hash ve crossorigin ekleyin, örn.\n"
        "   <script src=\"https://cdn.example/lib.js\" integrity=\"sha384-...\" crossorigin=\"anonymous\"></script>\n"
        "Hash üretimi: openssl dgst -sha384 -binary lib.js | openssl base64 -A  - veya dosyayı kendiniz barındırın."),
    r"Mixed content": (
        "HTTPS sayfalardaki HTTP alt kaynakları değiştirilebilir ve güvenli sayfanın korumasını boşa çıkarır.",
        "Tüm kaynak URL'lerini https:// yapın (veya göreli yol kullanın) ve "
        "CSP: upgrade-insecure-requests ekleyin."),
    r"Password form|password field": (
        "Kimlik bilgileri açık metin iletilir ve dinlenebilir.",
        "Giriş sayfasını ve form action'ını yalnızca HTTPS ile sunun, HTTP'yi yönlendirin, HSTS'i açın."),
    r"CSRF": (
        "Saldırganlar giriş yapmış kullanıcının tarayıcısına, onayı olmadan işlem yaptırabilir.",
        "1. Durum değiştiren tüm formlara CSRF token ekleyin (framework ara katmanı: Django CsrfViewMiddleware, "
        "Laravel @csrf, Spring Security).\n2. SameSite=Lax/Strict çerez kullanın.\n3. POST'larda Origin/Referer'ı doğrulayın."),
    r"HTML comment": (
        "Yorumlar iç notları, kimlik bilgilerini, uç noktaları veya TODO'ları sızdırabilir.",
        "Derleme sürecinde yorumları temizleyin (HTML minifier) ve sır içerip içermediklerini gözden geçirin."),
    r"Port \d+ open": (
        "Açık her servis saldırı yüzeyini büyütür; geliştirme sunucuları çoğunlukla kimlik doğrulamasızdır.",
        "1. Gerekmeyen portları kapatın (güvenlik duvarı / security group, örn. ufw deny 8080).\n"
        "2. Geliştirme/iç servisleri 127.0.0.1'e bağlayın.\n3. Herkese açık servisleri TLS'li bir ters vekilin arkasına alın."),
    r"User enumeration|users endpoint": (
        "Geçerli kullanıcı adları kaba kuvvet ve oltalamaya yardım eder.",
        "Uç noktayı kapatın veya kısıtlayın (WordPress: anonim kullanıcılar için /wp-json/wp/v2/users'ı engelleyin)."),
    r"API documentation|Swagger|OpenAPI": (
        "Herkese açık API dokümantasyonu her uç noktayı ve parametreyi saldırganlara gösterir.",
        "Canlıda dokümantasyonu iç ağ veya kimliği doğrulanmış kullanıcılarla sınırlayın."),
}
