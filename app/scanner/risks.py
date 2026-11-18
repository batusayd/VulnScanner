"""Hazards that scanning itself can cause. Shown in the UI and in every report (EN + TR)."""

SCAN_RISKS = [
    {
        "title": "Service load / accidental denial of service",
        "title_tr": "Sunucu yükü / istemeden hizmet engelleme",
        "level": "Medium",
        "description": "The scanner sends dozens to hundreds of requests (sensitive paths, parameter probes, "
                       "crawling, rate-limit burst). Small, slow or fragile servers can become slow or unavailable.",
        "description_tr": "Tarayıcı onlarca-yüzlerce istek gönderir (hassas yollar, parametre testleri, crawl, hız sınırı "
                          "denemesi). Küçük, yavaş veya kırılgan sunucular yavaşlayabilir veya erişilemez olabilir.",
        "mitigation": "Use the 'gentle' profile for fragile sites, scan outside peak hours, start with a staging copy, "
                      "and have the owner watch CPU/memory during the scan.",
        "mitigation_tr": "Kırılgan sitelerde 'nazik' profilini kullanın, yoğun saatler dışında tarayın, önce test kopyasıyla "
                         "başlayın; site sahibi tarama sırasında CPU/bellek izlesin.",
    },
    {
        "title": "WAF / IDS alerts and IP blocking",
        "title_tr": "WAF / IDS alarmları ve IP engelleme",
        "level": "Low",
        "description": "Probes for .git, .env, quotes in parameters, etc. look like attacks. "
                       "Security tooling may raise alerts, page on-call staff or ban your IP.",
        "description_tr": ".git, .env, parametrelerde tırnak vb. denemeler saldırı gibi görünür. Güvenlik araçları alarm "
                          "üretebilir, nöbetçi ekibi uyandırabilir veya IP adresinizi engelleyebilir.",
        "mitigation": "Tell the site owner / SOC the scan window and your source IP beforehand and "
                      "allow-list the scanner if required.",
        "mitigation_tr": "Tarama zamanını ve kaynak IP'nizi önceden site sahibine / SOC'a bildirin; gerekirse tarayıcıyı "
                         "izin listesine aldırın.",
    },
    {
        "title": "Polluted logs and application errors",
        "title_tr": "Kirlenen loglar ve uygulama hataları",
        "level": "Low",
        "description": "Test values (quote characters, random markers) end up in access/error logs, "
                       "analytics and error monitoring, and may trigger database error messages.",
        "description_tr": "Test değerleri (tırnak karakterleri, rastgele işaretler) erişim/hata loglarına, analitiğe ve hata "
                          "izlemeye düşer; veritabanı hata mesajlarını tetikleyebilir.",
        "mitigation": "Filter the User-Agent 'VulnScanner' in analytics; inform developers so the "
                      "errors are not treated as real incidents.",
        "mitigation_tr": "Analitikte 'VulnScanner' User-Agent'ını filtreleyin; hataların gerçek olay sayılmaması için "
                         "geliştiricileri bilgilendirin.",
    },
    {
        "title": "Side effects on application state",
        "title_tr": "Uygulama durumunda yan etkiler",
        "level": "Low",
        "description": "Only GET/OPTIONS/TRACE requests are sent, which should be read-only. Badly "
                       "designed apps may still change state on GET (e.g. /logout, /delete?id=).",
        "description_tr": "Yalnızca GET/OPTIONS/TRACE istekleri gönderilir; bunlar salt okunur olmalıdır. Kötü tasarlanmış "
                          "uygulamalar GET ile de durum değiştirebilir (örn. /logout, /delete?id=).",
        "mitigation": "Do not scan authenticated sessions or pages that perform actions on GET. "
                      "Review the target's URLs first.",
        "mitigation_tr": "Oturum açılmış sayfaları veya GET ile işlem yapan sayfaları taramayın. Önce hedefin URL'lerini "
                         "inceleyin.",
    },
    {
        "title": "Data sent to third parties (optional features)",
        "title_tr": "Üçüncü taraflara giden veri (isteğe bağlı özellikler)",
        "level": "Low",
        "description": "The optional CVE lookup sends detected product names and versions to the NVD API; "
                       "notifications send scan summaries to Telegram/Slack/e-mail if configured.",
        "description_tr": "İsteğe bağlı CVE sorgusu tespit edilen ürün adı ve sürümünü NVD API'ye gönderir; bildirimler "
                          "yapılandırıldıysa tarama özetini Telegram/Slack/e-postaya gönderir.",
        "mitigation": "Enable those features only when acceptable for the target owner; keep tokens secret.",
        "mitigation_tr": "Bu özellikleri yalnızca hedef sahibi için uygunsa açın; token'ları gizli tutun.",
    },
    {
        "title": "Sensitive data in reports and history",
        "title_tr": "Raporlarda ve geçmişte hassas veri",
        "level": "Medium",
        "description": "Reports and the history database contain evidence such as exposed file snippets, paths, "
                       "technology versions and certificate details. A leaked report is a roadmap for attackers.",
        "description_tr": "Raporlar ve geçmiş veritabanı, açığa çıkan dosya parçaları, yollar, teknoloji sürümleri ve "
                          "sertifika bilgileri gibi kanıtlar içerir. Sızan bir rapor saldırganlara yol haritası olur.",
        "mitigation": "Store exports and data/vulnscanner.db securely, share only with the owner, delete when fixed. "
                      "Never publish them.",
        "mitigation_tr": "Dışa aktarımları ve data/vulnscanner.db dosyasını güvenli saklayın, yalnızca sahibiyle paylaşın, "
                         "düzeltilince silin. Asla yayınlamayın.",
    },
    {
        "title": "Legal and contractual exposure",
        "title_tr": "Hukuki ve sözleşmesel risk",
        "level": "High",
        "description": "Scanning without written permission may violate computer-misuse laws "
                       "(e.g. TCK 243-244 in Turkey, CFAA in the US) and hosting/CDN terms of service. "
                       "Shared hosting or third-party services (CDN, SaaS) may not be covered by "
                       "the owner's permission.",
        "description_tr": "Yazılı izin olmadan tarama, bilişim suçları yasalarını (örn. Türkiye'de TCK 243-244, ABD'de CFAA) "
                          "ve barındırma/CDN kullanım şartlarını ihlal edebilir. Paylaşımlı hosting veya üçüncü taraf "
                          "servisler (CDN, SaaS) sahibin iznine dahil olmayabilir.",
        "mitigation": "Get written authorisation that names the domains, IPs, time window and test "
                      "types. Record it in the scope fields; the scanner then blocks anything outside it.",
        "mitigation_tr": "Alan adlarını, IP'leri, zaman aralığını ve test türlerini belirten yazılı izin alın. Kapsam alanlarına "
                         "girin; tarayıcı bunun dışındaki her şeyi engeller.",
    },
    {
        "title": "False positives and false negatives",
        "title_tr": "Yanlış pozitifler ve yanlış negatifler",
        "level": "Info",
        "description": "Automated heuristics can flag harmless behaviour and miss real flaws "
                       "(authentication, business logic, stored/DOM XSS, blind SQLi).",
        "description_tr": "Otomatik sezgiler zararsız davranışları işaretleyebilir ve gerçek açıkları kaçırabilir "
                          "(kimlik doğrulama, iş mantığı, stored/DOM XSS, kör SQLi).",
        "mitigation": "Verify every finding manually (mark false positives in the dashboard); combine with manual testing.",
        "mitigation_tr": "Her bulguyu elle doğrulayın (yanlış pozitifleri panelde işaretleyin); manuel testle birleştirin.",
    },
    {
        "title": "Scanner host exposure",
        "title_tr": "Tarayıcı sunucusunun açığa çıkması",
        "level": "Medium",
        "description": "If the dashboard is reachable by others it could be used to scan arbitrary targets "
                       "from your machine.",
        "description_tr": "Panele başkaları erişebilirse makinenizden rastgele hedefler taranabilir.",
        "mitigation": "Keep it bound to 127.0.0.1 (default). To expose it, set DASHBOARD_USER/DASHBOARD_PASSWORD "
                      "(required by the app when BIND_HOST is not loopback) and use HTTPS in front.",
        "mitigation_tr": "127.0.0.1'e bağlı tutun (varsayılan). Dışarı açacaksanız DASHBOARD_USER/DASHBOARD_PASSWORD "
                         "ayarlayın (BIND_HOST loopback değilse uygulama zorunlu tutar) ve önüne HTTPS koyun.",
    },
]
