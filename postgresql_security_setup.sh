#!/bin/bash

# Renk tanımlamaları
KIRMIZI='\033[0;31m'
YESIL='\033[0;32m'
SARI='\033[1;33m'
MAVI='\033[0;34m'
NC='\033[0m'

# PostgreSQL yapılandırma dosyalarını bul
find_postgresql_config() {
    # Yaygın PostgreSQL yapılandırma dizinleri
    local conf_dizinleri=(
        "/etc/postgresql/*/main"
        "/var/lib/postgresql/*/main"
        "/usr/local/pgsql/data"
        "/usr/local/var/postgres"
        "/opt/homebrew/var/postgres"
        "/var/lib/pgsql/data"
        "/var/lib/pgsql/*/data"
        "/usr/pgsql-*/data"
        "/usr/pgsql-*/var/data"
    )
    
    local pg_conf=""
    local pg_hba_conf=""
    
    # Her bir dizini kontrol et
    for dizin in "${conf_dizinleri[@]}"; do
        for path in $dizin; do
            if [ -d "$path" ]; then
                if [ -f "$path/postgresql.conf" ]; then
                    pg_conf="$path/postgresql.conf"
                    echo -e "${YESIL}PostgreSQL yapılandırma dosyası bulundu: $pg_conf${NC}"
                fi
                
                if [ -f "$path/pg_hba.conf" ]; then
                    pg_hba_conf="$path/pg_hba.conf"
                    echo -e "${YESIL}PostgreSQL kimlik doğrulama dosyası bulundu: $pg_hba_conf${NC}"
                fi
            fi
        done
    done
    
    # Dosyalar bulunamadıysa
    if [ -z "$pg_conf" ]; then
        echo -e "${KIRMIZI}PostgreSQL yapılandırma dosyası bulunamadı!${NC}"
        return 1
    fi
    
    if [ -z "$pg_hba_conf" ]; then
        echo -e "${KIRMIZI}PostgreSQL kimlik doğrulama dosyası bulunamadı!${NC}"
        return 1
    fi
    
    # Global değişkenlere ata
    POSTGRESQL_CONF="$pg_conf"
    POSTGRESQL_HBA_CONF="$pg_hba_conf"
    
    return 0
}

# Hata kontrolü fonksiyonu
check_error() {
    if [ $? -ne 0 ]; then
        echo -e "${KIRMIZI}Hata: $1${NC}"
        echo -e "${KIRMIZI}İşlem iptal edildi.${NC}"
        return 1
    fi
    return 0
}

# PostgreSQL servisinin çalışıp çalışmadığını kontrol et
check_postgresql() {
    if ! systemctl is-active --quiet postgresql; then
        echo -e "${KIRMIZI}PostgreSQL servisi çalışmıyor!${NC}"
        return 1
    fi
    return 0
}

# Ana menü
main_menu() {
    clear
    echo -e "${MAVI}=== PostgreSQL Güvenlik Yapılandırması ===${NC}"
    echo "1. PostgreSQL'i internete kapat ve özel IP'lere izin ver"
    echo "2. Kimlik doğrulama ayarlarını yapılandır"
    echo "3. Kullanıcı yetkilerini kontrol et"
    echo "4. Harici program erişimini kısıtla"
    echo "5. Tüm güvenlik önlemlerini uygula"
    echo "6. Çıkış"
    echo -e "${SARI}Seçiminiz (1-6):${NC} "
    read secim
}

# IP listesini al
get_current_ips() {
    local listen_line=$(grep "^listen_addresses" "$POSTGRESQL_CONF" 2>/dev/null)
    if [ -z "$listen_line" ]; then
        listen_line=$(grep "^#listen_addresses" "$POSTGRESQL_CONF" 2>/dev/null)
    fi
    
    if [ -n "$listen_line" ]; then
        # listen_addresses satırından IP'leri ayıkla ve sırala
        echo "$listen_line" | sed -E "s/^#?listen_addresses *= *'(.*)'/\1/" | tr ',' '\n' | grep -v "^localhost$" | grep -v "^$" | sort -u
    fi
}

# IP'leri göster
show_ips() {
    echo -e "${MAVI}Mevcut IP Adresleri:${NC}"
    local ip_listesi=$(get_current_ips)
    if [ -n "$ip_listesi" ]; then
        echo "$ip_listesi" | nl -w2 -s') '
    else
        echo -e "${SARI}Henüz hiç IP adresi eklenmemiş.${NC}"
    fi
}

# IP doğrulama
validate_ip() {
    local ip=$1
    if ! [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        return 1
    fi
    
    # IP adresinin geçerli olup olmadığını kontrol et
    local IFS='.'
    read -ra ADDR <<< "$ip"
    for i in "${ADDR[@]}"; do
        if [ $i -lt 0 ] || [ $i -gt 255 ]; then
            return 1
        fi
    done
    return 0
}

# PostgreSQL yapılandırmasını güncelle
update_postgresql_config() {
    local yeni_liste=$1
    local yedek_al=${2:-true}
    
    # Yedek al (eğer isteniyorsa)
    if [ "$yedek_al" = true ]; then
        cp "$POSTGRESQL_CONF" "$POSTGRESQL_CONF.backup.$(date +%Y%m%d_%H%M%S)"
        if ! check_error "Yedekleme başarısız oldu"; then
            return 1
        fi
    fi
    
    # Yapılandırmayı güncelle
    sed -i "s/^#\?listen_addresses.*/listen_addresses = '$yeni_liste'/" "$POSTGRESQL_CONF"
    if ! check_error "listen_addresses ayarı değiştirilemedi"; then
        return 1
    fi
    
    # PostgreSQL'i yeniden başlat
    if ! systemctl restart postgresql; then
        echo -e "${KIRMIZI}PostgreSQL yeniden başlatılamadı!${NC}"
        return 1
    fi
    
    return 0
}

# IP yönetim menüsü
ip_management() {
    while true; do
        clear
        echo -e "${MAVI}=== IP Yönetimi ===${NC}"
        echo "1. IP Listesini Görüntüle"
        echo "2. Yeni IP Ekle"
        echo "3. IP Sil"
        echo "4. Ana Menüye Dön"
        echo -e "${SARI}Seçiminiz (1-5):${NC} "
        read ip_secim

        case $ip_secim in
            1)
                show_ips
                ;;
            2)
                echo -e "${SARI}Eklenecek IP adreslerini virgülle ayırarak girin:${NC}"
                read yeni_ipler
                
                # Her IP'yi doğrula
                local gecersiz_ip=0
                for ip in $(echo $yeni_ipler | tr ',' ' '); do
                    if ! validate_ip "$ip"; then
                        echo -e "${KIRMIZI}Geçersiz IP adresi: $ip${NC}"
                        gecersiz_ip=1
                        break
                    fi
                done
                
                if [ $gecersiz_ip -eq 0 ]; then
                    # Mevcut ve yeni IP'leri birleştir
                    local mevcut_ipler=$(get_current_ips | tr '\n' ',' | sed 's/,$//')
                    local tum_ipler="localhost"
                    
                    if [ -n "$mevcut_ipler" ]; then
                        tum_ipler="$tum_ipler,$mevcut_ipler"
                    fi
                    if [ -n "$yeni_ipler" ]; then
                        tum_ipler="$tum_ipler,$yeni_ipler"
                    fi
                    
                    # Tekrar eden IP'leri temizle ve sırala
                    tum_ipler=$(echo "$tum_ipler" | tr ',' '\n' | sort -u | tr '\n' ',' | sed 's/,$//')
                    
                    if update_postgresql_config "$tum_ipler"; then
                        echo -e "${YESIL}IP adresleri başarıyla eklendi.${NC}"
                    fi
                fi
                ;;
            3)
                show_ips
                if [ -n "$(get_current_ips)" ]; then
                    echo -e "${SARI}Silmek istediğiniz IP'nin numarasını girin (Birden fazla için virgülle ayırın):${NC}"
                    read silinecek_no
                    
                    local yeni_liste="localhost"
                    local mevcut_ipler=($(get_current_ips))
                    local silinecek_numaralar=($(echo $silinecek_no | tr ',' ' '))
                    local gecersiz_numara=0
                    
                    # Silinecek numaraları kontrol et
                    for num in "${silinecek_numaralar[@]}"; do
                        if ! [[ "$num" =~ ^[0-9]+$ ]] || [ "$num" -lt 1 ] || [ "$num" -gt ${#mevcut_ipler[@]} ]; then
                            echo -e "${KIRMIZI}Geçersiz numara: $num${NC}"
                            gecersiz_numara=1
                            break
                        fi
                    done
                    
                    if [ $gecersiz_numara -eq 0 ]; then
                        # IP'leri filtrele
                        for i in $(seq 1 ${#mevcut_ipler[@]}); do
                            if ! echo "${silinecek_numaralar[@]}" | grep -q -w "$i"; then
                                yeni_liste="$yeni_liste,${mevcut_ipler[$((i-1))]}"
                            fi
                        done
                        
                        if update_postgresql_config "$yeni_liste"; then
                            echo -e "${YESIL}Seçilen IP adres(ler)i başarıyla silindi.${NC}"
                        fi
                    fi
                fi
                ;;
            4)
                return 0
                ;;
            *)
                echo -e "${KIRMIZI}Geçersiz seçim!${NC}"
                ;;
        esac
        
        echo -e "${SARI}Devam etmek için bir tuşa basın...${NC}"
        read -n 1
    done
}

# PostgreSQL'i internete kapat ve özel IP'lere izin ver
close_internet() {
    echo -e "${MAVI}PostgreSQL'i internete kapatma işlemi başlatılıyor...${NC}"
    
    # PostgreSQL yapılandırma dosyalarını bul
    if ! find_postgresql_config; then
        return 1
    fi
    
    # postgresql.conf dosyasını yedekle
    cp "$POSTGRESQL_CONF" "$POSTGRESQL_CONF.backup"
    if ! check_error "Yedekleme başarısız oldu"; then
        return 1
    fi
    
    # IP yönetim menüsünü çağır
    ip_management
    
    return 0
}

# Kimlik doğrulama ayarlarını yapılandır
configure_authentication() {
    echo -e "${MAVI}Kimlik doğrulama ayarları yapılandırılıyor...${NC}"
    
    # PostgreSQL yapılandırma dosyalarını bul
    if ! find_postgresql_config; then
        return 1
    fi
    
    # pg_hba.conf dosyasını yedekle
    cp "$POSTGRESQL_HBA_CONF" "$POSTGRESQL_HBA_CONF.backup"
    if ! check_error "Yedekleme başarısız oldu"; then
        return 1
    fi
    
    # SCRAM-SHA-256 şifreleme ayarını etkinleştir
    sed -i "s/^#\?password_encryption.*/password_encryption = 'scram-sha-256'/" "$POSTGRESQL_CONF"
    if ! check_error "Şifreleme ayarı değiştirilemedi"; then
        return 1
    fi
    
    echo -e "${YESIL}Kimlik doğrulama ayarları güncellendi.${NC}"
    systemctl restart postgresql
    if ! check_error "PostgreSQL yeniden başlatılamadı"; then
        return 1
    fi
    
    return 0
}

# Kullanıcı yetkilerini listele
list_permissions() {
    local kullanici=$1
    echo -e "${MAVI}=== Kullanıcı Yetkileri ===${NC}"
    
    # Geçici olarak HOME dizinini değiştir
    local OLD_HOME=$HOME
    export HOME=/var/lib/postgresql
    
    if [ -n "$kullanici" ]; then
        echo -e "${SARI}$kullanici kullanıcısının yetkileri:${NC}"
        if ! sudo -u postgres psql -c "
            SELECT 
                r.rolname as kullanici,
                CASE WHEN r.rolsuper THEN 'Evet' ELSE 'Hayır' END as super_kullanici,
                CASE WHEN r.rolcreatedb THEN 'Evet' ELSE 'Hayır' END as veritabani_olusturabilir,
                CASE WHEN r.rolcreaterole THEN 'Evet' ELSE 'Hayır' END as rol_olusturabilir,
                CASE WHEN r.rolreplication THEN 'Evet' ELSE 'Hayır' END as replikasyon,
                CASE WHEN r.rolbypassrls THEN 'Evet' ELSE 'Hayır' END as rls_bypass,
                CASE WHEN r.rolcanlogin THEN 'Evet' ELSE 'Hayır' END as giris_yapabilir
            FROM pg_roles r 
            WHERE r.rolname = '$kullanici';" 2>/dev/null; then
            echo -e "${KIRMIZI}Kullanıcı bilgileri alınamadı!${NC}"
            export HOME=$OLD_HOME
            return 1
        fi
    else
        echo -e "${SARI}Tüm kullanıcıların yetkileri:${NC}"
        if ! sudo -u postgres psql -c "
            SELECT 
                r.rolname as kullanici,
                CASE WHEN r.rolsuper THEN 'Evet' ELSE 'Hayır' END as super_kullanici,
                CASE WHEN r.rolcreatedb THEN 'Evet' ELSE 'Hayır' END as veritabani_olusturabilir,
                CASE WHEN r.rolcreaterole THEN 'Evet' ELSE 'Hayır' END as rol_olusturabilir,
                CASE WHEN r.rolreplication THEN 'Evet' ELSE 'Hayır' END as replikasyon,
                CASE WHEN r.rolbypassrls THEN 'Evet' ELSE 'Hayır' END as rls_bypass,
                CASE WHEN r.rolcanlogin THEN 'Evet' ELSE 'Hayır' END as giris_yapabilir
            FROM pg_roles r 
            ORDER BY r.rolname;" 2>/dev/null; then
            echo -e "${KIRMIZI}Kullanıcı listesi alınamadı!${NC}"
            export HOME=$OLD_HOME
            return 1
        fi
    fi
    
    # HOME dizinini eski haline getir
    export HOME=$OLD_HOME
    return 0
}

# Veritabanı yetkilerini listele
list_database_permissions() {
    local kullanici=$1
    local veritabani=$2
    
    echo -e "${MAVI}=== Veritabanı Yetkileri ===${NC}"
    
    if [ -n "$kullanici" ] && [ -n "$veritabani" ]; then
        echo -e "${SARI}$kullanici kullanıcısının $veritabani veritabanındaki yetkileri:${NC}"
        if ! sudo -u postgres psql -c "
            SELECT 
                has_database_privilege('$kullanici', '$veritabani', 'CREATE') as olusturma_yetkisi,
                has_database_privilege('$kullanici', '$veritabani', 'CONNECT') as baglanti_yetkisi,
                has_database_privilege('$kullanici', '$veritabani', 'TEMPORARY') as gecici_tablo_yetkisi;"; then
            echo -e "${KIRMIZI}Veritabanı yetkileri alınamadı!${NC}"
            return 1
        fi
    else
        echo -e "${SARI}Tüm veritabanlarındaki yetkiler:${NC}"
        if ! sudo -u postgres psql -c "
            SELECT 
                grantee as kullanici, 
                table_catalog as veritabani,
                string_agg(privilege_type, ', ') as yetkiler
            FROM information_schema.role_table_grants 
            GROUP BY grantee, table_catalog 
            ORDER BY grantee, table_catalog;"; then
            echo -e "${KIRMIZI}Veritabanı yetkileri listesi alınamadı!${NC}"
            return 1
        fi
    fi
    
    return 0
}

# Yetki yönetimi menüsü
permission_management() {
    while true; do
        clear
        echo -e "${MAVI}=== Yetki Yönetimi ===${NC}"
        echo "1. Tüm Kullanıcıların Yetkilerini Görüntüle"
        echo "2. Belirli Bir Kullanıcının Yetkilerini Görüntüle"
        echo "3. Veritabanı Yetkilerini Görüntüle"
        echo "4. Çoklu Yetki Ver"
        echo "5. Çoklu Yetki Al"
        echo "6. Kullanıcı Oluştur"
        echo "7. Kullanıcı Sil"
        echo "8. Ana Menüye Dön"
        echo -e "${SARI}Seçiminiz (1-8):${NC} "
        read yetki_secim

        case $yetki_secim in
            1)
                list_permissions
                ;;
            2)
                echo -e "${SARI}Kullanıcı adını girin:${NC}"
                read kullanici
                list_permissions "$kullanici"
                ;;
            3)
                echo -e "${SARI}Kullanıcı adını girin (tüm kullanıcılar için boş bırakın):${NC}"
                read kullanici
                echo -e "${SARI}Veritabanı adını girin (tüm veritabanları için boş bırakın):${NC}"
                read veritabani
                list_database_permissions "$kullanici" "$veritabani"
                ;;
            4)
                echo -e "${MAVI}=== Çoklu Yetki Verme ===${NC}"
                echo -e "${SARI}Kullanıcı adını girin:${NC}"
                read kullanici
                
                echo -e "${SARI}Vermek istediğiniz yetkileri seçin (birden fazla seçmek için numaraları virgülle ayırın):${NC}"
                echo "1. SUPERUSER - Süper kullanıcı yetkisi"
                echo "2. CREATEDB - Veritabanı oluşturma yetkisi"
                echo "3. CREATEROLE - Rol oluşturma yetkisi"
                echo "4. REPLICATION - Replikasyon yetkisi"
                echo "5. BYPASSRLS - Row Level Security bypass yetkisi"
                echo "6. LOGIN - Giriş yapabilme yetkisi"
                echo "7. INHERIT - Üye olduğu rollerden yetki kalıtımı"
                echo "8. NOPASSWORD - Şifresiz giriş"
                read -p "Seçimleriniz: " secimler
                
                yetkiler=""
                IFS=',' read -ra SECIM_ARRAY <<< "$secimler"
                for secim in "${SECIM_ARRAY[@]}"; do
                    case $secim in
                        1) yetkiler="$yetkiler SUPERUSER" ;;
                        2) yetkiler="$yetkiler CREATEDB" ;;
                        3) yetkiler="$yetkiler CREATEROLE" ;;
                        4) yetkiler="$yetkiler REPLICATION" ;;
                        5) yetkiler="$yetkiler BYPASSRLS" ;;
                        6) yetkiler="$yetkiler LOGIN" ;;
                        7) yetkiler="$yetkiler INHERIT" ;;
                        8) yetkiler="$yetkiler NOPASSWORD" ;;
                        *) 
                            echo -e "${KIRMIZI}Geçersiz seçim: $secim${NC}"
                            continue 2
                            ;;
                    esac
                done
                
                echo -e "${SARI}Verilecek yetkiler:${NC} ${yetkiler# }"
                echo -e "${SARI}Onaylıyor musunuz? (E/H)${NC}"
                read onay
                if [[ $onay =~ ^[Ee]$ ]]; then
                    if ! sudo -u postgres psql -c "ALTER ROLE $kullanici WITH $yetkiler;"; then
                        echo -e "${KIRMIZI}Yetki verme işlemi başarısız oldu!${NC}"
                    else
                        echo -e "${YESIL}Yetkiler başarıyla verildi.${NC}"
                        list_permissions "$kullanici"
                    fi
                fi
                ;;
            5)
                echo -e "${MAVI}=== Çoklu Yetki Alma ===${NC}"
                echo -e "${SARI}Kullanıcı adını girin:${NC}"
                read kullanici
                
                echo -e "${SARI}Almak istediğiniz yetkileri seçin (birden fazla seçmek için numaraları virgülle ayırın):${NC}"
                echo "1. SUPERUSER - Süper kullanıcı yetkisi"
                echo "2. CREATEDB - Veritabanı oluşturma yetkisi"
                echo "3. CREATEROLE - Rol oluşturma yetkisi"
                echo "4. REPLICATION - Replikasyon yetkisi"
                echo "5. BYPASSRLS - Row Level Security bypass yetkisi"
                echo "6. LOGIN - Giriş yapabilme yetkisi"
                echo "7. INHERIT - Üye olduğu rollerden yetki kalıtımı"
                read -p "Seçimleriniz: " secimler
                
                yetkiler=""
                IFS=',' read -ra SECIM_ARRAY <<< "$secimler"
                for secim in "${SECIM_ARRAY[@]}"; do
                    case $secim in
                        1) yetkiler="$yetkiler NOSUPERUSER" ;;
                        2) yetkiler="$yetkiler NOCREATEDB" ;;
                        3) yetkiler="$yetkiler NOCREATEROLE" ;;
                        4) yetkiler="$yetkiler NOREPLICATION" ;;
                        5) yetkiler="$yetkiler NOBYPASSRLS" ;;
                        6) yetkiler="$yetkiler NOLOGIN" ;;
                        7) yetkiler="$yetkiler NOINHERIT" ;;
                        *) 
                            echo -e "${KIRMIZI}Geçersiz seçim: $secim${NC}"
                            continue 2
                            ;;
                    esac
                done
                
                echo -e "${SARI}Alınacak yetkiler:${NC} ${yetkiler# }"
                echo -e "${SARI}Onaylıyor musunuz? (E/H)${NC}"
                read onay
                if [[ $onay =~ ^[Ee]$ ]]; then
                    if ! sudo -u postgres psql -c "ALTER ROLE $kullanici WITH $yetkiler;"; then
                        echo -e "${KIRMIZI}Yetki alma işlemi başarısız oldu!${NC}"
                    else
                        echo -e "${YESIL}Yetkiler başarıyla alındı.${NC}"
                        list_permissions "$kullanici"
                    fi
                fi
                ;;
            6)
                echo -e "${MAVI}=== Kullanıcı Oluşturma ===${NC}"
                echo -e "${SARI}Yeni kullanıcı adını girin:${NC}"
                read yeni_kullanici
                echo -e "${SARI}Şifre girin:${NC}"
                read -s sifre
                echo
                
                if ! sudo -u postgres psql -c "CREATE ROLE $yeni_kullanici WITH LOGIN PASSWORD '$sifre';"; then
                    echo -e "${KIRMIZI}Kullanıcı oluşturma başarısız oldu!${NC}"
                else
                    echo -e "${YESIL}Kullanıcı başarıyla oluşturuldu.${NC}"
                fi
                ;;
            7)
                echo -e "${MAVI}=== Kullanıcı Silme ===${NC}"
                echo -e "${SARI}Silinecek kullanıcı adını girin:${NC}"
                read silinecek_kullanici
                
                echo -e "${KIRMIZI}DİKKAT: Bu işlem geri alınamaz! Devam etmek istiyor musunuz? (E/H)${NC}"
                read onay
                if [[ $onay =~ ^[Ee]$ ]]; then
                    if ! sudo -u postgres psql -c "DROP ROLE $silinecek_kullanici;"; then
                        echo -e "${KIRMIZI}Kullanıcı silme işlemi başarısız oldu!${NC}"
                    else
                        echo -e "${YESIL}Kullanıcı başarıyla silindi.${NC}"
                    fi
                fi
                ;;
            8)
                return 0
                ;;
            *)
                echo -e "${KIRMIZI}Geçersiz seçim!${NC}"
                ;;
        esac
        
        echo -e "${SARI}Devam etmek için bir tuşa basın...${NC}"
        read -n 1
    done
}

# Ana kullanıcı yetkileri fonksiyonu
user_permissions() {
    echo -e "${MAVI}Kullanıcı yetkileri yönetimi başlatılıyor...${NC}"
    permission_management
    return $?
}

# Harici program erişimini kısıtla
restrict_external_programs() {
    echo -e "${MAVI}Harici program erişimi kısıtlanıyor...${NC}"
    
    # pg_execute_server_program yetkisine sahip kullanıcıları listele
    echo -e "${SARI}Harici program çalıştırma yetkisi olan kullanıcılar:${NC}"
    if ! sudo -u postgres psql -c "SELECT u.rolname FROM pg_roles u JOIN pg_auth_members m ON u.oid = m.member JOIN pg_roles r ON m.roleid = r.oid WHERE r.rolname = 'pg_execute_server_program';"; then
        echo -e "${KIRMIZI}Kullanıcı listesi alınamadı!${NC}"
        return 1
    fi
    
    # Yetkiyi kaldırma seçeneği
    echo -e "${SARI}Bu yetkiyi kaldırmak ister misiniz? (E/H)${NC}"
    read cevap
    if [[ $cevap =~ ^[Ee]$ ]]; then
        echo "Kullanıcı adını girin:"
        read kullanici
        if ! sudo -u postgres psql -c "REVOKE pg_execute_server_program FROM $kullanici;"; then
            echo -e "${KIRMIZI}Yetki kaldırma işlemi başarısız oldu!${NC}"
            return 1
        fi
    fi
    
    return 0
}

# Ana program döngüsü
while true; do
    if ! check_postgresql; then
        echo -e "${KIRMIZI}PostgreSQL servisi çalışmıyor. Program sonlandırılıyor...${NC}"
        exit 1
    fi
    
    main_menu
    
    case $secim in
        1) 
            if ! close_internet; then
                echo -e "${KIRMIZI}İşlem başarısız oldu. Devam etmek için bir tuşa basın...${NC}"
                read -n 1
                continue
            fi
            ;;
        2) 
            if ! configure_authentication; then
                echo -e "${KIRMIZI}İşlem başarısız oldu. Devam etmek için bir tuşa basın...${NC}"
                read -n 1
                continue
            fi
            ;;
        3) 
            if ! user_permissions; then
                echo -e "${KIRMIZI}İşlem başarısız oldu. Devam etmek için bir tuşa basın...${NC}"
                read -n 1
                continue
            fi
            ;;
        4) 
            if ! restrict_external_programs; then
                echo -e "${KIRMIZI}İşlem başarısız oldu. Devam etmek için bir tuşa basın...${NC}"
                read -n 1
                continue
            fi
            ;;
        5)
            if ! close_internet || ! configure_authentication || ! user_permissions || ! restrict_external_programs; then
                echo -e "${KIRMIZI}Bazı işlemler başarısız oldu. Devam etmek için bir tuşa basın...${NC}"
                read -n 1
                continue
            fi
            ;;
        6)
            echo -e "${YESIL}Program sonlandırılıyor...${NC}"
            exit 0
            ;;
        *)
            echo -e "${KIRMIZI}Geçersiz seçim!${NC}"
            sleep 2
            ;;
    esac
    
    echo -e "${SARI}Devam etmek için bir tuşa basın...${NC}"
    read -n 1
done 