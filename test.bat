@echo off
echo Tehdit Algılama Sistemi testi başlatılıyor...

REM Gerekli kütüphaneleri yükleyin
pip install numpy scikit-learn joblib pillow pystray

REM Python programını arka planda çalıştırın ve çıktısını bir dosyaya yönlendirin
start /B python ai_threat_detection_system.py > output.txt

REM Programın başlaması ve ilk analizleri yapması için biraz bekleyin
timeout /t 15 /nobreak

REM Çıktıyı kontrol edin
findstr /C:"Sonuç:" output.txt > nul
if %errorlevel% equ 0 (
    echo Test başarılı: Program çalışıyor ve detaylı tehdit analizleri yapılıyor.
    echo Son 5 analiz sonucu:
    findstr /C:"Zaman:" /C:"Sonuç:" /C:"Tehdit Olasılığı:" output.txt
) else (
    echo Test başarısız: Program düzgün çalışmıyor veya analiz sonuçları üretmiyor.
    echo Hata mesajları:
    findstr /C:"Error" /C:"Exception" output.txt
)

REM Programı kapatın
taskkill /F /IM python.exe

echo Test tamamlandı.
pause
