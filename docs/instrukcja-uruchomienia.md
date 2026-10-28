<!-- Instrukcja dla użytkownika: przygotowanie Windows, Gmail, instalacja, sprawdzenie działania i zmiana odbiorcy. -->

# OSO — uruchomienie na Windows 11

Instrukcja opisuje pierwszą instalację usługi monitorującej logowania. Wszystkie kroki wykonuj wewnątrz maszyny wirtualnej z Windows 11.

## Wymagania

- Windows 11 x64 i konto z uprawnieniami administratora.
- [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0) do zbudowania aplikacji. Sam pakiet Runtime nie wystarczy.
- Windows PowerShell 5.1. Skrypty instalacyjne korzystają z poleceń dostępnych w tej wersji.
- Konto Gmail nadawcy z włączoną weryfikacją dwuetapową i hasłem aplikacji.
- Połączenie z internetem do pobrania zależności oraz dostęp do `smtp.gmail.com` na porcie TCP `587` do wysyłania alertów.

## 1. Pobranie projektu i przygotowanie PowerShell

Pobierz [repozytorium OSO](https://github.com/noname6962/OSO) przez **Code → Download ZIP**. Rozpakuj zawartość do `C:\OSO`. W tym katalogu powinny znajdować się między innymi foldery `scripts` i `src`.

Zainstaluj .NET 10 SDK, a następnie otwórz **Windows PowerShell jako administrator**. Jeśli PowerShell był otwarty podczas instalacji SDK, zamknij go i uruchom ponownie.

Przejdź do katalogu projektu i sprawdź wersję SDK:

```powershell
cd C:\OSO
dotnet --version
```

Wersja SDK powinna zaczynać się od `10.`. Jeśli masz kilka wersji SDK, plik `global.json` w projekcie wybiera wersję z linii .NET 10.

Zezwól na uruchamianie lokalnych skryptów w bieżącym oknie:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
```

Jeśli pojawi się pytanie o zatwierdzenie, wybierz `Y`. Ustawienie wygasa po zamknięciu tego okna PowerShell.

Jeśli pobrane pliki są blokowane komunikatem o braku podpisu, odblokuj skrypty ze sprawdzonego repozytorium:

```powershell
Get-ChildItem C:\OSO\scripts\*.ps1 | Unblock-File
```

## 2. Zbudowanie aplikacji

W tym samym oknie uruchom:

```powershell
.\scripts\Publish.ps1
```

Po zakończeniu w katalogu `C:\OSO\artifacts\service` powinien znajdować się plik `Oso.Service.exe` wraz z pozostałymi plikami aplikacji. Nie przenoś samego pliku EXE — do działania potrzebuje całej zawartości tego katalogu.

Jeśli polecenie zakończy się błędem, rozwiąż go przed instalacją usługi.

## 3. Włączenie rejestrowania zdarzeń Windows

Uruchom poniższe polecenia w PowerShell jako administrator. Identyfikatory podkategorii są niezależne od języka Windows.

```powershell
# Logowanie: sukcesy i niepowodzenia (4624, 4625).
auditpol /set /subcategory:"{0cce9215-69ae-11d9-bed3-505054503030}" /success:enable /failure:enable

# Wylogowanie (4634, 4647).
auditpol /set /subcategory:"{0cce9216-69ae-11d9-bed3-505054503030}" /success:enable

# Specjalne logowanie — przyznanie specjalnych uprawnień (4672).
auditpol /set /subcategory:"{0cce921b-69ae-11d9-bed3-505054503030}" /success:enable
```

Program odczytuje zdarzenia zapisane przez Windows. Samo uruchomienie usługi nie włącza powyższych zasad inspekcji.

## 4. Konfiguracja konta Gmail

Na koncie, z którego mają wychodzić alerty:

1. Włącz weryfikację dwuetapową w ustawieniach konta Google.
2. Utwórz [hasło aplikacji](https://myaccount.google.com/apppasswords) dla OSO. Niektóre konta zarządzane przez organizację nie udostępniają tej opcji.
3. W PowerShell na maszynie wirtualnej uruchom:

```powershell
.\scripts\Set-GmailCredential.ps1
```

Gdy skrypt zapyta o hasło, wpisz hasło aplikacji Google, a nie zwykłe hasło do konta Gmail. Wpisywane znaki nie będą widoczne.

Hasło zostanie zapisane w postaci zaszyfrowanej w `C:\ProgramData\OSO\gmail-password.bin`. Plik jest związany z tą maszyną — nie kopiuj go z innego komputera. Nie wpisuj hasła do konfiguracji JSON.

Jeśli hasło zostało już zapisane i chcesz je zmienić, użyj:

```powershell
.\scripts\Set-GmailCredential.ps1 -ReplaceExisting
```

## 5. Instalacja i uruchomienie usługi

Podaj adres Gmail nadawcy oraz adres odbiorcy alertów:

```powershell
.\scripts\Install-Service.ps1 -GmailAddress "nadawca@gmail.com" -Recipient "odbiorca@example.com"
```

- `-GmailAddress` — konto Gmail, dla którego zapisano hasło aplikacji.
- `-Recipient` — adres, na który mają trafiać alerty. Nie musi to być Gmail.

Instalator skopiuje aplikację do `C:\Program Files\OSO`, utworzy dziennik `OSO-Warnings`, zarejestruje usługę `OsoLoginMonitor` i od razu ją uruchomi. Usługa będzie startować automatycznie razem z Windowsem i działać w tle po zamknięciu PowerShell.

To polecenie służy do pierwszej instalacji. Jeśli usługa już istnieje, nie uruchamiaj instalatora ponownie tylko po to, żeby zmienić odbiorcę — sposób zmiany adresu opisano w kroku 7.

## 6. Sprawdzenie działania

Sprawdź stan usługi:

```powershell
Get-Service OsoLoginMonitor
```

Oczekiwany stan to `Running`. Jeśli usługa została wcześniej zatrzymana, uruchom ją:

```powershell
Start-Service OsoLoginMonitor
```

Do sprawdzenia alertów użyj konta testowego. Domyślny próg to pięć nieudanych logowań na to samo konto w ciągu pięciu minut. Przed testem sprawdź politykę blokowania konta, żeby nie zablokować sobie dostępu do VM.

Po wygenerowaniu zdarzeń sprawdź ostrzeżenia:

```powershell
Get-WinEvent -FilterHashtable @{ LogName = 'OSO-Warnings'; Id = 1000 } -MaxEvents 10
```

Sprawdź również skrzynkę odbiorcy, w tym folder Spam. Przed pierwszym alertem polecenie może zgłosić brak pasujących zdarzeń — nie oznacza to błędu instalacji.

Stan `Running` potwierdza uruchomienie usługi, ale dopiero ostrzeżenie i otrzymany e-mail potwierdzają działanie całej ścieżki. Program nie grupuje alertów: kolejne zdarzenia spełniające regułę mogą powodować kolejne wiadomości.

Jeśli uruchomienie się nie powiedzie, sprawdź konfigurację poleceniem:

```powershell
& "C:\Program Files\OSO\Oso.Service.exe" --validate-config
```

Sprawdza ono lokalną konfigurację, odszyfrowanie hasła i dostęp do dziennika Security. Nie testuje połączenia z Gmailem. Szczegółowe błędy usługi można odczytać poleceniem:

```powershell
Get-WinEvent -LogName 'OSO-Warnings' -MaxEvents 20
```

## 7. Zmiana adresu odbiorcy

W PowerShell uruchomionym jako administrator otwórz konfigurację:

```powershell
notepad "C:\Program Files\OSO\appsettings.Local.json"
```

W sekcji `Smtp` zmień wartość `Recipient`. Pozostałe ustawienia pozostaw bez zmian. Zapisz plik i zrestartuj usługę:

```powershell
Restart-Service OsoLoginMonitor
```

## Zatrzymanie usługi

```powershell
Stop-Service OsoLoginMonitor
```

Zatrzymanie nie usuwa zapisanych ostrzeżeń ani konfiguracji. Aby wznowić działanie, użyj `Start-Service OsoLoginMonitor`.
