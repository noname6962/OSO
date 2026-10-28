<!-- Ten plik. Mapa kodu i odpowiedzialność poszczególnych plików. -->

# Struktura projektu OSO

Dwa projekty. `Oso.Core` zawiera logikę przetwarzania zdarzeń i alertów. `Oso.Service` podłącza ją do Windows, uruchamia w tle i obsługuje wysyłkę przez Gmail.

Czytanie kodu zacznij od `Program.cs`, potem przejdź do `MonitorWorker.cs`. Tam widać, jak całość jest połączona.

## Układ katalogów

```text
OSO/
├── .gitignore
├── Directory.Build.props
├── global.json
├── README.md
├── docs/
│   ├── instrukcja-uruchomienia.md
│   ├── struktura-projektu.md
│   ├── validation-results.md
│   └── windows-validation.md
├── scripts/
│   ├── Install-Service.ps1
│   ├── PrivateAcl.ps1
│   ├── Publish.ps1
│   ├── Set-GmailCredential.ps1
│   └── Uninstall-Service.ps1
└── src/
    ├── Oso.Core/
    │   ├── AlertFormatter.cs
    │   ├── DurableReporter.cs
    │   ├── EventParser.cs
    │   ├── LoginAnalyzer.cs
    │   ├── Models.cs
    │   ├── Oso.Core.csproj
    │   └── packages.lock.json
    └── Oso.Service/
        ├── appsettings.json
        ├── GmailEmailSink.cs
        ├── MonitorWorker.cs
        ├── Oso.Service.csproj
        ├── packages.lock.json
        ├── Program.cs
        ├── ServiceOptions.cs
        ├── WindowsCollector.cs
        └── WindowsWarningSink.cs
```

## Przepływ danych

```text
Windows Security
    ↓
WindowsCollector + EventParser       moduł 1: zbieranie i odczyt pól
    ↓ kolejka zdarzeń
LoginAnalyzer                       moduł 2: reguły i powiązane zdarzenia
    ↓ alert zapisany przez FileOutbox
DurableReporter + AlertFormatter     moduł 3: przygotowanie i dostarczenie
    ├── WindowsWarningSink → dziennik OSO-Warnings
    └── GmailEmailSink     → e-mail z załącznikiem XML
```

`MonitorWorker` uruchamia zbieranie, analizę i dostarczanie jako trzy osobne pętle asynchroniczne w jednym procesie. Problem z Gmailem nie zatrzymuje odczytu logów; alert czeka na dysku na ponowną wysyłkę.

Moduły są podzielone według odpowiedzialności. Nie odpowiadają trzem osobnym projektom ani usługom Windows.

## Pliki w katalogu głównym

| Plik | Co robi |
| --- | --- |
| `.gitignore` | Wyklucza z Gita wyniki kompilacji, paczki wdrożeniowe, lokalną konfigurację i pliki certyfikatów `.pfx`. |
| `Directory.Build.props` | Wspólne ustawienia kompilacji obu projektów: obsługa wartości null, automatyczne importy, ostrzeżenia jako błędy, lockfile zależności i docelowy runtime `win-x64`. |
| `global.json` | Wybiera SDK z linii .NET 10. Dopuszcza nowsze wydania SDK w obrębie tej samej wersji głównej i pobocznej. |
| `README.md` | Główny opis działania, reguł, budowania, instalacji i konfiguracji. |

## `src/Oso.Core` — logika aplikacji

Ten projekt nie odwołuje się bezpośrednio do API dzienników Windows ani do SMTP.

| Plik | Co robi |
| --- | --- |
| `Models.cs` | Wspólne struktury danych: `LoginEvent` to odczytane zdarzenie, `RuleMatch` to spełniona reguła z licznikami, a `SecurityAlert` to alert z dowodami. Zawiera też `DetectionOptions`, czyli progi i okna czasowe. Wylicza stały identyfikator alertu na podstawie zdarzenia. |
| `EventParser.cs` | Zamienia XML Windows na `LoginEvent`. Odczytuje konto, domenę, SID, IP, typ logowania i identyfikator sesji. Normalizuje nazwy i adresy, a brakujące pola zostawia jako brakujące. Zachowuje oryginalny XML. |
| `LoginAnalyzer.cs` | Sprawdza powtarzające się nieudane logowania, jeden IP atakujący wiele kont, wiele IP atakujących jedno konto i sukces po podejrzanych niepowodzeniach. Trzyma ostatnie zdarzenia w pamięci, usuwa stare i dołącza powiązane rekordy do alertu. Pomija ponowne odczytanie tego samego zdarzenia. |
| `AlertFormatter.cs` | Buduje czytelny opis alertu i XML z dowodami. Dzieli zbyt długie ostrzeżenia na ponumerowane wpisy, żeby zmieściły się w dzienniku Windows. |
| `DurableReporter.cs` | Zapis alertów na dysku, postęp dostarczania i ponawianie wysyłki. Najpierw zapisuje ostrzeżenie w Windows, potem wysyła e-mail. Po dostarczeniu usuwa z pliku treść dowodów, zostawiając tymczasowy znacznik zapobiegający powtórnej wysyłce po restarcie. |
| `Oso.Core.csproj` | Definicja biblioteki .NET 10. Pozostały projekt korzysta z niej przez referencję. |
| `packages.lock.json` | Wersje i sumy kontrolne zależności tego projektu. Utrzymuje go NuGet. |

W `DurableReporter.cs` jest kilka typów:

- `IWarningSink` i `IEmailSink` — interfejsy zapisu ostrzeżenia i wysyłki e-maila. Implementacje są w `Oso.Service`.
- `DeliveryRecord` — stan dostarczenia jednego alertu: zapisane części ostrzeżenia, próby wysyłki, termin kolejnej próby i potwierdzenie zakończenia.
- `FileOutbox` — obsługa plików JSON. Zapisuje przez plik tymczasowy, a potem podmienia właściwy plik, żeby przerwany zapis nie zostawił połowy dokumentu.
- `DurableReporter` — koordynuje zapis i wysyłkę. Po błędzie wydłuża odstęp między próbami, maksymalnie do pięciu minut.

## `src/Oso.Service` — uruchomienie i integracja z Windows

| Plik | Co robi |
| --- | --- |
| `Program.cs` | Punkt wejścia. Wczytuje konfigurację, sprawdza dostęp do Security, rejestrację dziennika ostrzeżeń i możliwość odszyfrowania hasła. Rejestruje zależności, zakłada blokadę drugiej instancji i uruchamia usługę. Obsługuje też `--validate-config`. |
| `MonitorWorker.cs` | Spina trzy moduły. Kolektor zapisuje do kolejki, analizator ją odczytuje, a osobna pętla dostarcza zapisane alerty. Obsługuje zatrzymanie i błędy pętli. Usuwa stare zdarzenia z pamięci również wtedy, gdy nie pojawiają się nowe. |
| `WindowsCollector.cs` | Odczytuje lokalny dziennik Security dla ID 4624, 4625, 4634, 4647 i 4672. Najpierw włącza obserwację nowych wpisów, potem odczytuje ostatnie dziesięć minut. Buforuje nowe zdarzenia podczas odczytu historii, żeby nie zostawić przerwy w monitorowaniu. |
| `WindowsWarningSink.cs` | Zapisuje przygotowaną treść do źródła `OsoLoginMonitor`, przypisanego do dziennika `OSO-Warnings`. Ostrzeżenia mają ID 1000. |
| `GmailEmailSink.cs` | Odszyfrowuje zapisane hasło aplikacji, łączy się z SMTP przez TLS i wysyła alert z załącznikiem XML. Błąd oddaje do `DurableReporter`, który zajmuje się ponowieniem. |
| `ServiceOptions.cs` | Klasy ustawień zapisu ostrzeżeń i SMTP oraz sprawdzanie ich poprawności. Nie przechowuje hasła wprost — tylko ścieżkę do zaszyfrowanego pliku. |
| `appsettings.json` | Domyślna konfiguracja: progi, czasy, nazwa dziennika, katalog danych, SMTP i poziomy logowania. Adresy nadawcy i odbiorcy uzupełnia instalator w osobnym pliku lokalnym. |
| `Oso.Service.csproj` | Definicja aplikacji dla Windows. Łączy ją z `Oso.Core` i bibliotekami do usług Windows, Event Log, szyfrowania oraz poczty. Wymusza poprawioną wersję pakietu kryptograficznego używanego przez zależności pocztowe. |
| `packages.lock.json` | Dokładne wersje i sumy kontrolne zależności usługi, w tym zależności pośrednich. Dzięki temu odtworzenie buildu nie wybiera przypadkowo innych wersji pakietów. |

## `scripts` — budowanie i instalacja

| Plik | Co robi |
| --- | --- |
| `Publish.ps1` | Buduje paczkę Windows x64 do `artifacts/service`. Dołącza runtime .NET, więc na maszynie uruchamiającej gotową paczkę nie trzeba go instalować osobno. |
| `Set-GmailCredential.ps1` | Pyta o hasło aplikacji Gmail i szyfruje je mechanizmem Windows DPAPI dla tej maszyny. Przygotowuje katalog danych i ogranicza dostęp do niego. Nadpisanie istniejącego hasła wymaga `-ReplaceExisting`. |
| `PrivateAcl.ps1` | Wspólna funkcja ustawiająca prawa do plików i katalogów. Zostawia dostęp kontu SYSTEM i administratorom. Korzystają z niej skrypty instalacji i konfiguracji hasła. |
| `Install-Service.ps1` | Kopiuje gotową paczkę, zapisuje lokalne ustawienia adresów, rejestruje dziennik i usługę. Ustawia automatyczny start oraz restart po awarii. Na końcu uruchamia usługę. Wymaga przygotowanego hasła i pustego katalogu instalacyjnego. |
| `Uninstall-Service.ps1` | Zatrzymuje usługę i usuwa jej rejestrację. Zostawia pliki aplikacji, ostrzeżenia, konfigurację, hasło i oczekujące alerty. |

## `docs` — dokumentacja

| Plik | Co zawiera |
| --- | --- |
| `instrukcja-uruchomienia.md` | Instrukcja dla użytkownika: przygotowanie Windows, Gmail, instalacja, sprawdzenie działania i zmiana odbiorcy. |
| `struktura-projektu.md` | Ten plik. Mapa kodu i odpowiedzialność poszczególnych plików. |
| `windows-validation.md` | Lista testów do wykonania na Windows 11: progi, logowania, wysyłka, restart i odzyskiwanie po błędach. |
| `validation-results.md` | Zapis wykonanych wcześniej sprawdzeń i ich ograniczeń. Wynik 36 testów dotyczy historycznej wersji sprzed usunięcia testów z repozytorium. |

## Pliki powstające podczas budowania i instalacji

Poniższe ścieżki odnoszą się do domyślnej konfiguracji na Windows.

| Ścieżka | Zawartość |
| --- | --- |
| `src/*/bin/`, `src/*/obj/` | Wyniki i pliki pośrednie kompilacji. Generowane przez .NET, pomijane przez Gita. |
| `artifacts/service/` | Gotowa paczka do instalacji: `Oso.Service.exe`, biblioteki, runtime i konfiguracja. Przenosi się cały katalog. |
| `C:\Program Files\OSO\` | Zainstalowana aplikacja wraz z bibliotekami i plikami runtime. |
| `C:\Program Files\OSO\appsettings.Local.json` | Lokalna konfiguracja nadpisująca domyślne ustawienia. Tutaj zmienia się odbiorcę w `Smtp.Recipient`. Po edycji trzeba zrestartować usługę. |
| `C:\ProgramData\OSO\gmail-password.bin` | Zaszyfrowane hasło aplikacji Gmail. Odszyfrowanie wymaga tej samej maszyny Windows. |
| `C:\ProgramData\OSO\.oso-state-directory` | Znacznik katalogu danych utworzonego przez skrypt konfiguracji hasła. Chroni przed przypadkową zmianą praw do obcego katalogu. |
| `C:\ProgramData\OSO\monitor.lock` | Otwarty z wyłącznym dostępem przez działającą usługę. Blokuje start drugiej instancji używającej tych samych danych. |
| `C:\ProgramData\OSO\outbox\<id-alertu>.json` | Alert oczekujący na dostarczenie albo metadane zakończonej wysyłki. Oczekujące rekordy zachowują dowody; zakończone mają usuniętą treść i są później sprzątane. |
| `C:\ProgramData\OSO\outbox\<id-alertu>.json.tmp` | Tymczasowy plik używany podczas zapisu stanu. Odczyt kolejki bierze pod uwagę tylko gotowe pliki `.json`. |

Same ostrzeżenia są w **Podglądzie zdarzeń → Dzienniki aplikacji i usług → OSO-Warnings**. `outbox` służy do obsługi dostarczania i ponowień; nie jest archiwum wszystkich ostrzeżeń.

## Gdzie szukać przy zmianach

- Progi i czasy: `appsettings.json`, sekcja `Detection`; na zainstalowanej VM można je nadpisać w `appsettings.Local.json`.
- Nowa reguła: `LoginAnalyzer.cs`.
- Nowy typ zdarzenia: `EventParser.cs` i mapowanie pól; filtr kolektora korzysta z `SupportedIds`.
- Wygląd ostrzeżenia lub treść wiadomości: `AlertFormatter.cs`; temat i załącznik wiadomości są w `GmailEmailSink.cs`.
- Problemy z odczytem Security: `WindowsCollector.cs` oraz zasady inspekcji i uprawnienia na VM.
- Problemy z wysyłką: `GmailEmailSink.cs`; harmonogram ponowień i stan dostarczenia są w `DurableReporter.cs`.

Zmienne środowiskowe z prefiksem `OSO_` mają pierwszeństwo przed plikami konfiguracji. Przykład: `OSO_Detection__FailureThreshold`. Ustawienia są wczytywane przy starcie usługi.
