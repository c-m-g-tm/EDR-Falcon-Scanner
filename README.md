# EDR-Falcon-Scanner

EDR Scanner (Crownstrike) Beta Windows Version by (c) www.c-m-g.de  Meier Thomas

 NORMAL ist im Code das Standard-Risiko-Level (riskLevel = "NORMAL") für jeden Prozess, der keine Heuristik-Regel trifft — also ein ganz gewöhnlicher Programmstart ohne Auffälligkeit. Erst wenn eine Regel zutrifft, wird der Wert überschrieben:

    NORMAL — unverdächtiger Prozess (z. B. notepad.exe)
    WARNUNG (Konsole gestartet) — cmd/powershell/pwsh gestartet
    KRITISCH (Blockiert) — calc.exe erkannt
    ABGEWEHRT — Prozess wurde gekillt
    INFO — EDR-interne Meldungen (Start/Stop der Engine)

Der Wert wird nur angezeigt, im Grid unter "Risiko-Level"; es passiert bei NORMAL keine Aktion.

Hinweis: WMI-Ereignisse brauchen Administratorrechte, sonst startet der Watcher nicht.
Zusammenfassung - Inhalt des Programmes
1. Sensoren (Überwachung)

BereichUmsetzungDateiProzesse (primär)ETW-Kernel-Provider (Process + FileIO Keywords, TraceEvent)Services/EtwMonitor.csProzesse (Fallback)WMI __InstanceCreationEvent auf Win32_ProcessServices/ProcessMonitor.csDateisystemFileSystemWatcher Dokumente/Desktop/Bilder, Ransomware-Burst + Endungs-/Note-HeuristikServices/FileSystemMonitor.csNetzwerkGetExtendedTcpTable mit PID-Zuordnung, alle 5 s, Loopback/Listener gefiltertServices/TcpTableReader.cs, NetworkMonitor.csRegistryAutostart-Schlüssel (Run/RunOnce HKCU/HKLM), alle 5 sServices/RegistryMonitor.cs
2. Detektion

    Eingebaute Heuristik (Services/RuleEngine.cs): CommandLine-Muster, verdächtige Pfade (TEMP/Downloads/Public/ProgramData), Namens-Maskerade, doppelte Endungen, Office→Shell/Parent-Child
    Sigma-Regel-Engine (Services/Detection/SigmaEngine.cs): YAML laden, Modifier contains/startswith/endswith/re/all, Wildcards, Bedingungen and/or/not, 1 of, all of; 5 Regeln in rules/
    MITRE ATT&CK-Mapping (Services/Detection/AttackMap.cs): 35 Techniken (Name + Tactic), an jeder Regel/Erkennung
    Signaturprüfung via WinVerifyTrust (Services/SignatureChecker.cs), SHA256-Hash (Services/Hasher.cs), CommandLine/Parent-Prozess (Services/ProcessInspector.cs)

3. Prävention

    Prozess-Kill bei kritischen Treffern + Auto-Block (umschaltbar)
    Quarantäne-Tresor (Services/QuarantineVault.cs): AES-256-GCM, Schlüssel per DPAPI, ACL-Härtung, Restore/Verify(SHA256)/Delete
    Host-Containment (Services/ContainmentService.cs): Firewall-Regeln blockieren ausgehend, LAN/DNS erlaubt

4. Tool-Sicherheit

    Audit-Log mit SHA256-Hash-Kette (Services/AuditLogger.cs) + Integritätsprüfung erkennt Manipulation
    Ausnahmeliste mit Selbstschutz (Services/ExclusionList.cs, eigene App + Systemprozesse)

5. GUI (MainWindow.xaml / .xaml.cs)

    Tabs: Ereignisse, Ausnahmen, Quarantäne, ATT&CK Matrix, Sicherheit/Audit, Systemstatus
    Live-Grid mit Zeilenfarben je Risiko, Volltextfilter + Stufenfilter, Live-Statistik (Events/Warnung/Kritisch), Technik-Spalte
    Kontextmenü: Details kopieren, beenden, suspendieren, fortsetzen, Ausnahme, in Quarantäne
    Tooltip mit Pfad/Hash/Signatur/Kommandozeile, Tray-Balloon bei kritischen Events
    ATT&CK-Heatmap (Zähler + Balken), Sensor-Status (ETW/WMI + Sigma-Anzahl)

6. Verifikation

    19 automatisierte Logik-Tests (RuleEngine, Sigma, ATT&CK, Quarantäne-Verschlüsselung/-Manipulation) — alle grün
    Live-Lauf bestätigt: Audit-Log enthält 2.564 echte Ereignisse aus deinem System

Zukunft

Noch offen (diskutiert, nicht umgesetzt): Cloud-Zentralserver/Multi-Host-Management, Alert-Triage-Workflow (Status/Zuweisung/Kommentare), YARA-Speicherscan, AMSI-Konsument, Kernel-Minifilter, echter Windows-Dienst. 
