/*
  Cleaned derivative patterns inspired by Elastic Security Labs public YARA for
  Linux.Trojan.Sansar / Linux.Trojan.Netns. Not unmodified Elastic product files.
  See ATTRIBUTION.md.
*/

rule CYVIDIA_Linux_Trojan_Sansar_derivative {
    meta:
        author = "CYVIDIA"
        description = "Derivative hex pattern for Sansar-class samples"
        threat_name = "Linux.Trojan.Sansar"
    strings:
        $a1 = { 8A 0A 88 4C 24 ?? 44 8A 5C 24 ?? 8D 48 01 44 89 DB D2 EB 34 07 89 C1 41 D2 E3 41 08 DB 89 F0 83 E0 1F 46 32 1C 10 44 88 1C 37 48 FF C6 48 FF C2 }
    condition:
        all of them
}

rule CYVIDIA_Linux_Trojan_Netns_derivative {
    meta:
        author = "CYVIDIA"
        description = "Derivative hex pattern for Netns-class samples"
        threat_name = "Linux.Trojan.Netns"
    strings:
        $a1 = { 66 89 85 ?? ?? ?? ?? 48 C7 85 ?? ?? ?? ?? 08 07 00 00 48 C7 85 ?? ?? ?? ?? 00 00 00 00 48 8D 95 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 41 B8 10 00 00 00 48 89 D1 BA 14 00 00 00 BE 01 00 00 00 89 C7 E8 ?? ?? ?? ?? }
    condition:
        all of them
}
