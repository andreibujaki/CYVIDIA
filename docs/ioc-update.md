# IOC and advisory pack updates

## Packs

| File | Role |
|------|------|
| `iocs/sansar.json` | REF3364 / SANSAR hashes, paths, network IOCs |
| `iocs/tor-miners.json` | Pluggable Tor-linked miner families |
| `iocs/nvidia-cves.json` | NVIDIA driver CVE advisory rows |
| `iocs/correlation.rules.json` | Finding correlation rules |
| `iocs/pack-manifest.json` | Versions + SHA-256 of each pack file |

## Update procedure

1. Edit the relevant pack file.
2. Bump that pack’s `pack_version` / `advisory_pack_version` / `version` field.
3. Recompute file SHA-256 values and refresh `iocs/pack-manifest.json`.
4. Note sources (Elastic REF3364, NVIDIA bulletins, NVD) in the PR/commit message.
5. Run `pytest` and fixture hunts.
6. Do **not** add live malware samples to the repo.

## Computing manifest hashes

On Linux:

```bash
sha256sum iocs/sansar.json iocs/tor-miners.json iocs/nvidia-cves.json iocs/correlation.rules.json
```

Or:

```bash
python3 -c "import hashlib,pathlib,json; root=pathlib.Path('iocs'); files=['sansar.json','tor-miners.json','nvidia-cves.json','correlation.rules.json']; packs=[]; 
for n in files:
 p=root/n; h=hashlib.sha256(p.read_bytes()).hexdigest();
 ver=json.loads(p.read_text()).get('pack_version') or json.loads(p.read_text()).get('advisory_pack_version') or json.loads(p.read_text()).get('version');
 packs.append({'name':n,'version':ver,'sha256':h});
print(json.dumps({'manifest_version':'0.1.0','packs':packs},indent=2))"
```
