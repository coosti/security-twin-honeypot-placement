import csv
import networkx as nx
import matplotlib.pyplot as plt
import re
import ipaddress
from collections import defaultdict
import json
import os
import asyncio
import aiohttp

# --- ASSET CLASSES ---
class Asset:
    def __init__(self, name, **kwargs): 
        self.name = name; 
        self.attributes = kwargs

    def __repr__(self): 
        return f"{self.__class__.__name__}(name='{self.name}')"

class Host(Asset):
    def __init__(self, name, **kwargs): 
        super().__init__(name, **kwargs)
        self.asset_score = kwargs.get('asset_score', 0.0)

class Software(Asset):
    def __init__(self, name, **kwargs):
        super().__init__(name, **kwargs)
        self.base_name = kwargs.get('base_name')
        self.version = kwargs.get('version')
        self.score = kwargs.get('score', 0.0)

class VirtualMachine(Host): pass

class Router(Asset):
    def __init__(self, name, **kwargs):
        super().__init__(name, **kwargs)

class CVEEnricher:
    def __init__(self, dt, api_key=None, cache_file='data/cve_cache.json'):
        self.graph = dt.graph
        self.assets = dt.assets
        self.api_key = api_key
        self.cache_file = cache_file
        self.cve_cache = self._load_cache()
        print(f"🔎 CVEEnricher inizializzato. Trovate {len(self.cve_cache)} voci nella cache locale.")

    def _load_cache(self):
        if os.path.exists(self.cache_file):
            with open(self.cache_file, 'r') as f: return json.load(f)
        return {}

    def _save_cache(self):
        with open(self.cache_file, 'w') as f: json.dump(self.cve_cache, f, indent=2)

    def _normalize_sw_name(self, name):
        return name.split('-')[0]

    async def _fetch_cve(self, session, sw_name, clean_version, original_key):
        """Executes a single asynchronous request to the NVD API."""
        if original_key in self.cve_cache:
            return original_key, self.cve_cache[original_key], '.'

        search_name = self._normalize_sw_name(sw_name)
        headers = {'apiKey': self.api_key} if self.api_key else {}
        query = f"keywordSearch={search_name} {clean_version}"
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?{query}"
        
        try:
            async with session.get(url, headers=headers, timeout=40) as response:
                response.raise_for_status()
                data = await response.json()
                vulnerabilities = []
                if 'vulnerabilities' in data:
                    for item in data['vulnerabilities']:
                        cve = item['cve']
                        score = -1.0
                        if 'cvssMetricV31' in cve['metrics']: score = cve['metrics']['cvssMetricV31'][0]['cvssData']['baseScore']
                        elif 'cvssMetricV2' in cve['metrics']: score = cve['metrics']['cvssMetricV2'][0]['cvssData']['baseScore']
                        vulnerabilities.append({'id': cve['id'], 'score': score})
                
                self.cve_cache[original_key] = vulnerabilities
                feedback_char = 'V' if vulnerabilities else '.'
                return original_key, vulnerabilities, feedback_char
        except Exception:
            # On error, cache an empty list to avoid re-querying and return 'E'
            self.cve_cache[original_key] = []
            return original_key, [], 'E'

    async def run_enrichment(self):
        print("\n📡 Inizio arricchimento dati CVE ottimizzato...")
        unique_software = {}
        for _, data in self.graph.nodes(data=True):
            if data.get('type') == 'Software':
                sw_name = data.get('base_name'); sw_version = data.get('version')
                if not sw_name or not sw_version: continue
                version_match = re.match(r'[\d\.:]+', sw_version)
                clean_version = version_match.group(0) if version_match else sw_version
                unique_software[f"{sw_name.lower()}|{sw_version}"] = (sw_name, clean_version)
        
        print(f"   -> Identificati {len(unique_software)} software unici.")
        
        items_to_fetch = [
            (key, sw_name, clean_version)
            for key, (sw_name, clean_version) in unique_software.items()
            if key not in self.cve_cache
        ]
        
        if not items_to_fetch:
            print("   -> Tutti i software sono già presenti nella cache locale.")
        else:
            print(f"   -> {len(items_to_fetch)} software non in cache. Esecuzione richieste di rete... (V=CVE, .=No CVE, E=Error)")
            async with aiohttp.ClientSession() as session:
                tasks = [self._fetch_cve(session, sw_name, clean_version, key) for key, sw_name, clean_version in items_to_fetch]
                results = await asyncio.gather(*tasks)
                for _, _, feedback in results:
                    print(feedback, end='', flush=True)
            print("\n   -> Richieste di rete completate.")

        for node_name, data in self.graph.nodes(data=True):
            if data.get('type') == 'Software':
                key = f"{data.get('base_name', '').lower()}|{data.get('version', '')}"
                vulnerabilities = self.cve_cache.get(key)
                if vulnerabilities:
                    self.graph.nodes[node_name]['vulnerabilities'] = vulnerabilities
                    scores = [v['score'] for v in vulnerabilities if v['score'] >= 0]
                    max_score = max(scores) if scores else 0.0
                    self.graph.nodes[node_name]['max_cvss'] = max_score
                    self.assets[node_name].score = max_score
                    
        
        self._save_cache()
        print("✅ Arricchimento dati CVE completato.")


# --- DIGITAL TWIN CLASS ---
class DigitalTwin:
    
    def __init__(self):
        self.graph = nx.DiGraph(); 
        self.assets = {}; 
        self.discovered_subnets = []

    def _parse_multiline_data(self, data: str):
        if not isinstance(data, str): return []
        return [item.strip() for item in data.split('<br>') if item.strip()]

    def _parse_software_data(self, data: str):
        if not isinstance(data, str): return []
        lines = self._parse_multiline_data(data)
        software_list = []
        for line in lines:
            parts = line.rsplit(' - ', 1)
            if len(parts) == 2: software_list.append({'name': parts[0].strip(), 'version': parts[1].strip()})
        return software_list
    
    def _discover_subnets_from_rows(self, all_rows):
        print("🔎 Inizio scoperta automatica delle sottoreti...")
        subnet_prefixes = set()
        for row in all_rows:
            ips = self._parse_multiline_data(row.get('Networking - IP', ''))
            for ip_str in ips:
                try:
                    ip_addr = ipaddress.ip_address(ip_str)
                    if ip_addr.is_loopback or ip_addr.version == 6 or not ip_addr.is_private: continue
                    subnet_prefixes.add('.'.join(ip_str.split('.')[:3]))
                except ValueError: continue
        self.discovered_subnets = [ipaddress.ip_network(f"{prefix}.0/24") for prefix in sorted(list(subnet_prefixes))]
        print(f"✅ Sottoreti scoperte: {len(self.discovered_subnets)}")
        for subnet in self.discovered_subnets: print(f"  -> {subnet}")

    def _get_subnet_for_ips(self, ips):
        for ip_str in ips:
            try:
                ip_addr = ipaddress.ip_address(ip_str)
                for subnet in self.discovered_subnets:
                    if ip_addr in subnet: return str(subnet)
            except ValueError: continue
        return 'Unknown/External'
    
    def _add_or_get_asset(self, name, asset_class, **kwargs):
        if name not in self.assets:
            self.assets[name] = asset_class(name, **kwargs)
            self.graph.add_node(name, type=asset_class.__name__, **kwargs)
        elif kwargs: nx.set_node_attributes(self.graph, {name: kwargs})
        return self.assets[name]
    
    def asset_score_calculator(self):
        for name, asset in self.assets.items():
            if isinstance(asset, Host): 
                host_score = 0.0
                if name not in self.graph: continue
                software_scores = []
                for _, neighbor, label in self.graph.edges(name, data=True):
                    if label.get('relationship') == 'INSTALLS':
                        attributes = self.graph.nodes[neighbor]
                        if attributes.get('type') == 'Software' :
                            sw_score = float(attributes.get('max_cvss', 0.0))
                            software_scores.append(sw_score)
                if software_scores:
                    host_score = max(software_scores) # + self.K * sum(software_scores)
                self.assets[name].asset_score = host_score 
                self.graph.nodes[name]['asset_score'] = host_score
    
    def subnet_score_calculator(self, subnets_map, subnet_ip):
        hosts_scores = []

        for host_name in subnets_map[subnet_ip]:
            host = self.assets[host_name]
            if isinstance(host, Host):
                hosts_scores.append(host.asset_score)

        if hosts_scores:
            max_score = max(hosts_scores)
        else:
            max_score = 0.0
        
        return max_score
    
    def add_routers(self):
        subnets_map = self.get_subnets()
        r = 1
        main_router = "Router_0"
        self._add_or_get_asset(main_router, Router, asset_score=10.0)
        # add gateway for every subnet
        for subnet, hosts in subnets_map.items():
            router_name = f"Router_{r}"
            gateway_score = self.subnet_score_calculator(subnets_map, subnet)
            self._add_or_get_asset(router_name, Router, asset_score=gateway_score, subnet=subnet)
        
            for host in hosts:
                self.graph.add_edge(router_name, host, relationship='GATEWAY')
                self.graph.add_edge(host, router_name, relationship='GATEWAY')

            self.graph.add_edge(router_name, main_router, relationship="ROUTER")
            self.graph.add_edge(main_router, router_name, relationship="ROUTER")

            r += 1

    def initialize_assets(self):
        assets = []

        for hosts in self.subnets_map.values():
            for asset in hosts:
                assets.append(asset)

        # include routers
        for router, data in self.graph.nodes(data = True):
            if data.get('type') == 'Router' and router != 'Router_0':
                assets.append(router)

        return assets

    def load_from_csv(self, file_path, delimiter=';'):
        print(f"📄 Inizio lettura e analisi del file: {file_path}")
        with open(file_path, mode='r', encoding='utf-8-sig') as infile:
            next(infile); all_rows = list(csv.DictReader(infile, delimiter=delimiter))
        self._discover_subnets_from_rows(all_rows)
        print("\n🏗️  Inizio costruzione del grafo...")
        for row in all_rows:
            host_name = row.get('Name')
            if not host_name: continue
            ips = self._parse_multiline_data(row.get('Networking - IP', ''))
            subnet = self._get_subnet_for_ips(ips)
            host_attributes = {'os': row.get('Operating System - Name'), 'asset_type': row.get('Type'), 'ips': ips, 'subnet': subnet}
            asset_class = VirtualMachine if host_attributes['asset_type'] == 'VM' else Host
            self._add_or_get_asset(host_name, asset_class, **host_attributes)
            for vm_name in self._parse_multiline_data(row.get('Virtual machines - Name', '')):
                self._add_or_get_asset(vm_name, VirtualMachine, os=host_attributes['os'], subnet=subnet)
                self.graph.add_edge(host_name, vm_name, relationship='HOSTS')
            for sw in self._parse_software_data(row.get('Software - Name', '')):
                sw_unique_name = f"{sw['name']} ({sw['version']})"
                self._add_or_get_asset(sw_unique_name, Software, base_name=sw['name'], version=sw['version'])
                self.graph.add_edge(host_name, sw_unique_name, relationship='INSTALLS')
        print("✅ Grafo principale costruito con successo.")

    def get_graph(self): return self.graph

    def get_summary(self):
        if not self.graph: return
        node_types = nx.get_node_attributes(self.graph, 'type')
        total_vulns = sum(len(d.get('vulnerabilities', [])) for _, d in self.graph.nodes(data=True))
        print("\n--- Riepilogo del Digital Twin Globale ---")
        print(f"Nodi (Asset): {self.graph.number_of_nodes()} | Relazioni: {self.graph.number_of_edges()}")
        type_counts = defaultdict(int)
        for node_type in node_types.values(): type_counts[node_type] += 1
        for n_type, count in sorted(type_counts.items()): print(f"  - {n_type}: {count}")
        print(f"Vulnerabilità Totali Rilevate: {total_vulns}")
        print("----------------------------------------\n")

    def _get_color_by_vulnerability(self, node_data):
        max_score = node_data.get('max_cvss', -1)
        if max_score >= 9.0: return '#6a0dad' # Viola
        if max_score >= 7.0: return '#ff0000' # Rosso
        if max_score >= 4.0: return '#ffa500' # Arancione
        if max_score >= 0.1: return '#ffff00' # Giallo
        return '#808080' # Grigio per software senza CVE note
    
    def get_subnets(self):
        subnets_map = defaultdict(list)
        
        for node, data in self.graph.nodes(data=True):
            if data.get('subnet') and data.get('type') in ['Host', 'VirtualMachine']:
                 subnets_map[data['subnet']].append(node)

        # print("\n valid subnets map:")
        # for subnet, hosts in subnets_map.items():
            # print(f"subnet: {subnet} -> {len(hosts)} hosts")
            # print(f"   nodes: {hosts[:3]}") 
        # print("-" * 40 + "\n")

        return subnets_map
    
    def get_routers(self):
        routers = []

        for router, data in self.graph.nodes(data = True):
            if data.get('type') == 'Router' and router != 'Router_0':
                routers.append(router)
        
        return routers
    
    def visualize_by_subnet(self):
        print("\n🎨 Suddivisione del grafo per sottorete...")
        subnets_map = self.get_subnets()

        print(f"Trovati {len(subnets_map)} gruppi di sottoreti. Generazione dei grafi...")
        for subnet_name, hosts_in_subnet in sorted(subnets_map.items()):
            all_nodes_for_subnet = set(hosts_in_subnet)
            for host in hosts_in_subnet: all_nodes_for_subnet.update(self.graph.successors(host))
            subnet_graph = self.graph.subgraph(all_nodes_for_subnet)
            # self._visualize_graph(subnet_graph, f"Digital Twin - Sottorete: {subnet_name}")
            
    def _visualize_graph(self, G, title):
        if not G.nodes(): return
        print(f"  - Visualizzazione di '{title.split(': ')[1]}' ({G.number_of_nodes()} nodi)")
        plt.figure(figsize=(26, 26))
        pos = nx.spring_layout(G, k=0.2, iterations=50)
        color_map_static = {'Host': 'skyblue', 'VirtualMachine': 'lightgreen', 'Unknown': 'grey'}
        colors = [self._get_color_by_vulnerability(data) if data.get('type') == 'Software' else color_map_static.get(data.get('type', 'Unknown'), 'grey') for node, data in G.nodes(data=True)]
        nx.draw(G, pos, with_labels=True, node_color=colors, node_size=2800, font_size=9, width=0.7, edge_color='gray')
        edge_labels = nx.get_edge_attributes(G, 'relationship')
        nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_color='darkred', font_size=7)
        plt.title(title, size=28)
        plt.show()