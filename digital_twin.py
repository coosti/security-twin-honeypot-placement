import csv
import networkx as nx
import matplotlib.pyplot as plt
import re
import ipaddress
from collections import defaultdict

# --- FASE 1: DEFINIZIONE DELLE CLASSI PER GLI ASSET (Invariata) ---
class Asset:
    """Classe base per ogni componente dell'infrastruttura."""
    def __init__(self, name, **kwargs):
        self.name = name
        self.attributes = kwargs
    def __repr__(self):
        return f"{self.__class__.__name__}(name='{self.name}')"

class Host(Asset):
    """Rappresenta un asset fisico o una VM."""
    def __init__(self, name, **kwargs):
        super().__init__(name, **kwargs)

class Software(Asset):
    """Rappresenta un'applicazione software."""
    def __init__(self, name, version=None, **kwargs):
        super().__init__(name, **kwargs)
        self.version = version
        self.unique_name = f"{self.name}_{self.version}" if version else self.name

class VirtualMachine(Host):
    """Rappresenta una macchina virtuale."""
    pass


# --- FASE 2: CLASSE PRINCIPALE DEL DIGITAL TWIN (Logica di Parsing Definitiva) ---

class DigitalTwin:
    """
    Orchestra la creazione del gemello digitale, scoprendo dinamicamente le sottoreti.
    """
    def __init__(self):
        self.graph = nx.DiGraph()
        self.assets = {}
        self.discovered_subnets = []

    def _parse_multiline_data(self, data: str):
        """Helper generico per parsare dati separati da <br>."""
        if not isinstance(data, str): return []
        return [item.strip() for item in data.split('<br>') if item.strip()]

    def _parse_software_data(self, data: str):
        """Parsing robusto per il software."""
        if not isinstance(data, str): return []
        lines = self._parse_multiline_data(data)
        software_list = []
        for line in lines:
            parts = line.rsplit(' - ', 1)
            if len(parts) == 2:
                software_list.append({'name': parts[0].strip(), 'version': parts[1].strip()})
        return software_list

    def _discover_subnets_from_rows(self, all_rows):
        """Analizza le righe del CSV per scoprire le sottoreti uniche."""
        print("🔎 Inizio scoperta automatica delle sottoreti...")
        subnet_prefixes = set()
        for row in all_rows:
            ips = self._parse_multiline_data(row.get('Networking - IP', ''))
            for ip_str in ips:
                try:
                    ip_addr = ipaddress.ip_address(ip_str)
                    if ip_addr.is_loopback or ip_addr.version == 6 or not ip_addr.is_private:
                        continue
                    prefix = '.'.join(ip_str.split('.')[:3])
                    subnet_prefixes.add(prefix)
                except ValueError:
                    continue
        
        self.discovered_subnets = [ipaddress.ip_network(f"{prefix}.0/24") for prefix in sorted(list(subnet_prefixes))]
        print(f"✅ Sottoreti scoperte: {len(self.discovered_subnets)}")
        for subnet in self.discovered_subnets:
            print(f"  -> {subnet}")

    def _get_subnet_for_ips(self, ips):
        """Identifica a quale delle sottoreti scoperte appartiene un host."""
        for ip_str in ips:
            try:
                ip_addr = ipaddress.ip_address(ip_str)
                for subnet in self.discovered_subnets:
                    if ip_addr in subnet:
                        return str(subnet)
            except ValueError:
                continue
        return 'Unknown/External'
    
    def _add_or_get_asset(self, name, asset_class, **kwargs):
        """Aggiunge un asset se non esiste, altrimenti lo restituisce."""
        if name not in self.assets:
            self.assets[name] = asset_class(name, **kwargs)
            self.graph.add_node(name, type=asset_class.__name__, **kwargs)
        elif kwargs:
            nx.set_node_attributes(self.graph, {name: kwargs})
        return self.assets[name]

    def load_from_csv(self, file_path, delimiter=';'):
        """
        Carica i dati dal CSV, gestendo header non standard e BOM.
        """
        print(f"📄 Inizio lettura e analisi del file: {file_path}")
        try:
            with open(file_path, mode='r', encoding='utf-8-sig') as infile:
                # **CORREZIONE**: Salta la prima riga di header inutile ("Column1;...")
                next(infile)
                
                # Leggi tutte le righe in memoria usando la seconda riga come header corretto
                all_rows = list(csv.DictReader(infile, delimiter=delimiter))

            # PASSAGGIO 1: Scoperta delle sottoreti dai dati letti
            self._discover_subnets_from_rows(all_rows)

            # PASSAGGIO 2: Costruzione del grafo
            print("\n🏗️  Inizio costruzione del grafo...")
            for row in all_rows:
                host_name = row.get('Name')
                if not host_name: continue

                ips = self._parse_multiline_data(row.get('Networking - IP', ''))
                subnet = self._get_subnet_for_ips(ips)
                
                host_attributes = {
                    'os': row.get('Operating System - Name'), 'asset_type': row.get('Type'),
                    'ips': ips, 'subnet': subnet
                }
                asset_class = VirtualMachine if host_attributes['asset_type'] == 'VM' else Host
                self._add_or_get_asset(host_name, asset_class, **host_attributes)
                
                for vm_name in self._parse_multiline_data(row.get('Virtual machines - Name', '')):
                    self._add_or_get_asset(vm_name, VirtualMachine, os=host_attributes['os'], subnet=subnet)
                    self.graph.add_edge(host_name, vm_name, relationship='HOSTS')
                
                for sw in self._parse_software_data(row.get('Software - Name', '')):
                    sw_unique_name = f"{sw['name']} ({sw['version']})"
                    self._add_or_get_asset(sw_unique_name, Software, version=sw['version'])
                    self.graph.add_edge(host_name, sw_unique_name, relationship='INSTALLS')
                        
            print("✅ Grafo principale costruito con successo.")
        except FileNotFoundError:
            print(f"❌ Errore: File {file_path} non trovato.")
        except Exception as e:
            print(f"❌ Errore inaspettato: {e}")

    def get_summary(self):
        """Stampa un riepilogo del digital twin."""
        if not self.graph: return
        node_types = nx.get_node_attributes(self.graph, 'type')
        print("\n--- Riepilogo del Digital Twin Globale ---")
        print(f"Nodi (Asset): {self.graph.number_of_nodes()} | Relazioni: {self.graph.number_of_edges()}")
        type_counts = defaultdict(int)
        for node_type in node_types.values(): type_counts[node_type] += 1
        for n_type, count in sorted(type_counts.items()): print(f"  - {n_type}: {count}")
        print("----------------------------------------\n")

    def _visualize_graph(self, G, title):
        """Funzione helper per visualizzare un grafo."""
        if not G.nodes(): return
        plt.figure(figsize=(24, 24))
        pos = nx.kamada_kawai_layout(G)
        color_map = {'Host': 'skyblue', 'VirtualMachine': 'lightgreen', 'Software': 'lightcoral', 'Unknown': 'grey'}
        colors = [color_map.get(G.nodes[node].get('type', 'Unknown'), 'grey') for node in G]
        
        nx.draw(G, pos, with_labels=True, node_color=colors, node_size=2500,
                font_size=8, font_weight='bold', width=0.6, alpha=0.9,
                edge_color='gray')
        edge_labels = nx.get_edge_attributes(G, 'relationship')
        nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_color='darkred', font_size=7)
        plt.title(title, size=25)
        plt.show()

    def visualize_by_subnet(self):
        """Crea e visualizza un grafo per ogni sottorete scoperta."""
        print("\n🎨 Suddivisione del grafo per sottorete...")
        subnets_map = defaultdict(list)
        # Raggruppa solo gli Host e le VM per sottorete
        for node, data in self.graph.nodes(data=True):
            if data.get('subnet') and data.get('type') in ['Host', 'VirtualMachine']:
                 subnets_map[data['subnet']].append(node)

        print(f"Trovati {len(subnets_map)} gruppi di sottoreti. Generazione dei grafi...")
        for subnet_name, hosts_in_subnet in sorted(subnets_map.items()):
            # Costruisci l'insieme di nodi per il sottografo
            all_nodes_for_subnet = set(hosts_in_subnet)
            for host in hosts_in_subnet:
                # Aggiungi tutti i nodi direttamente collegati (figli)
                all_nodes_for_subnet.update(self.graph.successors(host))
            
            subnet_graph = self.graph.subgraph(all_nodes_for_subnet)
            
            title = f"Digital Twin - Sottorete: {subnet_name}"
            print(f"  - Visualizzazione di '{subnet_name}' ({subnet_graph.number_of_nodes()} nodi, {subnet_graph.number_of_edges()} relazioni)")
            self._visualize_graph(subnet_graph, title)

# --- ESECUZIONE PRINCIPALE ---
if __name__ == "__main__":
    it_digital_twin = DigitalTwin()
    it_digital_twin.load_from_csv('glpi.csv') # Assicurati che il nome file sia corretto
    it_digital_twin.get_summary()
    it_digital_twin.visualize_by_subnet()