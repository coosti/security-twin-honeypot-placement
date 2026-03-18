import random
import math
import networkx as nx

from digital_twin import *
from lateral_movement import *

# --- HONEYPOT CLASS ---

class Honeypot:
    def __init__(self, dt, num_honeypots = 5):
        self.dt = dt
        self.graph = dt.graph
        self.subnets_map = dt.get_subnets()
        self.routers_list = dt.get_routers()

        self.num_honeypots = self.validate_num_honeypot(num_honeypots)

        self.assets = self.dt.initialize_assets()

        # betweenness centrality values for every node
        self.bc_values = nx.betweenness_centrality(self.graph)

        self.initialize_honeypots()

    def validate_num_honeypot(self, num_honeypots):
        subnets = len(self.subnets_map)

        routers = len(self.routers_list)
        
        max_subnets = max(1, int(subnets * 0.20)) if subnets > 0 else 0

        max_routers = max(1, int(routers * 0.20)) if routers > 0 else 0

        # number of honeypots must be lower than 20% of number of subnet + 20% of number of routers
        if num_honeypots <= max_subnets + max_routers:
            return num_honeypots
        else:
            return max_subnets + max_routers

    def initialize_honeypots(self):

        types = ['Host', 'VirtualMachine', 'Router']

        # set honeypot attribute
        for n, data in self.graph.nodes(data = True):
            if data.get('type') in types:
                self.graph.nodes[n]['is_honeypot'] = False

    # pick n random nodes between assets
    def random_strategy(self):

        self.initialize_honeypots()

        chosen_assets = random.sample(self.assets, self.num_honeypots)

        for asset in chosen_assets:
            self.graph.nodes[asset]['is_honeypot'] = True

        return chosen_assets
    
    # pick n assets with max score
    def max_cvss_strategy(self):
        
        self.initialize_honeypots()

        sorted_assets = []

        for n in self.assets:

            score = self.graph.nodes[n].get('asset_score', 0.0)

            if score > 0:

                attack_surface = sum(1 for sw in self.graph.successors(n)
                                        if self.graph.nodes[sw].get('type') == 'Software' and self.graph.nodes[sw].get('max_cvss', 0.0) > 4.0)
                
                sorted_assets.append((n, score, attack_surface))

        # check empty list case
        
        # in case of asset score equality order by attack surface
        sorted_assets.sort(key=lambda x: (x[1], x[2]), reverse=True)

        chosen_assets = [x[0] for x in sorted_assets[:self.num_honeypots]]

        for asset in chosen_assets:
            self.graph.nodes[asset]['is_honeypot'] = True

        return chosen_assets

    # pick n most critical assets
    def critical_nodes_strategy(self, compromised_nodes):

        self.initialize_honeypots()

        # compromised nodes as dict already sorted

        critical_assets = []

        for n in compromised_nodes:

            asset_bc = self.bc_values.get(n, 0.0)

            critical_assets.append((n, compromised_nodes[n], asset_bc))

        # in case of counter equality order by betweenness centrality
        critical_assets.sort(key=lambda x: (x[1], x[2]), reverse=True)

        chosen_assets = [x[0] for x in critical_assets[:self.num_honeypots]]

        for asset in chosen_assets:
            self.graph.nodes[asset]['is_honeypot'] = True

        return chosen_assets
    
    # place honeypots on gateways (external coverage) and on hosts (internal coverage)
    def architectural_strategy(self):

        self.initialize_honeypots()

        router_honeypots = math.ceil(self.num_honeypots / 2)

        subnet_honeypots = math.floor(self.num_honeypots / 2)

        chosen_subnets = set()

        # pick n routers to place honeypots on

        # use betweenness centrality values
        sorted_routers = sorted(self.routers_list, key=lambda r: self.bc_values.get(r, 0.0), reverse=True)

        chosen_routers = [r for r in sorted_routers[:router_honeypots]]

        # add ips of chosen subnets to the set

        for r in chosen_routers:
            ip = self.graph.nodes[r].get('subnet')
            
            if ip:
                chosen_subnets.add(ip)

        # pick m assets to place honeypots on

        sorted_hosts = []

        # leave routers out
        for n in self.assets:
            
            if self.graph.nodes[n].get('type') != 'Router' and self.graph.nodes[n].get('subnet') not in chosen_subnets:

                score = self.graph.nodes[n].get('asset_score', 0.0)

                if score > 0:

                    sorted_hosts.append((n, score))

        # use asset score values
        sorted_hosts.sort(key=lambda x: x[1], reverse=True)

        chosen_hosts = []

        for n, score in sorted_hosts:

            if len(chosen_hosts) == subnet_honeypots:
                break

            ip = self.graph.nodes[n].get('subnet')

            if ip not in chosen_subnets:

                chosen_hosts.append(n)

                chosen_subnets.add(ip)

        
        chosen_assets = chosen_routers + chosen_hosts

        for asset in chosen_assets:
            self.graph.nodes[asset]['is_honeypot'] = True

        return chosen_assets