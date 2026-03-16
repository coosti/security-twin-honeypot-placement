import random

from digital_twin import *
from lateral_movement import *

# --- HONEYPOT CLASS ---

class Honeypot:
    def __init__(self, dt, num_honeypots = 5):
        self.dt = dt
        self.graph = dt.graph
        self.subnets_map = dt.get_subnets()

        self.num_honeypots = num_honeypots

        self.assets = self.initialize_assets()

        self.initialize_honeypots()

    def initialize_assets(self):
        assets = []

        for hosts in self.subnets_map.values():
            for asset in hosts:
                assets.append(asset)

        # include routers
        for router, data in self.graph.nodes(data = True):
            if data.get('type') == 'Router' and router != 'Router_0':
                assets.append(router)

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

            score = self.graph.nodes[n].get('asset_score')

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