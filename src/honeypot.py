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

        self.initialize_honeypots()

    def initialize_honeypots(self):

        types = ['Host', 'VirtualMachine', 'Router']

        # set honeypot attribute
        for n, data in self.graph.nodes(data = True):
            if data.get('type') in types:
                self.graph.nodes[n]['is_honeypot'] = False

    # pick n random nodes between assets
    def random_strategy(self):

        self.initialize_honeypots()

        assets = []

        for hosts in self.subnets_map.values():
            for asset in hosts:
                assets.append(asset)

        # include routers
        for router, data in self.graph.nodes(data = True):
            if data.get('type') == 'Router' and router != 'Router_0':
                assets.append(router)

        chosen_assets = random.sample(assets, self.num_honeypots)

        for asset in chosen_assets:
            self.graph.nodes[asset]['is_honeypot'] = True

        return chosen_assets