from digital_twin import *
from lateral_movement import *

# --- HONEYPOT CLASS ---

class Honeypot:
    def __init__(self, dt):
        self.dt = dt
        self.graph = dt.graph

        self.initialize_honeypots()

    def initialize_honeypots(self):

        types = ['Host', 'VirtualMachine', 'Router']

        # set honeypot attribute
        for n, data in self.graph.nodes(data = True):
            if data.get('type') in types:
                self.graph.nodes[n]['is_honeypot'] = False