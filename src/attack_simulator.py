import random
from collections import Counter
import networkx as nx

from digital_twin import *
from lateral_movement import *

# --- ATTACK SIMULATOR CLASS ---

class AttackSimulator:
    def __init__(self, dt, lm, num_simulation = 1000, threshold = 7.0, **kwargs):
        self.dt = dt

        self.graph = self.dt.graph
        self.assets = self.dt.initialize_assets()

        self.lm = lm
        self.num_simulation = num_simulation

        self.threshold = 7.0

    def lm_simulator(self):

        occurrences = Counter()

        for _ in range(self.num_simulation):

            compromised_nodes = self.lm.graph_visit()

            occurrences.update(compromised_nodes)

        return occurrences.most_common()
    
    def opportunistic_initial_access(self):
        vulnerable_hosts = []

        for n in self.assets:
            if self.graph.nodes[n].get('type') != 'Router':
                vulnerable_hosts.append(n)

        # chosen host is a random one bewteen all hosts
        entry_point = random.choice(vulnerable_hosts)

        return entry_point
    
    def opportunistic_subnet_choice(self, main_router, visited_nodes):

        valid_types = ['Host', 'VirtualMachine']

        # not visited subnets
        gateways = []

        for g in self.graph.successors(main_router):
            if self.graph.nodes[g].get('type') == 'Router' and g not in visited_nodes:
                gateways.append(g)

        # all subnets visited
        if not gateways:
            return None
        
        max_score = max(self.graph.nodes[g].get('asset_score', 0.0) for g in gateways)

        subnets = []

        for g in gateways:
            if self.graph.nodes[g].get('asset_score', 0.0) == max_score:
                subnets.append(g)
        
        return random.choice(subnets)
    
    def opportunistic_neighbor_choice(self, source_node, visited_nodes):
        valid_types = ['Host', 'VirtualMachine']

        # find max score between only host/vm successors
        successors = []
        
        for n in self.graph.successors(source_node):
            if self.graph.nodes[n].get('type') in valid_types and n not in visited_nodes:
                successors.append(n)

        # empty list check
        if not successors:
            return None

        max_score = max(self.graph.nodes[n].get('asset_score', 0.0) for n in successors)

        # find nodes with max score
        nodes = []

        for n in successors:
            if self.graph.nodes[n].get('asset_score', 0.0) == max_score:
                nodes.append(n)
        
        return random.choice(nodes)
    
    def opportunistic_attack(self):

        visited_nodes = set()

        entry_point = self.opportunistic_initial_access()

        visited_nodes.add(entry_point)

        current_node = entry_point

        while True:

            if current_node is None:
                break

            # current node is gateway
            if self.graph.nodes[current_node].get('type') == 'Router':

                next_node = self.opportunistic_neighbor_choice(current_node, visited_nodes)

                if next_node is None:
                    main_router = self.lm.router_hop(current_node)

                    if main_router is None:
                        break

                    next_subnet = self.opportunistic_subnet_choice(main_router, visited_nodes)

                    if next_subnet is None:
                        break

                    visited_nodes.add(next_subnet)
                    current_node = next_subnet
                else:
                    visited_nodes.add(next_node)
                    current_node = next_node

            # current node is host/vm
            elif self.graph.nodes[current_node].get('type') in ['Host', 'VirtualMachine']:

                next_node = self.opportunistic_neighbor_choice(current_node, visited_nodes)

                if next_node is None:
                    gateway = self.lm.router_hop(current_node)

                    if gateway is None:
                        break
                    else:
                        visited_nodes.add(gateway)
                        current_node = gateway
                else:
                    visited_nodes.add(next_node)
                    current_node = next_node
            else:
                break

        return visited_nodes