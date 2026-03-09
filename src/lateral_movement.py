import random
from collections import defaultdict

from digital_twin import *

# --- LATERAL MOVEMENT CLASS ---

class LateralMovement:
    def __init__(self, dt, **kwargs):
        self.dt = dt
        self.assets = dt.assets
        self.graph = dt.graph
        self.attributes = kwargs

    def initial_access(self):
        subnets_map = self.dt.get_subnets()
        vulnerable_nodes = []
        for hosts in subnets_map.values():
            for asset in hosts:
                host = self.dt.assets[asset]
                if isinstance(host, Host) and host.asset_score >= 9.0: # keep 9.0 ?
                    vulnerable_nodes.append(asset)

        if not vulnerable_nodes:
            subnet = random.choice(list(subnets_map.keys()))
            entry_point = random.choice(subnets_map[subnet])
        else:
            entry_point = random.choice(vulnerable_nodes)

        return entry_point
    
    def neighbor_choice(self, source_node, visited_nodes):

        valid_types = ['Host', 'VirtualMachine']

        # maybe successors list and max score in the graph visit funct because i have to check when max score is minor than threshold

        # find max score between only host/vm successors
        successors = [n for n in self.graph.successors(source_node) 
                      if self.graph.nodes[n].get('type') in valid_types
                      and n not in visited_nodes]

        # empty list check
        if not successors:
            return None

        max_score = max(self.graph.nodes[n].get('asset_score', 0.0) for n in successors)

        # find nodes with max score
        score_nodes = [n for n in successors if self.graph.nodes[n].get('asset_score', 0.0) == max_score]

        # early return
        if len(score_nodes) == 1:
            return score_nodes[0]
        
        # in case of score equality check node degree

        # find max degree between only host/vm successors
        degrees = {}
        for node in score_nodes:
            degrees[node] = sum(1 for n in self.graph.successors(node) if self.graph.nodes[n].get('type') in valid_types)

        max_degree = max(degrees.values())

        # find nodes with max degree
        degree_nodes = [node for node in score_nodes if degrees[node] == max_degree]

        if len(degree_nodes) == 1:
            return degree_nodes[0]

        # in case of degree equality casual choice
        return random.choice(degree_nodes)

    def graph_visit(self):

        visited_nodes = set()

        # first steps
        entry_point = self.initial_access()

        visited_nodes.add(entry_point)

        current_node = entry_point

        while True:
            next_node = self.neighbor_choice(current_node, visited_nodes)

            if next_node is None:
                break

            visited_nodes.add(next_node)

            current_node = next_node