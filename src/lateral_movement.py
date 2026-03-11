import random
import numpy as np

from digital_twin import *

# --- LATERAL MOVEMENT CLASS ---

class LateralMovement:
    def __init__(self, dt, min_threshold = 8.0, percentile_value = 75, **kwargs):
        self.dt = dt
        self.assets = dt.assets
        self.graph = dt.graph
        self.subnets_map = dt.get_subnets()

        # parameters useful for host threshold
        self.min_threshold = min_threshold
        self.percentile_value = percentile_value

        self.attributes = kwargs

        # host threshold
        self.host_threshold = self.threshold_calculator()

    def threshold_calculator(self):
        valid_assets = set()

        # only hosts in valid subnets
        for hosts in self.subnets_map.values():
            for asset in hosts:
                valid_assets.add(asset)

        assets_scores = []

        # pick asset scores of hosts
        for n, data in self.graph.nodes(data = True):
            if n in valid_assets and data.get('asset_score', 0.0) > 0:
                score = data.get('asset_score', 0.0)
                assets_scores.append(score)

        # calculate threshold
        if assets_scores:
            threshold = max(np.percentile(assets_scores, self.percentile_value), self.min_threshold)
        else:
            threshold = self.min_threshold

        return threshold

    def initial_access(self):
        vulnerable_nodes = []

        for hosts in self.subnets_map.values():
            for asset in hosts:
                host = self.dt.assets[asset]
                if isinstance(host, Host) and host.asset_score >= 9.0:
                    vulnerable_nodes.append(asset)

        if not vulnerable_nodes:
            subnet = random.choice(list(self.subnets_map.keys()))
            entry_point = random.choice(self.subnets_map[subnet])
        else:
            entry_point = random.choice(vulnerable_nodes)

        return entry_point
    
    def neighbor_choice(self, source_node, visited_nodes):

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

        if max_score < self.host_threshold:
            return None

        # find nodes with max score
        score_nodes = []

        for n in successors:
            if self.graph.nodes[n].get('asset_score', 0.0) == max_score:
                score_nodes.append(n)

        # early return
        if len(score_nodes) == 1:
            return score_nodes[0]
        
        # in case of score equality check attack surfaces
        attack_surfaces = {}

        # find max attack surface between
        for node in score_nodes:
            attack_surfaces[node] = sum(1 for sw in self.graph.successors(node)
                                        if self.graph.nodes[sw].get('type') == 'Software' and self.graph.nodes[sw].get('max_cvss', 0.0) > 4.0)

        max_surface = max(attack_surfaces.values())

        # find nodes with widest attack surface
        vulnerable_nodes = []

        for node in score_nodes:
            if attack_surfaces[node] == max_surface:
                vulnerable_nodes.append(node)

        if len(vulnerable_nodes) == 1:
            return vulnerable_nodes[0]
        
        # in case of attack surface equality pick random
        return random.choice(vulnerable_nodes)

    def graph_visit(self):

        visited_nodes = set()

        # first steps
        entry_point = self.initial_access()

        visited_nodes.add(entry_point)

        current_node = entry_point

        while True:
               
            next_node = self.neighbor_choice(current_node, visited_nodes)

            # max score too low or no more neighbors 
            if next_node is None:
                break
            
            visited_nodes.add(next_node)

            current_node = next_node

        return visited_nodes