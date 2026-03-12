import random
import numpy as np

from digital_twin import *

# --- LATERAL MOVEMENT CLASS ---

class LateralMovement:
    def __init__(self, dt, min_host_threshold = 8.0, percentile_value = 75, subnet_threshold = 7.0, **kwargs):
        self.dt = dt
        self.assets = dt.assets
        self.graph = dt.graph
        self.subnets_map = dt.get_subnets()

        # parameters useful for host threshold
        self.min_host_threshold = min_host_threshold
        self.percentile_value = percentile_value

        self.attributes = kwargs

        # host threshold
        self.host_threshold = self.threshold_calculator()

        # subnet threshold
        self.subnet_threshold = subnet_threshold

    def threshold_calculator(self):
        valid_assets = set()

        # only hosts in valid subnets
        for hosts in self.subnets_map.values():
            for asset in hosts:
                valid_assets.add(asset)

        assets_scores = []

        # pick hosts asset scores
        for n, data in self.graph.nodes(data = True):
            if n in valid_assets and data.get('asset_score', 0.0) > 0:
                score = data.get('asset_score', 0.0)
                assets_scores.append(score)

        # calculate threshold
        if assets_scores:
            threshold = max(np.percentile(assets_scores, self.percentile_value), self.min_host_threshold)
        else:
            threshold = self.min_host_threshold

        return threshold

    def initial_access(self):
        vulnerable_nodes = []

        # select critical assets
        for hosts in self.subnets_map.values():
            for asset in hosts:
                host = self.dt.assets[asset]
                if isinstance(host, Host) and host.asset_score >= 9.0:
                    vulnerable_nodes.append(asset)

        # if empty pick a random asset
        if not vulnerable_nodes:
            subnet = random.choice(list(self.subnets_map.keys()))
            entry_point = random.choice(self.subnets_map[subnet])
        # pick a random vulnerable asset as entry point
        else:
            entry_point = random.choice(vulnerable_nodes)

        return entry_point
    
    def subnet_choice(self, main_router, visited_nodes):

        valid_types = ['Host', 'VirtualMachine']

        # current node is main router

        # already not visited subnets
        gateways = []

        for g in self.graph.successors(main_router):
            if self.graph.nodes[g].get('type') == 'Router' and g not in visited_nodes:
                gateways.append(g)

        # all subnets visited
        if not gateways:
            return None
        
        max_score = max(self.graph.nodes[g].get('asset_score', 0.0) for g in gateways)

        # subnet score under threshold
        if max_score < self.subnet_threshold:
            return None
        
        subnets_scores = []

        for g in gateways:
            if self.graph.nodes[g].get('asset_score', 0.0) == max_score:
                subnets_scores.append(g)

        if len(subnets_scores) == 1:
            return subnets_scores[0]
        
        # in case of score equality check how many host are high/critical
        node_count = {}

        for s in subnets_scores:
            node_count[s] = sum(1 for host in self.graph.successors(s)
                                if self.graph.nodes[host].get('type') in valid_types and self.graph.nodes[host].get('asset_score', 0.0) >= self.subnet_threshold)
            
        max_count = max(node_count.values())

        critical_subnets = []

        for s in subnets_scores:
            if node_count[s] == max_count:
                critical_subnets.append(s)

        if len(critical_subnets) == 1:
            return critical_subnets[0]
        
        # in case of number of vulnerable nodes equality pick random
        return random.choice(critical_subnets)
    
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

        # max host score under threshold
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
        for n in score_nodes:
            attack_surfaces[n] = sum(1 for sw in self.graph.successors(n)
                                        if self.graph.nodes[sw].get('type') == 'Software' and self.graph.nodes[sw].get('max_cvss', 0.0) > 4.0)

        max_surface = max(attack_surfaces.values())

        # find nodes with widest attack surface
        vulnerable_nodes = []

        for n in score_nodes:
            if attack_surfaces[n] == max_surface:
                vulnerable_nodes.append(n)

        if len(vulnerable_nodes) == 1:
            return vulnerable_nodes[0]
        
        # in case of attack surface equality pick random
        return random.choice(vulnerable_nodes)
    
    def router_hop(self, current_node):
        # hop on router
        for r in self.graph.successors(current_node):
            if self.graph.nodes[r].get('type') == 'Router':
                return r
            
        return None

    def graph_visit(self):

        visited_nodes = set()

        # first steps
        entry_point = self.initial_access()

        visited_nodes.add(entry_point)

        current_node = entry_point

        while True:

            if current_node is None:
                break

            # current node is gateway
            if self.graph.nodes[current_node].get('type') == 'Router':
                # go to main router
                main_router = self.router_hop(current_node)

                # chose next subnet
                next_node = self.subnet_choice(main_router, visited_nodes)

                # no more subnets to visit
                if next_node is None:
                    break

                visited_nodes.add(next_node)

                current_node = next_node

            # current node is host/vm
            elif self.graph.nodes[current_node].get('type') in ['Host', 'VirtualMachine']:

                next_node = self.neighbor_choice(current_node, visited_nodes)

                # max score too low or no more neighbors 
                if next_node is None:
                    # exit from current subnet
                    gateway_node = self.router_hop(current_node)

                    visited_nodes.add(gateway_node)
                    
                    current_node = gateway_node
                else:
                    # pick next asset
                    visited_nodes.add(next_node)

                    current_node = next_node

        return visited_nodes