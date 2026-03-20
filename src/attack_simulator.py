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

        if not vulnerable_hosts:
            return None

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

    def target_choice(self):

        sorted_targets = []

        for n in self.assets:
            score = self.graph.nodes[n].get('asset_score', 0.0)
            asset_type = self.graph.nodes[n].get('type')

            # chose target node between critical assets
            if score > 0 and asset_type != 'Router':
                num_vulnerabilities = 0

                for sw in self.graph.successors(n):
                    if self.graph.nodes[sw].get('type') == 'Software' and self.graph.nodes[sw].get('max_cvss', 0.0) >= 9.0:

                        vulnerabilities = self.graph.nodes[sw].get('vulnerabilities', [])

                        num_vulnerabilities += sum(1 for v in vulnerabilities
                                                  if v['score'] >= 9.0)
                
                sorted_targets.append((n, score, num_vulnerabilities))
        
        # in case of asset score equality order by total number of critical vulnerabilities
        sorted_targets.sort(key=lambda x: (x[1], x[2]), reverse=True)

        if not sorted_targets:
            return None

        # pick name of chosen node
        target = sorted_targets[0][0]

        return target

    def targeted_initial_access(self, target):

        vulnerable_hosts = []

        for n in self.assets:
            asset_type = self.graph.nodes[n].get('type')
            score = self.graph.nodes[n].get('asset_score', 0.0)

            # chose entry point between medium/high assets
            if asset_type != 'Router' and n != target and 7.0 <= score <= 9.0:

                attack_surface = sum(1 for sw in self.graph.successors(n)
                                        if self.graph.nodes[sw].get('type') == 'Software' and self.graph.nodes[sw].get('max_cvss', 0.0) > 4.0)
                
                vulnerable_hosts.append((n, score, attack_surface))

        if vulnerable_hosts:
            # in case of score equality chose by attack surface
            vulnerable_hosts.sort(key=lambda x: (x[1], x[2]), reverse=True)
                
            entry_point = vulnerable_hosts[0][0]

            return entry_point
        else:
            # in case of no medium/high assets in the network chose between critical assets
            max_vulnerable_hosts = []

            for n in self.assets:
                if self.graph.nodes[n].get('type') != 'Router' and n != target:
                    max_vulnerable_hosts.append((n, self.graph.nodes[n].get('asset_score')))

            if not max_vulnerable_hosts:
                return None

            max_vulnerable_hosts.sort(key=lambda x: x[1], reverse=True)

            return max_vulnerable_hosts[0][0]

        
    def targeted_attack(self):

        visited_nodes = []

        target = self.target_choice()

        if not target:
            return []

        entry_point = self.targeted_initial_access(target)

        if not entry_point:
            return []

        # attacker moves on shortest path between entry point and chosen target
        try:
            visited_nodes = nx.shortest_path(self.graph, entry_point, target)
        except nx.NetworkXNoPath:
            visited_nodes = [entry_point]

        return visited_nodes