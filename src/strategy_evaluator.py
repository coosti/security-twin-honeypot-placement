from collections import Counter

from digital_twin import *
from honeypot import *
from attack_simulator import *

# --- STRATEGY EVALUATOR CLASS ---

class StrategyEvaluator:

    def __init__(self, digital_twin, lateral_movement, honeypot_manager, attack_simulator, num_targets=10, **kwargs):
        self.dt = digital_twin
        self.graph = digital_twin.graph

        self.lm = lateral_movement
        self.hm = honeypot_manager
        self.simulator = attack_simulator

        self.num_targets = num_targets

    # executor for a generic strategy
    def strategy_executor(self, strategy_name, **kwargs):

        strategy = getattr(self.hm, strategy_name)

        # apply strategy
        honeypots = strategy(**kwargs)

        # print chosen assets
        for n in honeypots:
            node_type = self.graph.nodes[n].get('type')
            print(f" - {n} ({node_type})")

        # execute 1000 simulations of opportunistic attack
        runs = self.simulator.num_simulation

        detected_attacks = 0
        
        for _ in range(runs):
            opportunistic_nodes = self.simulator.opportunistic_attack()

            for node in opportunistic_nodes:
                if node in honeypots:
                    # attack detected
                    detected_attacks += 1
                    break

        # calculate detection rate
        opportunistic_detection_rate = detected_attacks / runs

        detected_attacks = 0

        # execute targeted attack on n different targets

        top_targets = self.simulator.get_top_targets(self.num_targets)

        for target in top_targets:

            targeted_nodes = self.simulator.targeted_attack(target)

            for node in targeted_nodes:
                if node in honeypots:
                    # attack detected
                    detected_attacks += 1
                    break

        if len(top_targets) > 0:
            targeted_detection_rate = detected_attacks / len(top_targets)
        else:
            targeted_detection_rate = 0.0

        return opportunistic_detection_rate, targeted_detection_rate