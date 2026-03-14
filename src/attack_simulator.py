from collections import Counter

from digital_twin import *
from lateral_movement import *

# --- ATTACK SIMULATOR CLASS ---

class AttackSimulator:
    def __init__(self, dt, lm, num_simulation = 1000, **kwargs):
        self.dt = dt
        self.lm = lm
        self.num_simulation = num_simulation

    def lm_simulator(self):

        occurrences = Counter()

        for _ in range(self.num_simulation):

            compromised_nodes = self.lm.graph_visit()

            occurrences.update(compromised_nodes)

        return occurrences.most_common()