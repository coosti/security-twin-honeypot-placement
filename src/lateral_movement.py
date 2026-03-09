from digital_twin import *

# --- LATERAL MOVEMENT CLASS ---

class LateralMovement:
    def __init__(self, dt, **kwargs):
        self.dt = dt
        self.assets = dt.assets
        self.graph = dt.graph
        self.attributes = kwargs