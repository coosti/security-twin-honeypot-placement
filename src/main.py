import asyncio
import os
import nest_asyncio
from pathlib import Path

from digital_twin import *
from lateral_movement import *
from attack_simulator import *
from honeypot import *
from strategy_evaluator import *
from results_visualizer import *

def main():
    nest_asyncio.apply()

    BASE_DIR = Path(__file__).resolve().parent.parent

    CSV_PATH = BASE_DIR / "data" / "glpi.csv"
    CACHE_PATH = BASE_DIR / "data" / "cve_cache.json"
    OUTPUT_PATH = BASE_DIR / "data" / "honeypot_placement.png"

    NVD_API_KEY = os.getenv("NVD_API_KEY")
    
    dt = DigitalTwin()
    dt.load_from_csv(str(CSV_PATH))
    
    enricher = CVEEnricher(dt, api_key = NVD_API_KEY, cache_file=str(CACHE_PATH))
    asyncio.run(enricher.run_enrichment())

    dt.asset_score_calculator()

    dt.add_routers()
    
    dt.get_summary()
    # dt.visualize_by_subnet()

    NUM_SIMULATIONS = 1000
    MAX_STEPS = 15

    THRESHOLD = 8.0

    PERCENTILE = 75

    NUM_HONEYPOTS = 5
    NUM_TARGETS = 10

    lm = LateralMovement(dt, min_host_threshold = THRESHOLD, percentile_value = PERCENTILE)

    simulator = AttackSimulator(dt, lm, num_simulation = NUM_SIMULATIONS, max_steps = MAX_STEPS, threshold = THRESHOLD)

    hm = Honeypot(dt, num_honeypots = NUM_HONEYPOTS)

    evaluator = StrategyEvaluator(dt, lm, hm, simulator, num_targets = NUM_TARGETS)

    strategies = [
        'random_strategy',
        'max_cvss_strategy',
        'critical_nodes_strategy',
        'architectural_strategy'
    ]

    opportunistic_results = []
    targeted_results = []

    print("\nStrategies execution:\n")
    for strategy_name in strategies:
        print(f"{strategy_name.replace('_', ' ').title()}")
        
        if strategy_name == 'critical_nodes_strategy':
            compromised_nodes_dict = dict(simulator.lm_simulator())
            opp_dr, tar_dr = evaluator.strategy_executor(strategy_name, compromised_nodes = compromised_nodes_dict)
        else:
            opp_dr, tar_dr = evaluator.strategy_executor(strategy_name)

        opportunistic_results.append(opp_dr * 100)
        targeted_results.append(tar_dr * 100)
        
        print(f"Opp DR -> {opp_dr*100:.2f}% | Tar DR -> {tar_dr*100:.2f}%\n")

    print("Bar chart generation")
    strategies_strings = ['Random', 'Max CVSS', 'Critical Nodes', 'Architectural']
    
    generate_graph(strategies_strings, opportunistic_results, targeted_results, str(OUTPUT_PATH))

if __name__ == "__main__":
    main()