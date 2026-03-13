import asyncio
import os
import nest_asyncio

from digital_twin import DigitalTwin, CVEEnricher
import lateral_movement

def main():
    nest_asyncio.apply()
    NVD_API_KEY = os.getenv("NVD_API_KEY")
    
    dt = DigitalTwin()
    dt.load_from_csv('data/glpi.csv')
    
    # enricher = CVEEnricher(dt.get_graph(), api_key=NVD_API_KEY)
    enricher = CVEEnricher(dt, api_key = NVD_API_KEY)
    asyncio.run(enricher.run_enrichment())

    dt.asset_score_calculator()

    dt.add_routers()
    
    dt.get_summary()
    dt.visualize_by_subnet()

if __name__ == "__main__":
    main()