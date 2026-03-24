import matplotlib.pyplot as plt
import numpy as np

def generate_graph(strategies, opportunistic_dr, targeted_dr):

    x = np.arange(len(strategies))

    width = 0.30
    gap = 0.05

    fig, ax = plt.subplots(figsize=(7, 4))

    opportunistic_bars = ax.bar(x - width/2 - gap/2, opportunistic_dr, width, label='Opportunistic', color='#2B5B84')
    targeted_bars = ax.bar(x + width/2 + gap/2, targeted_dr, width, label='Targeted', color='#A32638')

    ax.set_title('Honeypot placement results', fontsize=14, fontweight='bold')

    ax.set_ylabel('Detection rates (%)')

    ax.bar_label(opportunistic_bars, padding = 3)
    ax.bar_label(targeted_bars, padding = 3)

    ax.set_xticks(x)
    ax.set_xticklabels(strategies)

    ax.set_ylim(0, 115)

    ax.legend()

    plt.tight_layout()

    plt.savefig('honeypot_placement.png', dpi=300)
    plt.show()