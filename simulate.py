 # !/usr/bin/env python3

"""
Paul Hutelmyer
ph2225@nyu.edu
NYU - CS GY 6813 Information Security & Privacy
Research Project
Empirical Evidence

Hypothesis
-----------
The implementation of a continuous synthetic event solution for the purpose of testing and validating detection
signatures and their components will increase the confidence in the detection system.

Script
-----------
This script generates a dataframe and line chart of detection signature confidence intervals between a system without the
implementation of a synthetic event solution and one with one. The following are definitions:

Glossary
-----------
Detection Signature: Logic that is used to detect patterns against traffic
Detection Confidence: Confidence that detection is functioning properly (Can be signature or system level)
Log: Data that is stored and transmitted by a device or system (e.g., Windows, Network)
SIEM: Security Incident Event Management platform used to store logs and detect patterns using detection signatures.
Synthetic: Artificial / user generated object/
Synthetic Event: A synthetic log used to mimic a legitimate log.
"""

# Package Imports
import random
import pandas as pd
from matplotlib import pyplot as plt

# Globals
# Signature Confidence Rate - Data Y-Axis Maximum
TOTAL_CONFIDENCE_MAX = 100
# Signature Confidence Rate - Data Y-Axis Minimum
TOTAL_CONFIDENCE_MIN = 0

# !Non synthetic only!
#  Rule detection rate to cause signature fire
NON_SYNTHETIC_DETECTION_RATE = .1
# Non synthetic only - Confidence appreciation if consecutive rule fire occurs
NON_SYNTHETIC_CONFIDENCE_APPRECIATE_RATE = 30
# Non synthetic only - Confidence depreciation if no consecutive rule fire occurs
NON_SYNTHETIC_CONFIDENCE_DEPRECIATION_RATE = 5

# !Synthetic only! - Synthetics should always fire unless broken
SYNTHETIC_COMPONENT_MALFUNCTION_RATE = .1

# Graphing Only - Steps for Chart Lines
GRAPH_STEPS = 10


def simulate(amount_of_signatures, amount_of_days):
    """
    (Non-synthetic) If signature has never fired, assume a confidence of zero
    (Non-synthetic) If a signature does fire, appreciate confidence in rule validation potential
    (Synthetic) If a synthetic does not fire, assume a confidence of zero
    :parameter amount_of_signatures: Number of signatures to be tested against synthetic and non-synthetic tests
    :parameter amount_of_days: Number of days to execute test for
    :return results: Both synthetic and non-synthetic results based on tests and provided arguments
    """
    synthetics_df = pd.DataFrame()
    no_synthetics_df = pd.DataFrame()

    day = 1

    while amount_of_days >= day:
        synthetic_results = {'day': day}
        no_synthetics_results = {'day': day}

        signature = 1

        while amount_of_signatures >= signature:

            # Check previous confidence rate (No Synthetics Only)
            if day > 1:
                previous_day = day - 1
                previous_confidence_rate = (no_synthetics_df.tail(1))['Signature {}'.format(signature)].values[0]
            else:
                previous_confidence_rate = TOTAL_CONFIDENCE_MIN

            # Synthetics - Check for Component Failure (Signature Specific) - Should be function
            if random.random() <= SYNTHETIC_COMPONENT_MALFUNCTION_RATE:
                synthetic_results['Signature {}'.format(signature)] = TOTAL_CONFIDENCE_MIN
            else:
                synthetic_results['Signature {}'.format(signature)] = TOTAL_CONFIDENCE_MAX

            # Non Synthetics - Check for alert and appreciate / depreciate based on previous confidence rate
            if random.random() <= NON_SYNTHETIC_DETECTION_RATE:
                no_synthetics_results['Signature {}'.format(
                    signature)] = previous_confidence_rate + NON_SYNTHETIC_CONFIDENCE_APPRECIATE_RATE
            else:
                no_synthetics_results['Signature {}'.format(
                    signature)] = previous_confidence_rate - NON_SYNTHETIC_CONFIDENCE_DEPRECIATION_RATE

            if no_synthetics_results['Signature {}'.format(signature)] > 100:
                no_synthetics_results['Signature {}'.format(signature)] = 100
            elif no_synthetics_results['Signature {}'.format(signature)] < 0:
                no_synthetics_results['Signature {}'.format(signature)] = 0

            signature += 1
        synthetics_df = synthetics_df.append(synthetic_results, ignore_index=True).astype(int)
        no_synthetics_df = no_synthetics_df.append(no_synthetics_results, ignore_index=True).astype(int)

        day += 1

    return synthetics_df, no_synthetics_df


def plot_data(df):
    """
    Generates visualization of simulation dataframe.
    :parameter df: Simulation dataframe
    :return None
    """
    num = 0
    palette = plt.get_cmap('Set1')

    # Generate plot for Synthetics
    for column in df.drop('day', axis=1):
        num += 1
        plt.plot(df['day'], df[column].to_numpy(), marker='', color=palette(num), linewidth=1,
                 alpha=0.9, label=column)

    # Add styling and legend
    plt.style.use('seaborn-darkgrid')
    plt.legend(loc=2, ncol=2)
    plt.legend(loc=2, ncol=2)

    # Add titles
    plt.title("Simulation Events", loc='center', fontsize=20, fontweight=2, color='black')
    plt.xlabel("Days")
    plt.ylabel("Confidence Rating")
    plt.show()


def export_data(synthetics_df, no_synthetics_df):
    """
    Exports dataframes to CSV files
    :parameter synthetics_df: Synthetic simulation dataframe
    :parameter no_synthetics_df: Non-synthetic simulation dataframe
    :return None
    """
    synthetics_df.to_csv('synthetics.csv')
    no_synthetics_df.to_csv('no_synthetics.csv')


if __name__ == '__main__':
    """
    Sample Data
    System Confidence: Average of Daily Signature Validations
    Synthetic System: {Day 5: [{Signature 1: 95, Signature 2: 95, Signature 3: 0}], System Confidence: 63}
    No_Synthetics: {Day 5: [{Signature 1: 0, {Signature 2: 20}, {Signature 3: 60], System Confidence: 27}
    """
    amount_of_signatures = 3
    amount_of_days = 30

    # Simulates Signatures With Synthetic Events
    synthetics_df, no_synthetics_df = simulate(amount_of_signatures, amount_of_days)

    # Outputs dataframes to matplotlib charts
    plot_data(synthetics_df)
    plot_data(no_synthetics_df)

    # Exports data to CSV
    export_data(synthetics_df, no_synthetics_df)
