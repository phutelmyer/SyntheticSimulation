# Synthetic Simulation

Hypothesis
-----------
The implementation of a continuous synthetic event solution for the purpose of testing and validating detection
signatures and their components will increase the confidence in the detection system.

Script
-----------
This script generates a dataframe and line chart of detection signature confidence intervals between a system without the
implementation of a synthetic event solution and one with one.

To use this script, either run `simulate.py` directly using the defaults, or modify the global variables and user inputs in the `main` function.

Glossary
-----------
Detection Signature: Logic that is used to detect patterns against traffic

Detection Confidence: Confidence that detection is functioning properly (Can be signature or system level)

Log: Data that is stored and transmitted by a device or system (e.g., Windows, Network)

SIEM: Security Incident Event Management platform used to store logs and detect patterns using detection signatures.

Synthetic: Artificial / user generated object/

Synthetic Event: A synthetic log used to mimic a legitimate log.
