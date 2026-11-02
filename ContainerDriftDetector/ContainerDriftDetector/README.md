# Container Drift Detector (base version)

Compares a container's expected baseline against its runtime snapshot and reports drift.

## Requirements
Java 17+

## Run
    java ContainerDriftDetector.java                      # built-in demo
    java ContainerDriftDetector.java samples/baseline.properties samples/runtime.properties

## Exit codes
0 = no drift, 1 = drift found, 2 = HIGH severity drift found
