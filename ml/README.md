# Machine Learning Subsystem

This directory contains the machine learning components of the Cybersecurity Threat Analyzer. The ML subsystem is responsible for advanced threat detection using various algorithms and techniques.

## Directory Structure

- `__init__.py` - Package initialization
- `advanced_algorithms.py` - Main interface for advanced security algorithms
- `anomaly_detector.py` - Core anomaly detection algorithms

## Adding New Algorithms

For detailed instructions on extending the ML capabilities, please refer to the [extending_ml.md](../docs/extending_ml.md) documentation.

## Training Models

Models can be trained using the management commands:

```bash
python manage.py train_ml_model --algorithm ensemble --training_data baseline
```

## Available Algorithms

The system includes the following ML algorithms:

- **Anomaly Detection**
  - Isolation Forest
  - Local Outlier Factor
  - One-Class SVM
  - Gaussian Mixture Models
  - Variational Autoencoders

- **Classification**
  - XGBoost
  - Random Forest
  - Support Vector Machines
  - Neural Networks

- **Sequence Analysis**
  - LSTM Networks
  - Transformer Models
  - Temporal Convolutional Networks

- **Ensemble Methods**
  - Voting Ensembles
  - Stacking Ensembles
  - Weighted Ensembles

## Model Storage

Trained models are stored in the `ml_models/` directory, which is not tracked by Git due to file size constraints. Use the model management commands to create, update, and maintain your models. 