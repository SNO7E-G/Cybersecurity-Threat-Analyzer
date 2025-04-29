import numpy as np
import pandas as pd
import tensorflow as tf
from tensorflow.keras import layers, models
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.decomposition import PCA
from sklearn.manifold import TSNE
import lightgbm as lgb
import xgboost as xgb
from transformers import BertTokenizer, TFBertModel
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
import logging
from django.conf import settings
import os
import pickle
import json

logger = logging.getLogger('core')

class AdvancedSecurityAlgorithms:
    """
    Advanced machine learning algorithms for security analysis and threat detection.
    This class implements multiple state-of-the-art algorithms for different security use cases.
    """
    
    def __init__(self):
        """Initialize the advanced security algorithms manager."""
        self.models = {}
        self.scalers = {}
        self.tokenizers = {}
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model_path = os.path.join(settings.BASE_DIR, 'ml', 'models')
        
        # Ensure model directory exists
        os.makedirs(self.model_path, exist_ok=True)
        
        # Initialize available algorithms
        self._initialize_algorithms()
    
    def _initialize_algorithms(self):
        """Initialize all available machine learning algorithms."""
        self.available_algorithms = {
            # Unsupervised anomaly detection
            'isolation_forest': self._create_isolation_forest,
            'vae_anomaly': self._create_vae_anomaly_detector,
            'autoencoder': self._create_autoencoder,
            
            # Supervised classification
            'xgboost': self._create_xgboost,
            'lightgbm': self._create_lightgbm,
            'deep_neural_network': self._create_dnn,
            
            # Time series analysis
            'lstm_sequence': self._create_lstm_sequence,
            'transformer_sequence': self._create_transformer_sequence,
            
            # NLP for log analysis
            'bert_log_analyzer': self._create_bert_log_analyzer,
            
            # Ensemble methods
            'security_ensemble': self._create_security_ensemble,
            
            # Zero-day attack detection
            'zero_day_detector': self._create_zero_day_detector,
            
            # Encrypted traffic analysis
            'encrypted_traffic_analyzer': self._create_encrypted_traffic_analyzer
        }
    
    def get_algorithm(self, algorithm_name):
        """
        Get a specific algorithm instance.
        
        Args:
            algorithm_name: Name of the algorithm to retrieve
            
        Returns:
            Algorithm instance or None if not found
        """
        if algorithm_name in self.models:
            return self.models[algorithm_name]
        
        if algorithm_name in self.available_algorithms:
            # Create algorithm if it doesn't exist
            algorithm = self.available_algorithms[algorithm_name]()
            self.models[algorithm_name] = algorithm
            return algorithm
        
        return None
    
    def _create_isolation_forest(self):
        """Create an Isolation Forest model for anomaly detection."""
        from sklearn.ensemble import IsolationForest
        
        model = IsolationForest(
            n_estimators=200,
            max_samples='auto',
            contamination=0.03,
            n_jobs=-1,
            random_state=42
        )
        
        return {
            'model': model,
            'type': 'unsupervised',
            'requires_scaling': True,
            'output': 'anomaly'
        }
    
    def _create_vae_anomaly_detector(self):
        """Create a Variational Autoencoder (VAE) for anomaly detection."""
        class VAE(tf.keras.Model):
            def __init__(self, input_dim, latent_dim=16):
                super(VAE, self).__init__()
                self.latent_dim = latent_dim
                
                # Encoder
                self.encoder = tf.keras.Sequential([
                    layers.InputLayer(input_shape=(input_dim,)),
                    layers.Dense(128, activation='relu'),
                    layers.Dense(64, activation='relu'),
                    layers.Dense(latent_dim + latent_dim)
                ])
                
                # Decoder
                self.decoder = tf.keras.Sequential([
                    layers.InputLayer(input_shape=(latent_dim,)),
                    layers.Dense(64, activation='relu'),
                    layers.Dense(128, activation='relu'),
                    layers.Dense(input_dim)
                ])
            
            def encode(self, x):
                mean, logvar = tf.split(self.encoder(x), num_or_size_splits=2, axis=1)
                return mean, logvar
                
            def reparameterize(self, mean, logvar):
                eps = tf.random.normal(shape=mean.shape)
                return eps * tf.exp(logvar * .5) + mean
                
            def decode(self, z):
                return self.decoder(z)
                
            def call(self, inputs):
                mean, logvar = self.encode(inputs)
                z = self.reparameterize(mean, logvar)
                reconstructed = self.decode(z)
                return reconstructed, mean, logvar
        
        return {
            'model_class': VAE,
            'type': 'unsupervised',
            'requires_scaling': True,
            'output': 'anomaly'
        }
    
    def _create_autoencoder(self):
        """Create a deep Autoencoder for anomaly detection."""
        def create_autoencoder(input_dim):
            # Encoder
            encoder = tf.keras.Sequential([
                layers.Dense(128, activation='relu', input_shape=(input_dim,)),
                layers.Dropout(0.2),
                layers.Dense(64, activation='relu'),
                layers.Dropout(0.2),
                layers.Dense(32, activation='relu')
            ])
            
            # Decoder
            decoder = tf.keras.Sequential([
                layers.Dense(64, activation='relu', input_shape=(32,)),
                layers.Dropout(0.2),
                layers.Dense(128, activation='relu'),
                layers.Dropout(0.2),
                layers.Dense(input_dim, activation='sigmoid')
            ])
            
            # Autoencoder
            autoencoder = tf.keras.Sequential([encoder, decoder])
            autoencoder.compile(optimizer='adam', loss='mse')
            
            return autoencoder
        
        return {
            'model_function': create_autoencoder,
            'type': 'unsupervised',
            'requires_scaling': True,
            'output': 'anomaly'
        }
    
    def _create_xgboost(self):
        """Create an XGBoost classifier for attack classification."""
        model = xgb.XGBClassifier(
            n_estimators=200,
            max_depth=10,
            learning_rate=0.1,
            objective='multi:softprob',
            tree_method='gpu_hist' if tf.config.list_physical_devices('GPU') else 'hist',
            eval_metric='mlogloss',
            use_label_encoder=False
        )
        
        return {
            'model': model,
            'type': 'supervised',
            'requires_scaling': False,
            'output': 'classification'
        }
    
    def _create_lightgbm(self):
        """Create a LightGBM classifier for attack classification."""
        model = lgb.LGBMClassifier(
            n_estimators=200,
            num_leaves=31,
            learning_rate=0.1,
            objective='multiclass',
            class_weight='balanced',
            device='gpu' if tf.config.list_physical_devices('GPU') else 'cpu'
        )
        
        return {
            'model': model,
            'type': 'supervised',
            'requires_scaling': False,
            'output': 'classification'
        }
    
    def _create_dnn(self):
        """Create a Deep Neural Network for attack classification."""
        def create_dnn(input_dim, num_classes):
            model = models.Sequential([
                layers.Dense(256, activation='relu', input_shape=(input_dim,)),
                layers.BatchNormalization(),
                layers.Dropout(0.3),
                layers.Dense(128, activation='relu'),
                layers.BatchNormalization(),
                layers.Dropout(0.3),
                layers.Dense(64, activation='relu'),
                layers.BatchNormalization(),
                layers.Dropout(0.3),
                layers.Dense(num_classes, activation='softmax')
            ])
            
            model.compile(
                optimizer='adam',
                loss='sparse_categorical_crossentropy',
                metrics=['accuracy']
            )
            
            return model
        
        return {
            'model_function': create_dnn,
            'type': 'supervised',
            'requires_scaling': True,
            'output': 'classification'
        }
    
    def _create_lstm_sequence(self):
        """Create an LSTM model for time series attack detection."""
        def create_lstm(seq_length, num_features, num_classes):
            model = models.Sequential([
                layers.LSTM(128, return_sequences=True, input_shape=(seq_length, num_features)),
                layers.Dropout(0.3),
                layers.LSTM(64),
                layers.Dropout(0.3),
                layers.Dense(num_classes, activation='softmax')
            ])
            
            model.compile(
                optimizer='adam',
                loss='sparse_categorical_crossentropy',
                metrics=['accuracy']
            )
            
            return model
        
        return {
            'model_function': create_lstm,
            'type': 'supervised',
            'requires_scaling': True,
            'output': 'sequence_classification'
        }
    
    def _create_transformer_sequence(self):
        """Create a Transformer model for sequence analysis."""
        def create_transformer(seq_length, num_features, num_classes):
            inputs = layers.Input(shape=(seq_length, num_features))
            
            # Transformer layers
            x = layers.MultiHeadAttention(
                num_heads=8, key_dim=64
            )(inputs, inputs)
            x = layers.LayerNormalization(epsilon=1e-6)(x + inputs)
            
            # Feed-forward network
            feed_forward = layers.Dense(256, activation='relu')(x)
            feed_forward = layers.Dense(num_features)(feed_forward)
            
            # Add & Norm
            x = layers.LayerNormalization(epsilon=1e-6)(x + feed_forward)
            
            # Classification head
            x = layers.GlobalAveragePooling1D()(x)
            x = layers.Dense(128, activation='relu')(x)
            x = layers.Dropout(0.3)(x)
            outputs = layers.Dense(num_classes, activation='softmax')(x)
            
            model = models.Model(inputs=inputs, outputs=outputs)
            model.compile(
                optimizer='adam',
                loss='sparse_categorical_crossentropy',
                metrics=['accuracy']
            )
            
            return model
        
        return {
            'model_function': create_transformer,
            'type': 'supervised',
            'requires_scaling': True,
            'output': 'sequence_classification'
        }
    
    def _create_bert_log_analyzer(self):
        """Create a BERT-based model for log analysis."""
        class BERTLogAnalyzer(nn.Module):
            def __init__(self, num_classes):
                super(BERTLogAnalyzer, self).__init__()
                self.bert = TFBertModel.from_pretrained('bert-base-uncased')
                self.dropout = nn.Dropout(0.3)
                self.classifier = nn.Linear(768, num_classes)
                
            def forward(self, input_ids, attention_mask):
                outputs = self.bert(input_ids=input_ids, attention_mask=attention_mask)
                pooled_output = outputs[1]
                pooled_output = self.dropout(pooled_output)
                return self.classifier(pooled_output)
        
        tokenizer = BertTokenizer.from_pretrained('bert-base-uncased')
        self.tokenizers['bert_log_analyzer'] = tokenizer
        
        return {
            'model_class': BERTLogAnalyzer,
            'type': 'supervised',
            'requires_scaling': False,
            'requires_tokenization': True,
            'output': 'text_classification'
        }
    
    def _create_security_ensemble(self):
        """Create an ensemble of multiple models for robust detection."""
        return {
            'type': 'ensemble',
            'models': ['xgboost', 'lightgbm', 'deep_neural_network'],
            'voting': 'soft',
            'output': 'classification'
        }
    
    def _create_zero_day_detector(self):
        """Create a specialized model for zero-day attack detection."""
        # This combines unsupervised and transfer learning approaches
        return {
            'type': 'hybrid',
            'models': ['isolation_forest', 'autoencoder'],
            'requires_scaling': True,
            'output': 'anomaly'
        }
    
    def _create_encrypted_traffic_analyzer(self):
        """Create a model specialized for encrypted traffic analysis."""
        def create_encrypted_analyzer(input_dim):
            model = models.Sequential([
                layers.Dense(256, activation='relu', input_shape=(input_dim,)),
                layers.BatchNormalization(),
                layers.Dropout(0.3),
                layers.Dense(128, activation='relu'),
                layers.BatchNormalization(),
                layers.Dropout(0.3),
                layers.Dense(64, activation='relu'),
                layers.BatchNormalization(),
                layers.Dropout(0.3),
                layers.Dense(32, activation='relu'),
                layers.Dense(2, activation='softmax')  # Benign vs. Malicious
            ])
            
            model.compile(
                optimizer='adam',
                loss='sparse_categorical_crossentropy',
                metrics=['accuracy']
            )
            
            return model
        
        return {
            'model_function': create_encrypted_analyzer,
            'type': 'supervised',
            'requires_scaling': True,
            'output': 'binary_classification'
        }
    
    def train_model(self, algorithm_name, X, y=None, **kwargs):
        """
        Train a specific model.
        
        Args:
            algorithm_name: Name of the algorithm to train
            X: Training features
            y: Training labels (if supervised)
            **kwargs: Additional parameters
            
        Returns:
            Trained model or None if error
        """
        try:
            # Get algorithm
            algorithm = self.get_algorithm(algorithm_name)
            if not algorithm:
                logger.error(f"Algorithm {algorithm_name} not found")
                return None
            
            # Preprocess data if needed
            if algorithm.get('requires_scaling', False):
                scaler = MinMaxScaler()
                X = scaler.fit_transform(X)
                self.scalers[algorithm_name] = scaler
            
            # Handle different algorithm types
            if algorithm['type'] == 'supervised':
                if y is None:
                    logger.error(f"Labels required for supervised algorithm {algorithm_name}")
                    return None
                
                if 'model' in algorithm:
                    # Use existing model instance
                    model = algorithm['model']
                    model.fit(X, y)
                elif 'model_function' in algorithm:
                    # Create model using function
                    if algorithm['output'] == 'classification':
                        num_classes = len(np.unique(y))
                        model = algorithm['model_function'](X.shape[1], num_classes)
                    else:
                        model = algorithm['model_function'](X.shape[1])
                    
                    # Train model
                    model.fit(X, y, epochs=kwargs.get('epochs', 50), 
                             batch_size=kwargs.get('batch_size', 64),
                             validation_split=kwargs.get('validation_split', 0.2),
                             verbose=kwargs.get('verbose', 0))
                
                self.models[algorithm_name] = model
                self._save_model(algorithm_name, model)
                return model
            
            elif algorithm['type'] == 'unsupervised':
                if 'model' in algorithm:
                    # Use existing model instance
                    model = algorithm['model']
                    model.fit(X)
                elif 'model_function' in algorithm:
                    # Create model using function
                    model = algorithm['model_function'](X.shape[1])
                    
                    # Train model
                    model.fit(X, X, epochs=kwargs.get('epochs', 50), 
                             batch_size=kwargs.get('batch_size', 64),
                             validation_split=kwargs.get('validation_split', 0.2),
                             verbose=kwargs.get('verbose', 0))
                
                self.models[algorithm_name] = model
                self._save_model(algorithm_name, model)
                return model
            
            elif algorithm['type'] == 'ensemble':
                # Train each model in the ensemble
                for model_name in algorithm['models']:
                    self.train_model(model_name, X, y, **kwargs)
                
                return self.models
            
            elif algorithm['type'] == 'hybrid':
                # Train each component model
                for model_name in algorithm['models']:
                    if self.get_algorithm(model_name)['type'] == 'supervised':
                        self.train_model(model_name, X, y, **kwargs)
                    else:
                        self.train_model(model_name, X, **kwargs)
                
                return self.models
        
        except Exception as e:
            logger.error(f"Error training model {algorithm_name}: {str(e)}")
            return None
    
    def predict(self, algorithm_name, X, **kwargs):
        """
        Make predictions using a trained model.
        
        Args:
            algorithm_name: Name of the algorithm to use
            X: Features to predict on
            **kwargs: Additional parameters
            
        Returns:
            Predictions or None if error
        """
        try:
            # Get algorithm
            algorithm = self.get_algorithm(algorithm_name)
            if not algorithm:
                logger.error(f"Algorithm {algorithm_name} not found")
                return None
            
            # Apply scaling if needed
            if algorithm.get('requires_scaling', False) and algorithm_name in self.scalers:
                X = self.scalers[algorithm_name].transform(X)
            
            # Handle different algorithm types
            if algorithm['type'] in ['supervised', 'unsupervised']:
                if algorithm_name in self.models:
                    model = self.models[algorithm_name]
                    return model.predict(X)
                else:
                    logger.error(f"Model {algorithm_name} not trained")
                    return None
            
            elif algorithm['type'] == 'ensemble':
                # Make predictions with each model in the ensemble
                predictions = []
                for model_name in algorithm['models']:
                    if model_name in self.models:
                        pred = self.predict(model_name, X)
                        predictions.append(pred)
                
                # Combine predictions (voting)
                if algorithm['voting'] == 'soft':
                    # Average probabilities
                    return np.mean(predictions, axis=0)
                else:
                    # Hard voting (majority)
                    return np.apply_along_axis(
                        lambda x: np.bincount(x.astype(int)).argmax(),
                        axis=0, 
                        arr=np.array(predictions)
                    )
            
            elif algorithm['type'] == 'hybrid':
                # Combine predictions from component models
                results = {}
                for model_name in algorithm['models']:
                    results[model_name] = self.predict(model_name, X)
                
                return results
        
        except Exception as e:
            logger.error(f"Error making predictions with {algorithm_name}: {str(e)}")
            return None
    
    def _save_model(self, algorithm_name, model):
        """Save model to disk."""
        try:
            model_path = os.path.join(self.model_path, f"{algorithm_name}.pkl")
            with open(model_path, 'wb') as f:
                pickle.dump(model, f)
            
            # Save scaler if exists
            if algorithm_name in self.scalers:
                scaler_path = os.path.join(self.model_path, f"{algorithm_name}_scaler.pkl")
                with open(scaler_path, 'wb') as f:
                    pickle.dump(self.scalers[algorithm_name], f)
            
            logger.info(f"Saved model {algorithm_name} to {model_path}")
        except Exception as e:
            logger.error(f"Error saving model {algorithm_name}: {str(e)}")
    
    def _load_model(self, algorithm_name):
        """Load model from disk."""
        try:
            model_path = os.path.join(self.model_path, f"{algorithm_name}.pkl")
            if os.path.exists(model_path):
                with open(model_path, 'rb') as f:
                    model = pickle.load(f)
                
                self.models[algorithm_name] = model
                
                # Load scaler if exists
                scaler_path = os.path.join(self.model_path, f"{algorithm_name}_scaler.pkl")
                if os.path.exists(scaler_path):
                    with open(scaler_path, 'rb') as f:
                        self.scalers[algorithm_name] = pickle.load(f)
                
                logger.info(f"Loaded model {algorithm_name} from {model_path}")
                return model
            
            return None
        except Exception as e:
            logger.error(f"Error loading model {algorithm_name}: {str(e)}")
            return None 