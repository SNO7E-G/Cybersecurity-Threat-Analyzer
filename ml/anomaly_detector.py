import os
import numpy as np
import pandas as pd
import logging
import pickle
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from django.conf import settings
from django.utils import timezone
from core.models import MLModel, SystemSettings

logger = logging.getLogger('core')

class AnomalyDetector:
    """
    Machine Learning-based anomaly detector for network traffic.
    Uses Isolation Forest algorithm for detecting anomalies in network packets.
    """
    
    def __init__(self, model_name='network_traffic_anomaly'):
        """
        Initialize the anomaly detector.
        
        Args:
            model_name: Name of the model to load
        """
        self.model_name = model_name
        self.model = None
        self.scaler = None
        self.features = [
            'packet_length', 'src_port', 'dst_port', 'tcp_window_size',
            'tcp_flags', 'protocol_TCP', 'protocol_UDP', 'protocol_ICMP'
        ]
        
        # Try to load existing model
        self._load_model()
        
        # If model doesn't exist, create a new one
        if self.model is None:
            self._create_model()
    
    def _load_model(self):
        """Load trained model from database or filesystem."""
        try:
            # Try to get model file path from SystemSettings
            model_path = SystemSettings.get('ml_model_path')
            
            if model_path and os.path.exists(model_path):
                with open(model_path, 'rb') as f:
                    self.model = pickle.load(f)
                
                # Load scaler
                scaler_path = os.path.join(os.path.dirname(model_path), 'scaler.pkl')
                if os.path.exists(scaler_path):
                    with open(scaler_path, 'rb') as f:
                        self.scaler = pickle.load(f)
                
                logger.info(f"Loaded anomaly detection model from {model_path}")
                return
            
            # Try to get active model from database
            db_model = MLModel.objects.filter(name=self.model_name, is_active=True).order_by('-created_at').first()
            
            if db_model and db_model.model_file:
                model_path = db_model.model_file.path
                with open(model_path, 'rb') as f:
                    self.model = pickle.load(f)
                
                # Load scaler from the same directory
                scaler_path = os.path.join(os.path.dirname(model_path), 'scaler.pkl')
                if os.path.exists(scaler_path):
                    with open(scaler_path, 'rb') as f:
                        self.scaler = pickle.load(f)
                
                logger.info(f"Loaded anomaly detection model {db_model.name} v{db_model.version}")
                return
        
        except Exception as e:
            logger.error(f"Error loading anomaly detection model: {str(e)}")
    
    def _create_model(self):
        """Create a new anomaly detection model."""
        try:
            # Create a simple Isolation Forest model
            self.model = IsolationForest(
                n_estimators=100,
                max_samples='auto',
                contamination=0.05,  # Expected % of anomalies
                random_state=42
            )
            
            # Create a standard scaler
            self.scaler = StandardScaler()
            
            logger.info("Created new anomaly detection model")
            
            # In a real system, you'd train this model on historical data
            # For now, we'll just leave it untrained until train() is called
        
        except Exception as e:
            logger.error(f"Error creating anomaly detection model: {str(e)}")
    
    def preprocess(self, features):
        """
        Preprocess the features for the model.
        
        Args:
            features: Dictionary of packet features
            
        Returns:
            Preprocessed features as numpy array
        """
        # Create a feature vector
        feature_vector = {}
        
        # Extract numerical features
        feature_vector['packet_length'] = features.get('packet_length', 0)
        feature_vector['src_port'] = features.get('src_port', 0)
        feature_vector['dst_port'] = features.get('dst_port', 0)
        feature_vector['tcp_window_size'] = features.get('tcp_window_size', 0)
        feature_vector['tcp_flags'] = features.get('tcp_flags', 0)
        
        # One-hot encode protocol
        protocol = features.get('protocol', 'UNKNOWN')
        feature_vector['protocol_TCP'] = 1 if protocol == 'TCP' else 0
        feature_vector['protocol_UDP'] = 1 if protocol == 'UDP' else 0
        feature_vector['protocol_ICMP'] = 1 if protocol == 'ICMP' else 0
        
        # Convert to DataFrame
        df = pd.DataFrame([feature_vector])
        
        # Scale features if scaler exists
        if self.scaler:
            df = pd.DataFrame(
                self.scaler.transform(df),
                columns=df.columns
            )
        
        return df.values
    
    def detect(self, features):
        """
        Detect if a packet is anomalous.
        
        Args:
            features: Dictionary of packet features
            
        Returns:
            Tuple of (is_anomaly, confidence, anomaly_type)
        """
        if self.model is None:
            logger.warning("Anomaly detection model not loaded")
            return False, 0.0, 'unknown'
        
        try:
            # Preprocess features
            X = self.preprocess(features)
            
            # Get anomaly score (negative score means anomaly)
            score = self.model.decision_function(X)[0]
            
            # Convert score to anomaly probability (0-1)
            # Lower scores indicate higher anomaly probability
            normalized_score = 1.0 / (1.0 + np.exp(score))
            
            # Determine if it's an anomaly (isolation forest returns -1 for anomalies, 1 for normal)
            prediction = self.model.predict(X)[0]
            is_anomaly = prediction == -1
            
            # Determine anomaly type based on features
            anomaly_type = self._determine_anomaly_type(features, normalized_score)
            
            return is_anomaly, normalized_score, anomaly_type
        
        except Exception as e:
            logger.error(f"Error in anomaly detection: {str(e)}")
            return False, 0.0, 'unknown'
    
    def _determine_anomaly_type(self, features, score):
        """
        Determine the type of anomaly based on features.
        
        Args:
            features: Dictionary of packet features
            score: Anomaly score
            
        Returns:
            String describing the anomaly type
        """
        protocol = features.get('protocol', 'UNKNOWN')
        src_port = features.get('src_port', 0)
        dst_port = features.get('dst_port', 0)
        
        # Check port scanning patterns
        if protocol == 'TCP' and score > 0.8:
            if features.get('tcp_flags', 0) == 2:  # SYN flag
                return 'Port Scan'
        
        # Check DDoS patterns
        if score > 0.9 and protocol in ('TCP', 'UDP', 'ICMP'):
            return 'Potential DDoS'
        
        # Check data exfiltration
        if protocol in ('TCP', 'UDP') and features.get('packet_length', 0) > 8000 and score > 0.85:
            return 'Data Exfiltration'
        
        # Default anomaly type for lower scores
        if score > 0.95:
            return 'Critical Anomaly'
        elif score > 0.9:
            return 'Severe Anomaly'
        elif score > 0.8:
            return 'Moderate Anomaly'
        else:
            return 'Mild Anomaly'
    
    def train(self, data):
        """
        Train the anomaly detection model on historical data.
        
        Args:
            data: DataFrame of packet features
            
        Returns:
            True if training was successful, False otherwise
        """
        if len(data) < 100:
            logger.warning("Not enough data to train anomaly detection model")
            return False
        
        try:
            # Fit the scaler
            self.scaler = StandardScaler()
            scaled_data = self.scaler.fit_transform(data)
            
            # Fit the model
            self.model.fit(scaled_data)
            
            # Save the trained model
            self._save_model()
            
            logger.info(f"Trained anomaly detection model on {len(data)} samples")
            return True
        
        except Exception as e:
            logger.error(f"Error training anomaly detection model: {str(e)}")
            return False
    
    def _save_model(self):
        """Save the trained model to database and filesystem."""
        try:
            # Create directory for ML models if it doesn't exist
            models_dir = os.path.join(settings.BASE_DIR, 'ml_models')
            os.makedirs(models_dir, exist_ok=True)
            
            # Create timestamp for version
            timestamp = timezone.now().strftime('%Y%m%d%H%M%S')
            
            # Save model to file
            model_filename = f"{self.model_name}_{timestamp}.pkl"
            model_path = os.path.join(models_dir, model_filename)
            
            with open(model_path, 'wb') as f:
                pickle.dump(self.model, f)
            
            # Save scaler to file
            scaler_path = os.path.join(models_dir, f"scaler_{timestamp}.pkl")
            with open(scaler_path, 'wb') as f:
                pickle.dump(self.scaler, f)
            
            # Save model information to database
            with open(model_path, 'rb') as f:
                db_model = MLModel.objects.create(
                    name=self.model_name,
                    description='Anomaly detection model for network traffic',
                    model_type='IsolationForest',
                    version=timestamp,
                    is_active=True,
                )
                db_model.model_file.save(model_filename, f)
            
            # Deactivate other models of the same name
            MLModel.objects.filter(name=self.model_name).exclude(id=db_model.id).update(is_active=False)
            
            # Update system settings
            SystemSettings.set('ml_model_path', model_path, 'Path to current anomaly detection model')
            
            logger.info(f"Saved anomaly detection model to {model_path}")
            return True
        
        except Exception as e:
            logger.error(f"Error saving anomaly detection model: {str(e)}")
            return False 