import os
import logging
from collections import Counter
import numpy as np
import joblib
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

logger = logging.getLogger(__name__)

def evaluate_predictions(y_true, y_pred):
    """
    Evaluates Random Forest ML predictions against ground truth labels y_true using sklearn.metrics.
    Returns calculated classification metrics or N/A indicators if ground truth is absent.
    """
    if y_true is None or len(y_true) == 0:
        return {
            'has_ground_truth': False,
            'accuracy': None,
            'precision': None,
            'recall': None,
            'f1': None,
            'f1_score': None,
            'correct_predictions': None,
            'wrong_predictions': None,
            'total_evaluated': 0,
            'confusion_matrix': None,
            'message': 'Ground-truth labels unavailable — evaluation metrics cannot be calculated.'
        }
    
    y_t = [str(val).strip() for val in y_true]
    y_p = [str(val).strip() for val in y_pred]

    # Filter out empty or N/A values if all are N/A
    non_na = [t for t in y_t if t.upper() not in ('N/A', 'NONE', '', 'NAN', 'NULL')]
    if not non_na:
        return {
            'has_ground_truth': False,
            'accuracy': None,
            'precision': None,
            'recall': None,
            'f1': None,
            'f1_score': None,
            'correct_predictions': None,
            'wrong_predictions': None,
            'total_evaluated': len(y_t),
            'confusion_matrix': None,
            'message': 'Ground-truth labels unavailable — evaluation metrics cannot be calculated.'
        }

    try:
        acc = accuracy_score(y_t, y_p)
        prec = precision_score(y_t, y_p, average='weighted', zero_division=0)
        rec = recall_score(y_t, y_p, average='weighted', zero_division=0)
        f1 = f1_score(y_t, y_p, average='weighted', zero_division=0)
        
        labels = sorted(list(set(y_t + y_p)))
        cm = confusion_matrix(y_t, y_p, labels=labels)
        
        correct = int(np.sum([1 for t, p in zip(y_t, y_p) if t == p]))
        wrong = int(len(y_t) - correct)
        
        # Detailed audit logging
        actual_dist = dict(Counter(y_t))
        pred_dist = dict(Counter(y_p))
        logger.info(f"--- RANDOM FOREST EVALUATION AUDIT ---")
        logger.info(f"Actual labels distribution: {actual_dist}")
        logger.info(f"Predicted labels distribution: {pred_dist}")
        logger.info(f"Total samples: {len(y_t)} | Correct: {correct} | Wrong: {wrong}")
        logger.info(f"Accuracy: {acc*100:.2f}% | Precision: {prec*100:.2f}% | Recall: {rec*100:.2f}% | F1: {f1*100:.2f}%")
        logger.info(f"--------------------------------------")
        
        acc_pct = round(float(acc) * 100, 2)
        prec_pct = round(float(prec) * 100, 2)
        rec_pct = round(float(rec) * 100, 2)
        f1_pct = round(float(f1) * 100, 2)
        
        return {
            'has_ground_truth': True,
            'accuracy': acc_pct,
            'precision': prec_pct,
            'recall': rec_pct,
            'f1': f1_pct,
            'f1_score': f1_pct,
            'correct_predictions': correct,
            'wrong_predictions': wrong,
            'total_evaluated': len(y_t),
            'confusion_matrix': {
                'labels': labels,
                'matrix': cm.tolist()
            },
            'message': 'Ground-truth labels verified in uploaded dataset. Evaluation metrics calculated dynamically using sklearn.metrics.'
        }
    except Exception as e:
        logger.error(f"Error computing evaluation metrics: {str(e)}")
        return {
            'has_ground_truth': False,
            'accuracy': None,
            'precision': None,
            'recall': None,
            'f1': None,
            'f1_score': None,
            'correct_predictions': None,
            'wrong_predictions': None,
            'total_evaluated': len(y_t),
            'confusion_matrix': None,
            'message': f'Ground-truth labels unavailable — evaluation error: {str(e)}'
        }

def evaluate_uploaded_file(y_true, y_pred):
    """
    Convenience alias for evaluate_predictions.
    """
    return evaluate_predictions(y_true, y_pred)

def get_production_model_evaluation(models_dir=None):
    """
    Single source of truth for Random Forest model metadata and evaluation.
    Dynamically loads feature count and class labels from trained model artifacts.
    """
    if models_dir is None:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        models_dir = os.path.join(base_dir, 'models')
        
    feat_paths = [
        os.path.join(models_dir, 'feature_names_milestone2.pkl'),
        os.path.join(models_dir, 'feature_names.pkl')
    ]
    le_paths = [
        os.path.join(models_dir, 'label_encoder_milestone2.pkl'),
        os.path.join(models_dir, 'label_encoder.pkl')
    ]
    model_paths = [
        os.path.join(models_dir, 'network_model_milestone2.pkl'),
        os.path.join(models_dir, 'network_model.pkl')
    ]
    
    result = {
        'model_name': 'Random Forest (Production Model)',
        'model_type': 'Random Forest Classifier',
        'production': True,
        'features': 78,
        'classes': 4,
        'class_names': ['BENIGN', 'DDoS', 'FTP-Patator', 'SSH-Patator'],
        'is_available': False,
        'description': 'Production model evaluation based on the latest uploaded dataset.'
    }
    
    feat_file = next((p for p in feat_paths if os.path.exists(p)), None)
    if feat_file:
        try:
            feats = joblib.load(feat_file)
            if feats is not None and hasattr(feats, '__len__'):
                result['features'] = len(feats)
        except Exception as e:
            logger.error(f"Error loading feature names from {feat_file}: {str(e)}")
            
    le_file = next((p for p in le_paths if os.path.exists(p)), None)
    if le_file:
        try:
            le = joblib.load(le_file)
            if le is not None and hasattr(le, 'classes_'):
                result['classes'] = len(le.classes_)
                result['class_names'] = [str(c) for c in le.classes_]
        except Exception as e:
            logger.error(f"Error loading label encoder from {le_file}: {str(e)}")
            
    model_file = next((p for p in model_paths if os.path.exists(p)), None)
    if model_file:
        result['is_available'] = True

    # Dynamically evaluate model metrics against ground truth in predictions table
    try:
        from database import fetch_all
        pred_rows = fetch_all("""
            SELECT actual_label, predicted_label, confidence
            FROM predictions
            WHERE actual_label IS NOT NULL
              AND actual_label NOT IN ('N/A', 'None', '', 'NaN', 'null')
        """)
        if pred_rows and len(pred_rows) > 0:
            y_t = [r['actual_label'] for r in pred_rows]
            y_p = [r['predicted_label'] for r in pred_rows]
            eval_res = evaluate_predictions(y_t, y_p)
            result.update({
                'has_ground_truth': eval_res.get('has_ground_truth', False),
                'accuracy': eval_res.get('accuracy'),
                'precision': eval_res.get('precision'),
                'recall': eval_res.get('recall'),
                'f1_score': eval_res.get('f1_score'),
                'f1': eval_res.get('f1_score'),
                'total_evaluated': eval_res.get('total_evaluated', len(pred_rows)),
                'correct_predictions': eval_res.get('correct_predictions'),
                'wrong_predictions': eval_res.get('wrong_predictions'),
                'confusion_matrix': eval_res.get('confusion_matrix'),
                'evaluation_message': eval_res.get('message')
            })

            # Real per-class accuracy and model confidence
            per_class = {}
            for row in pred_rows:
                cls = row['predicted_label']
                if cls not in per_class:
                    per_class[cls] = {'total': 0, 'correct': 0, 'conf_sum': 0.0}
                per_class[cls]['total'] += 1
                if row['actual_label'] == row['predicted_label']:
                    per_class[cls]['correct'] += 1
                conf = float(row.get('confidence') or 0.0)
                if conf > 1.0:
                    conf = conf / 100.0
                per_class[cls]['conf_sum'] += conf

            class_metrics = []
            for cls in result['class_names']:
                info = per_class.get(cls)
                if info and info['total'] > 0:
                    cls_acc = round((info['correct'] / info['total']) * 100, 1)
                    cls_conf = round((info['conf_sum'] / info['total']) * 100, 1)
                    class_metrics.append({
                        'class_name': cls,
                        'accuracy': cls_acc,
                        'confidence': cls_conf,
                        'total_samples': info['total']
                    })
                else:
                    class_metrics.append({
                        'class_name': cls,
                        'accuracy': None,
                        'confidence': None,
                        'total_samples': 0
                    })
            result['class_metrics'] = class_metrics
        else:
            result.update({
                'has_ground_truth': False,
                'accuracy': None,
                'precision': None,
                'recall': None,
                'f1_score': None,
                'f1': None,
                'total_evaluated': 0,
                'correct_predictions': None,
                'wrong_predictions': None,
                'confusion_matrix': None,
                'class_metrics': [],
                'evaluation_message': 'Ground-truth labels are unavailable for runtime evaluation.'
            })
    except Exception as e:
        logger.warning(f"Note: Could not query predictions for evaluation: {str(e)}")
        result.update({
            'has_ground_truth': False,
            'accuracy': None,
            'precision': None,
            'recall': None,
            'f1_score': None,
            'f1': None,
            'class_metrics': [],
            'evaluation_message': 'Ground-truth labels are unavailable for runtime evaluation.'
        })

    return result

