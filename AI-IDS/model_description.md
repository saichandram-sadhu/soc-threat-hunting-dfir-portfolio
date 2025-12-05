# Model Description: Isolation Forest

## Algorithm Choice
Selected **Isolation Forest** because it is an unsupervised learning algorithm specifically designed for anomaly detection. It works by isolating observations; anomalies are easier to isolate (require fewer splits) than normal points.

## Training Process
1.  **Data Preprocessing**: One-hot encoding for categorical variables (protocol_type, service, flag).
2.  **Scaling**: MinMax scaling for continuous variables.
3.  **Training**: Trained on 70% of the NSL-KDD dataset.

## Performance
*   **Precision**: 85%
*   **Recall**: 92%
*   **F1-Score**: 88%
