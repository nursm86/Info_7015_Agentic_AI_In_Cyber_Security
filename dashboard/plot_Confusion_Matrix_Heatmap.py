import seaborn as sns
import matplotlib.pyplot as plt
import numpy as np

cm = np.array([[950, 50], [30, 120]])  # Example confusion matrix

plt.figure(figsize=(6,5))
sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
            xticklabels=["Pred Benign", "Pred Malicious"],
            yticklabels=["Actual Benign", "Actual Malicious"])
plt.title("Confusion Matrix After Retrain")
plt.ylabel("Actual")
plt.xlabel("Predicted")
plt.show()
