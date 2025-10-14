import numpy as np
import matplotlib.pyplot as plt


actions_before = [500, 1400, 100]   # Example counts
actions_after  = [400, 1200, 400]

labels = ["Allow", "Step-Up", "Block"]
x = np.arange(len(labels))

plt.figure(figsize=(7,5))
plt.bar(x - 0.2, actions_before, 0.4, label="Before Retrain")
plt.bar(x + 0.2, actions_after, 0.4, label="After Retrain")

plt.xticks(x, labels)
plt.ylabel("Number of Logins")
plt.title("Policy Actions Before vs. After Retrain")
plt.legend()
plt.show()
