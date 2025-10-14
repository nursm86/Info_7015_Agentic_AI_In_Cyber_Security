import matplotlib.pyplot as plt

# Example data (replace with your retrain logs)
retrain_steps = [1, 2, 3, 4, 5]
tau1_values = [0.02, 0.03, 0.05, 0.07, 0.06]
tau2_values = [0.35, 0.38, 0.42, 0.40, 0.43]

plt.figure(figsize=(8,5))
plt.plot(retrain_steps, tau1_values, marker='o', label="τ1 (Allow/Step)")
plt.plot(retrain_steps, tau2_values, marker='o', label="τ2 (Step/Block)")
plt.xlabel("Retrain Cycle")
plt.ylabel("Threshold Value")
plt.title("Threshold Adaptation Across Retrains")
plt.legend()
plt.grid(True)
plt.show()
