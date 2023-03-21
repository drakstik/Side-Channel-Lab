import numpy as np
import matplotlib.pyplot as plt

data = np.genfromtxt("Output.txt", dtype=int)

# Print the most frequent int in Output.txt
print("Most frequent index with fastest access time: ")
print(np.bincount(data).argmax())

xpoints = np.array([1, 8])
ypoints = np.array([3, 10])

plt.plot(xpoints, ypoints)
plt.show()