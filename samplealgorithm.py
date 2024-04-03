import numpy as np
from sklearn import svm
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

# Sample data representing features (IP address, ICMP packet header, checksum, time)
# Here, 'X' represents your feature data, and 'y' represents the corresponding labels (0 for normal, 1 for DDoS)
X = np.array([
    [192, 168, 0, 1, 80, 255, 255, 255, 255, 192, 168, 0, 2, 192, 168, 0, 3],  # Example normal traffic
    [192, 168, 0, 1, 80, 255, 255, 255, 255, 192, 168, 0, 2, 192, 168, 0, 3],  # Another example of normal traffic
    [255, 255, 255, 255, 255, 192, 168, 0, 1, 192, 168, 0, 2, 192, 168, 0, 3],  # Example DDoS attack traffic
])

y = np.array([0, 0, 1])  # Labels: 0 for normal traffic, 1 for DDoS attack

# Split the data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train SVM model
clf = svm.SVC(kernel='linear')  # You can experiment with different kernels
clf.fit(X_train, y_train)

# Predictions
y_pred_train = clf.predict(X_train)
y_pred_test = clf.predict(X_test)

# Evaluate model
train_accuracy = accuracy_score(y_train, y_pred_train)
test_accuracy = accuracy_score(y_test, y_pred_test)

print("Training Accuracy:", train_accuracy)
print("Testing Accuracy:", test_accuracy)

# Real-time detection (not implemented in this example)
# In real-world usage, you would continuously monitor incoming traffic and classify it using the trained SVM model.
# If an instance is classified as DDoS attack traffic, appropriate mitigation actions can be taken.
