import csv
import numpy as np
from sklearn import svm
from sklearn.model_selection import train_test_split
from sklearn.metric import accuracy_score
from joblib import dump

# Load data from CSV file
def load_data(csv_normal_file, csv_ddos_file):
    X = []
    y = []

    # Load data for normal traffic
    with open(csv_normal_file, 'r') as file:
        reader = csv.reader(file)
        next(reader)
        for row in reader:
            features = list(map(float, row[:-1]))
            X.append(features)
            y.append(0) # 0 means normal traffic

    # Load data for ddos traffic
    with open(csv_ddos_file, 'r') as file:
        reader = csv.reader(file)
        next(reader)
        for row in reader:
            features = list(map(float, row[:-1]]))
            X.append(features)
            y.append(1)

    return np.array(X), np.array(y)

# Load data from CSV files
csv_normal_file = 'normal_traffic.csv'
csv_ddos_file = 'ddos_traffic.csv'
X, y = load_data(csv_normal_file, csv_ddos_file)

# Split data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size = 0.2, random_state = 42)

# Train SVM model
clf = svm.SVC(kernel = 'linear')
clf.fit(X_train, y_train)

# Save trained model to file
model_file = 'svm_model.pkl'
dump(clf, model_file)

# Predictions
y_pred_train = slf.predict(X_train)
y_pred_test = clf.predict(X_test)

# Evaluate model
train_accuracy = accuracy_score(y_train, y_pred_train)
test_accuracy = accuracy_score(y_test, y_pred_test)

print("Training Accuracy: ", train_accuracy)
print("Testing Accuracy: ", test_accuracy)

