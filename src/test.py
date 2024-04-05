import csv
import numpy as np
from sklearn import svm
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from joblib import dump

# Load data from CSV file
def load_icmp_data(csv_normal_file, csv_ddos_file):
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
            features = list(map(float, row[:-1]))
            X.append(features)
            y.append(1)

    return np.array(X), np.array(y)


# Get the file names of
csv_normal_file = input("Enter the file name of the normal traffic file excluding the prefix (ex. normal_traffic.csv): ")
csv_ddos_file = input("Enter the file name of the ddos traffic file excluding the prefix (ex. ddos_traffic.csv): ")
pkl_filename = input("Enter the file name of the training model (ex. svm_model.pkl): ")

prefixes = ['udp_', 'tcp_', 'icmp_']

normal_traffic_files = {
    'udp': prefixes[0] + csv_normal_file,
    'tcp': prefixes[1] + csv_normal_file,
    'icmp': prefixes[2] + csv_normal_file
}

ddos_traffic_files = {
    'udp': prefixes[0] + csv_ddos_file,
    'tcp': prefixes[1] + csv_ddos_file,
    'icmp': prefixes[2] + csv_ddos_file
}

X_train = {}
X_test = {}
y_train = {}
y_test = {}
clf = {}

# Create a dataset for each protocol
for protocol in normal_traffic_files:
    try:
        X, y = load_data(normal_traffic_files[protocol], ddos_traffic_files[protocol])

        # Split data into training and testing sets
        X_train[protocol], X_test[protocol], y_train[protocol], y_test[protocol] = train_test_split(X, y, test_size = 0.2, random_state = 42)

        # Train SVM model
        clf[protocol] = svm.SVC(kernel = 'linear')
        clf[protocol].fit(X_train[protocol], y_train[protocol])

        # Save trained model to file
        model_file = f'{protocol}_svm_model.pkl'
        dump(clf[protocol], model_file)

        # Predictions
        y_pred_train = clf[protocol].predict(X_train[protocol])
        y_pred_test = clf[protocol].predict(X_test[protocol])

        # Evaluate model
        train_accuracy = accuracy_score(y_train[protocol], y_pred_train)
        test_accuracy = accuracy_score(y_test[protocol], y_pred_test)

        print(f"Protocol: {protocol.upper()} - Training Accuracy: {train_accuracy}, Testing Accuracy: {test_accuracy}")

    except FileNotFoundError:
        print(f'File not found for protocol {protocol.upper()}, Skipping...')
