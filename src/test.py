import csv
import numpy as np
from sklearn import svm
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from joblib import dump

# Load data from UDP CSV file
def load_udp_data(csv_normal_file, csv_ddos_file):
    X = []
    y = []

    # Load data for udp normal traffic
    with open(csv_normal_file, 'r') as file:
        reader = csv.reader(file)
        next(reader)
        for row in reader:
            features = list(map(float, row[:-1]))
            X.append(features)
            y.append(0) # 0 means normal traffic

    # Load data for udp ddos traffic
    with open(csv_ddos_file, 'r') as file:
        reader = csv.reader(file)
        next(reader)
        for row in reader:
            features = list(map(float, row[:-1]))
            X.append(features)
            y.append(1)

    return np.array(X), np.array(y)

# Load data from TCP CSV file
def load_tcp_data(csv_normal_file, csv_ddos_file):
    X = []
    y = []

    # Load data for tcp normal traffic
    with open(csv_normal_file, 'r') as file:
        reader = csv.reader(file)
        next(reader)
        for row in reader:
            features = list(map(float, row[:-1]))
            X.append(features)
            y.append(0) # 0 means normal traffic

    # Load data for tcp ddos traffic
    with open(csv_ddos_file, 'r') as file:
        reader = csv.reader(file)
        next(reader)
        for row in reader:
            features = list(map(float, row[:-1]))
            X.append(features)
            y.append(1)

    return np.array(X), np.array(y)

# Load data from ICMP CSV file
def load_icmp_data(csv_normal_file, csv_ddos_file):
    X = []
    y = []

    src_ips = []
    dst_ips = []

    # Load data for icmp normal traffic
    with open(csv_normal_file, 'r') as file:
        reader = csv.reader(file)
        next(reader)
        for row in reader:
            src_ips.append(row[0])
            dst_ips.append(row[1])
            
            features = list(map(float, row[2:-1]))
            X.append(features)
            y.append(0)

    # Load data for icmp ddos traffic
    with open(csv_ddos_file, 'r') as file:
        reader = csv.reader(file)
        next(reader)
        for row in reader:
            src_ips.append(row[0])
            dst_ips.append(row[1])

            src_ips.append
            features = list(map(float, row[2:-1]))
            X.append(features)
            y.append(1)

    return np.array(X), np.array(y)


# Get the file names of the CSV files excluding the prefix
csv_normal_file = input("Enter the file name of the normal traffic file excluding the prefix (ex. normal_traffic.csv): ")
csv_ddos_file = input("Enter the file name of the ddos traffic file excluding the prefix (ex. ddos_traffic.csv): ")
pkl_filename = input("Enter the file name of the training model (ex. svm_model.pkl): ")

prefixes = ['udp', 'tcp', 'icmp']
normal_traffic_files = {}
ddos_traffic_files = {}

# Create dictionary for file names for easy access
for prefix in prefixes:
    normal_traffic_files[prefix] = prefix + "_" + csv_normal_file
    ddos_traffic_files[prefix] = prefix + "_" + csv_ddos_file

X = {}
y = {}
X_train = {}
X_test = {}
y_train = {}
y_test = {}
clf = {}

# Train AI on the 3 datasets
for prefix in prefixes:
    try:
        if prefix == "udp":
            continue
            #X[prefix], y[prefix] = load_udp_data(normal_traffic_files[prefix], ddos_traffic_files[prefix])
        elif prefix == "tcp":
            continue
            #X[prefix], y[prefix] = load_tcp_data(normal_traffic_files[prefix], ddos_traffic_files[prefix])
        elif prefix == "icmp":
            X[prefix], y[prefix] = load_icmp_data(normal_traffic_files[prefix], ddos_traffic_files[prefix])

        # Split data into training and testing sets
        X_train[prefix], X_test[prefix], y_train[prefix], y_test[prefix] = train_test_split(X[prefix], y[prefix], test_size = 0.2, random_state = 42)

        # Train SVM model
        clf[prefix] = svm.SVC(kernel = 'linear')
        clf[prefix].fit(X_train[prefix], y_train[prefix])

        # Save trained model to file
        model_file = f'{prefix}_svm_model.pkl'
        dump(clf[prefix], model_file)

        # Predictions
        y_pred_train = clf[prefix].predict(X_train[prefix])
        y_pred_test = clf[prefix].predict(X_test[prefix])

        # Evaluate model
        train_accuracy = accuracy_score(y_train[prefix], y_pred_train)
        test_accuracy = accuracy_score(y_test[prefix], y_pred_test)

        print(f"Protocol: {prefix.upper()} - Training Accuracy: {train_accuracy}, Testing Accuracy: {test_accuracy}")

    except FileNotFoundError:
        print(f'File not found for protocol {prefix.upper()}, Skipping...')
