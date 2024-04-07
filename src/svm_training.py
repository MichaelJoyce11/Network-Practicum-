import csv
import numpy as np
from sklearn import svm
from sklearn.compose import ColumnTransformer
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from sklearn.preprocessing import OneHotEncoder
from joblib import dump
import warnings

# Ignore warning saying that for OneHotEncoder sparse_output will be changed in the future
warnings.filterwarnings("ignore", category=FutureWarning, message="`sparse` was renamed to `sparse_output`.*")

# Load data from UDP CSV file
def load_udp_data(csv_normal_file, csv_ddos_file):
    X = []
    y = []

    # Load data for udp normal traffic
    with open(csv_normal_file, 'r') as file:
        reader = csv.reader(file)
        next(reader)
        i = 0
        for row in reader:
            # Parse data from CSV file and add to arrays for further processing
            features = [row[0], row[1], row[2], row[3], row[5], row[6]]
            X.append(features)
            y.append(0)
            if i == 2000:
                break
            i = i + 1

    # Load data for udp ddos traffic
    with open(csv_ddos_file, 'r') as file:
        reader = csv.reader(file)
        next(reader)
        i = 0
        for row in reader:
            # Parse data from CSV file and add to arrays for further processing
            features = [row[0], row[1], row[2], row[3], row[5], row[6]]
            X.append(features)
            y.append(1)
            if i == 2000:
                break
            i = i + 1

    return np.array(X), np.array(y)

# Load data from TCP CSV file
def load_tcp_data(csv_normal_file, csv_ddos_file):
    X = []
    y = []

    # Load data for tcp normal traffic
    with open(csv_normal_file, 'r') as file:
        reader = csv.reader(file)
        next(reader)
        i = 0
        for row in reader:
            # Parse data from CSV file and add to arrays for further processing
            features = [row[0], row[1], row[2], row[3], row[5], row[6], row[7:]]
            X.append(features)
            y.append(0)
            if i == 2000:
                break
            i = i + 1

    # Load data for tcp ddos traffic
    with open(csv_ddos_file, 'r') as file:
        reader = csv.reader(file)
        next(reader)
        i = 0
        for row in reader:
            # Parse data from CSV file and add to arrays for further processing
            features = [row[0], row[1], row[2], row[3], row[5], row[6], row[7:]]
            X.append(features)
            y.append(1)
            if i == 2000:
                break
            i = i + 1

    return np.array(X), np.array(y)

# Load data from ICMP CSV file
def load_icmp_data(csv_normal_file, csv_ddos_file):
    X = []
    y = []

    # Load data for icmp normal traffic
    with open(csv_normal_file, 'r') as file:
        reader = csv.reader(file)
        next(reader)
        i = 0
        for row in reader:
            # Parse data from CSV file and add to arrays for further processing
            features = [row[0], row[1], row[3], row[4], row[5]]
            X.append(features)
            y.append(0)
            if i == 2000:
                break
            i = i + 1

    # Load data for icmp ddos traffic
    with open(csv_ddos_file, 'r') as file:
        reader = csv.reader(file)
        next(reader)
        i = 0
        for row in reader:
            # Parse data from CSV file and add to arrays for further processing
            features = [row[0], row[1], row[3], row[4], row[5]]
            X.append(features)
            y.append(1)
            if i == 2000:
                break
            i = i + 1

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
            X[prefix], y[prefix] = load_udp_data(normal_traffic_files[prefix], ddos_traffic_files[prefix])
            columns_to_encode = [0, 2, 5]
            encoder = OneHotEncoder(sparse_output=False)

            ct = ColumnTransformer(transformers=[('one_hot_encode', encoder, columns_to_encode)], remainder='passthrough')

            # Apply OneHotEncoding
            X[prefix] = ct.fit_transform(X[prefix])

        elif prefix == "tcp":
            X[prefix], y[prefix] = load_tcp_data(normal_traffic_files[prefix], ddos_traffic_files[prefix])
            columns_to_encode = [0, 2,5]
            encoder = OneHotEncoder(sparse_output=False)

            ct = ColumnTransformer(transformers=[('one_hot_encode', encoder, columns_to_encode)], remainder='passthrough')

            # Apply OneHotEncoding
            X[prefix] = ct.fit_transform(X[prefix])

        elif prefix == "icmp":
            X[prefix], y[prefix] = load_icmp_data(normal_traffic_files[prefix], ddos_traffic_files[prefix])
            columns_to_encode = [0, 1, -2]
            encoder = OneHotEncoder(sparse_output=False)

            ct = ColumnTransformer(transformers=[('one_hot_encode', encoder, columns_to_encode)], remainder='passthrough')

            # Apply OneHotEncoding
            X[prefix] = ct.fit_transform(X[prefix])

        # Split data into training and testing sets
        X_train[prefix], X_test[prefix], y_train[prefix], y_test[prefix] = train_test_split(X[prefix], y[prefix], test_size=0.2, random_state=42)

        # Train SVM model
        clf[prefix] = svm.SVC(kernel='linear')
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
