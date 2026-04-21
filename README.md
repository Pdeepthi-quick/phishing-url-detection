# phishing-url-detection
Phishing URL Detection using Machine Learning (Java + WEKA)
# Phishing URL Detection System

## Overview
This project implements a machine learning-based system to detect phishing websites using URL-based features. The system classifies URLs as phishing or legitimate using an ensemble approach combining Decision Tree (J48) and Random Forest models.

## Technologies Used
- Java
- WEKA Machine Learning Library
- Spark Java (REST API)
- HTML, CSS, JavaScript

## Machine Learning Models
- Decision Tree (J48)
- Random Forest
- Ensemble Learning (Voting)

## Features
- Real-time URL classification
- REST API for backend communication
- Web-based user interface
- Dataset preprocessing and cleaning

## Dataset
The system uses a phishing dataset in ARFF format containing more than 11,000 instances and multiple URL-based features.

## Evaluation
The models were evaluated using:
- Accuracy
- Precision
- Recall
- F1-score

Random Forest and the ensemble approach showed the best performance.

## Project Structure
com.phishingdetection
- rest        (API layer)
- ml          (Machine learning logic)
- utils       (Data preprocessing)
- evaluation  (Model comparison)

## How to Run
1. Clone the repository:
   git clone https://github.com/YOUR_USERNAME/phishing-url-detection.git

2. Build the project:
   mvn clean install

3. Run the server:
   java -cp target/... Server

4. Open in browser:
   http://localhost:4567

## Future Scope
- Browser extension integration
- Real-time dataset updates
- Advanced feature extraction

## Author
Deepthi
