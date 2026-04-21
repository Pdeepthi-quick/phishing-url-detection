package com.phishingdetection.evaluation;

import weka.classifiers.Evaluation;
import weka.classifiers.bayes.NaiveBayes;
import weka.classifiers.lazy.IBk;
import weka.classifiers.functions.Logistic;
import weka.classifiers.functions.SMO;          // SVM
import weka.classifiers.trees.J48;              // Decision Tree
import weka.classifiers.trees.RandomForest;
import weka.classifiers.Classifier;
import weka.core.Instances;
import weka.core.converters.ConverterUtils.DataSource;

import java.util.Random;

public class ModelEvaluation {

    public static void main(String[] args) throws Exception {

        // STEP 1: Load dataset
        DataSource source = new DataSource("dataset/Training_Dataset.cleaned.arff");
        Instances data = source.getDataSet();

        if (data.classIndex() == -1) {
            data.setClassIndex(data.numAttributes() - 1);
        }

        System.out.println("Dataset Loaded");
        System.out.println("Instances: " + data.numInstances());
        System.out.println("Attributes: " + data.numAttributes());

        // STEP 2: Evaluate models
        evaluateModel(new NaiveBayes(), data, "Naive Bayes");
        evaluateModel(new IBk(5), data, "KNN (k=5)");
        evaluateModel(new Logistic(), data, "Logistic Regression");
        evaluateModel(new SMO(), data, "SVM (SMO)");
        evaluateModel(new J48(), data, "Decision Tree (J48)");
        evaluateModel(new RandomForest(), data, "Random Forest");
    }

    private static void evaluateModel(Classifier model,
                                      Instances data,
                                      String modelName) throws Exception {

        Evaluation eval = new Evaluation(data);
        eval.crossValidateModel(model, data, 10, new Random(1));

        System.out.println("\n======================================");
        System.out.println("MODEL: " + modelName);
        System.out.println("======================================");

        // Accuracy, Precision, Recall, F1-score
        System.out.println(eval.toSummaryString());

        // Class-wise Precision, Recall, F-measure
        System.out.println(eval.toClassDetailsString());

        // Confusion Matrix
        System.out.println(eval.toMatrixString());
    }
}
