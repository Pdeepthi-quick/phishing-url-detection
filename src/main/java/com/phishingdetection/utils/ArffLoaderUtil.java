package com.phishingdetection.utils;

import weka.core.Instances;
import weka.core.converters.ConverterUtils.DataSource;

public class ArffLoaderUtil {

    public static Instances load(String path) {
        try {
            DataSource ds = new DataSource(path);
            Instances data = ds.getDataSet();
            if (data.classIndex() == -1) data.setClassIndex(data.numAttributes() - 1);
            System.out.println("Debug: Loaded ARFF: rows=" + data.numInstances() + " cols=" + data.numAttributes());
            return data;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}