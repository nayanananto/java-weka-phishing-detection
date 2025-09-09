package org.example.phishingweka;

import weka.core.*;
import weka.core.converters.ConverterUtils.DataSource;
import weka.core.converters.ArffSaver;

import weka.filters.Filter;
import weka.filters.unsupervised.attribute.Remove;
import weka.filters.unsupervised.attribute.RemoveUseless;
import weka.filters.unsupervised.attribute.Normalize;
import weka.filters.unsupervised.attribute.ReplaceMissingValues;
import weka.filters.unsupervised.attribute.NumericToNominal;
//import weka.filters.supervised.instance.SMOTE;

import java.io.File;
import java.util.ArrayList;

public final class DataPrep {
    private DataPrep() {}

    public static Instances loadCsv(String path) throws Exception {
        Instances raw = new DataSource(path).getDataSet();
        if (raw.classIndex() == -1) raw.setClassIndex(raw.numAttributes() - 1);
        System.out.println("=== RAW DATASET ===");
        System.out.println("Relation: " + raw.relationName());
        System.out.println("Instances: " + raw.numInstances());
        System.out.println("Attributes: " + raw.numAttributes());
        System.out.println("Class: " + raw.classAttribute());
        System.out.println("Class type: " + (raw.classAttribute().isNominal() ? "Nominal" : "Numeric"));
        Utils.printFirstValues(raw);
        return raw;
    }

    public static Instances preprocess(Instances raw) throws Exception {
        Instances data = new Instances(raw);
        
        // DEBUG: Initial class distribution
        printClassDistribution(data, "INITIAL");

        // STEP 1: Extract URL features BEFORE removing URL attribute
        data = UrlFeatureExtractor.extractUrlFeatures(data);
        System.out.println("✅ URL features extracted and original URL removed");
        
        // DEBUG: After URL extraction
        printClassDistribution(data, "AFTER URL EXTRACTION");

        // STEP 2: Replace missing values
        ReplaceMissingValues rmv = new ReplaceMissingValues();
        rmv.setInputFormat(data);
        data = Filter.useFilter(data, rmv);
        System.out.println("✅ Missing values replaced");
        
        // DEBUG: After missing value replacement
        printClassDistribution(data, "AFTER MISSING VALUE REPLACEMENT");

        // STEP 3: Remove useless attributes
        RemoveUseless ru = new RemoveUseless();
        ru.setInputFormat(data);
        data = Filter.useFilter(data, ru);
        System.out.println("✅ Useless attributes removed");
        
        // DEBUG: After removing useless attributes
        printClassDistribution(data, "AFTER REMOVING USELESS ATTRIBUTES");

        // STEP 4: FIX CLASS ATTRIBUTE
        data = fixClassAttribute(data);
        
        // DEBUG: After class fixing
        printClassDistribution(data, "AFTER CLASS FIXING");

        return data;
    }

    // Helper method 
    private static void printClassDistribution(Instances data, String step) {
        System.out.println("\n=== CLASS DISTRIBUTION - " + step + " ===");
        System.out.println("Class index: " + data.classIndex());
        
        if (data.classIndex() == -1) {
            System.out.println("❌ No class attribute set!");
            return;
        }
        
        Attribute classAttr = data.classAttribute();
        System.out.println("Class name: " + classAttr.name());
        System.out.println("Class type: " + (classAttr.isNominal() ? "Nominal" : "Numeric"));
        
        if (classAttr.isNominal()) {
            int[] dist = data.attributeStats(data.classIndex()).nominalCounts;
            System.out.println("Distribution:");
            for (int i = 0; i < classAttr.numValues(); i++) {
                double percentage = (100.0 * dist[i] / data.numInstances());
                System.out.printf("  [%d] %s: %d instances (%.1f%%)\n", 
                                i, classAttr.value(i), dist[i], percentage);
            }
        } else {
            // For numeric class, show unique values
            java.util.Set<Double> uniqueValues = new java.util.HashSet<>();
            for (int i = 0; i < Math.min(1000, data.numInstances()); i++) {
                if (!data.instance(i).isMissing(data.classIndex())) {
                    uniqueValues.add(data.instance(i).classValue());
                }
            }
            System.out.println("Unique values (sampled): " + uniqueValues);
        }
    }
    /**
     * Fix class attribute - ensure it's nominal for classification
     */
    private static Instances fixClassAttribute(Instances data) throws Exception {
        System.out.println("\n=== CLASS ATTRIBUTE ANALYSIS ===");
        System.out.println("Current class: " + data.classAttribute().name());
        System.out.println("Current type: " + (data.classAttribute().isNominal() ? "Nominal" : "Numeric"));
        
        if (data.classAttribute().isNumeric()) {
            System.out.println("⚠️ Class attribute is numeric - converting to nominal for classification");
            
            // Check unique values to ensure it's actually categorical
            java.util.Set<Double> uniqueValues = new java.util.HashSet<>();
            for (int i = 0; i < data.numInstances(); i++) {
                if (!data.instance(i).isMissing(data.classIndex())) {
                    uniqueValues.add(data.instance(i).classValue());
                }
            }
            
            System.out.println("Unique class values found: " + uniqueValues.size());
            for (Double val : uniqueValues) {
                System.out.println("  " + val);
            }
            
            if (uniqueValues.size() <= 10) { // Reasonable number for classification
                // Convert numeric class to nominal
                NumericToNominal numToNom = new NumericToNominal();
                numToNom.setAttributeIndices(String.valueOf(data.classIndex() + 1)); // 1-based
                numToNom.setInputFormat(data);
                data = Filter.useFilter(data, numToNom);
                data.setClassIndex(data.numAttributes() - 1); // Restore class index
                
                System.out.println("✅ Class attribute converted to nominal");
                System.out.println("New class values:");
                for (int i = 0; i < data.classAttribute().numValues(); i++) {
                    System.out.println("  [" + i + "] " + data.classAttribute().value(i));
                }
            } else {
                System.out.println("⚠️ Too many unique values (" + uniqueValues.size() + ") - might be regression problem");
                System.out.println("Keeping as numeric - only RandomForest will work");
            }
        } else {
            System.out.println("✅ Class attribute is already nominal");
            System.out.println("Class values:");
            for (int i = 0; i < data.classAttribute().numValues(); i++) {
                System.out.println("  [" + i + "] " + data.classAttribute().value(i));
            }
        }
        
        return data;
    }

    /**
     * Normalize only numeric attributes, excluding the class attribute
     */
    private static Instances normalizeFeatures(Instances data) throws Exception {
        // Simple approach: normalize all numeric attributes, then restore class if it was normalized
        boolean classIsNominal = data.classAttribute().isNominal();
        
        // Count numeric attributes (excluding nominal class)
        int numericCount = 0;
        for (int i = 0; i < data.numAttributes(); i++) {
            if (data.attribute(i).isNumeric() && (i != data.classIndex() || !classIsNominal)) {
                numericCount++;
            }
        }
        
        if (numericCount > 0) {
            if (classIsNominal) {
                // Class is nominal, so we can safely normalize all numeric attributes
                Normalize norm = new Normalize();
                norm.setInputFormat(data);
                data = Filter.useFilter(data, norm);
                System.out.println("Normalized " + numericCount + " numeric features (class preserved)");
            } else {
                // Class is numeric - need more careful approach
                // For now, normalize all and let regression handle it
                Normalize norm = new Normalize();
                norm.setInputFormat(data);
                data = Filter.useFilter(data, norm);
                System.out.println("Normalized all numeric attributes including class (regression mode)");
            }
        } else {
            System.out.println("No numeric features to normalize");
        }
        
        return data;
    }

    public static void saveArff(Instances data, String outPath) throws Exception {
        ArffSaver saver = new ArffSaver();
        saver.setInstances(data);
        File f = new File(outPath);
        f.getParentFile().mkdirs();
        saver.setFile(f);
        saver.writeBatch();
        System.out.println("✅ Saved ARFF → " + outPath);
    }
}