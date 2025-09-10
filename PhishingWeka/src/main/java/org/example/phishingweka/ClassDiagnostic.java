package org.example.phishingweka;

import weka.core.*;
import java.util.*;

/**
 * Utility class for diagnosing class attribute issues
 */
public final class ClassDiagnostic {
    private ClassDiagnostic() {}

    /**
     * Comprehensive analysis of class attribute
     */
    public static void analyzeClassAttribute(Instances data) {
        System.out.println("\n=== COMPREHENSIVE CLASS ATTRIBUTE ANALYSIS ===");
        
        if (data == null || data.numInstances() == 0) {
            System.out.println(" No data to analyze");
            return;
        }

        Attribute classAttr = data.classAttribute();
        if (classAttr == null) {
            System.out.println(" No class attribute found");
            System.out.println("Class index: " + data.classIndex());
            return;
        }

        // Basic information
        System.out.println("Class attribute name: " + classAttr.name());
        System.out.println("Class attribute index: " + data.classIndex());
        System.out.println("Class attribute type: " + getAttributeTypeString(classAttr));
        System.out.println("Number of instances: " + data.numInstances());

        // Analyze values
        if (classAttr.isNominal()) {
            analyzeNominalClass(data, classAttr);
        } else if (classAttr.isNumeric()) {
            analyzeNumericClass(data, classAttr);
        } else {
            System.out.println(" Unknown attribute type");
        }

        // Check for missing values
        analyzeMissingValues(data);
        
        // Recommendations
        provideRecommendations(data, classAttr);
    }

    private static void analyzeNominalClass(Instances data, Attribute classAttr) {
        System.out.println("\n--- NOMINAL CLASS ANALYSIS ---");
        System.out.println("Number of class values: " + classAttr.numValues());
        
        // Show class values
        System.out.println("Class values:");
        for (int i = 0; i < classAttr.numValues(); i++) {
            System.out.println("  [" + i + "] '" + classAttr.value(i) + "'");
        }

        // Count actual distribution
        int[] counts = new int[classAttr.numValues()];
        for (int i = 0; i < data.numInstances(); i++) {
            if (!data.instance(i).isMissing(data.classIndex())) {
                int classVal = (int) data.instance(i).classValue();
                if (classVal >= 0 && classVal < counts.length) {
                    counts[classVal]++;
                }
            }
        }

        System.out.println("Actual class distribution:");
        int total = 0;
        for (int count : counts) total += count;
        
        for (int i = 0; i < counts.length; i++) {
            double percentage = total > 0 ? (100.0 * counts[i] / total) : 0.0;
            System.out.printf("  %s: %d instances (%.1f%%)\n", 
                            classAttr.value(i), counts[i], percentage);
        }

        // Check for class imbalance
        if (counts.length == 2) {
            int min = Math.min(counts[0], counts[1]);
            int max = Math.max(counts[0], counts[1]);
            if (min > 0) {
                double ratio = (double) max / min;
                System.out.printf("Class imbalance ratio: %.2f:1", ratio);
                if (ratio > 3.0) {
                    System.out.println(" ( Highly imbalanced)");
                } else if (ratio > 1.5) {
                    System.out.println(" ( Moderately imbalanced)");
                } else {
                    System.out.println(" ( Well balanced)");
                }
            }
        }

        System.out.println(" Nominal class is compatible with all classifiers");
    }

    private static void analyzeNumericClass(Instances data, Attribute classAttr) {
        System.out.println("\n--- NUMERIC CLASS ANALYSIS ---");
        
        // Collect all values
        ArrayList<Double> values = new ArrayList<>();
        for (int i = 0; i < data.numInstances(); i++) {
            if (!data.instance(i).isMissing(data.classIndex())) {
                values.add(data.instance(i).classValue());
            }
        }

        if (values.isEmpty()) {
            System.out.println(" No valid class values found");
            return;
        }

        // Basic statistics
        Collections.sort(values);
        double min = values.get(0);
        double max = values.get(values.size() - 1);
        double mean = values.stream().mapToDouble(Double::doubleValue).average().orElse(0.0);
        
        System.out.println("Value range: " + min + " to " + max);
        System.out.printf("Mean value: %.4f\n", mean);

        // Check unique values
        Set<Double> uniqueValues = new HashSet<>(values);
        System.out.println("Unique values: " + uniqueValues.size());
        
        if (uniqueValues.size() <= 20) {
            System.out.println("Unique values found:");
            ArrayList<Double> sortedUnique = new ArrayList<>(uniqueValues);
            Collections.sort(sortedUnique);
            for (int i = 0; i < Math.min(10, sortedUnique.size()); i++) {
                double value = sortedUnique.get(i);
                long count = values.stream().filter(v -> v.equals(value)).count();
                System.out.printf("  %.4f (appears %d times)\n", value, count);
            }
            if (sortedUnique.size() > 10) {
                System.out.println("  ... and " + (sortedUnique.size() - 10) + " more values");
            }
        }

        // Check if it looks like classification data
        boolean looksLikeClassification = false;
        if (uniqueValues.size() <= 10) {
            // Check if values are integers or look like class labels
            boolean allIntegers = uniqueValues.stream()
                .allMatch(v -> v != null && v == Math.floor(v));
            
            boolean binary = uniqueValues.size() == 2;
            boolean smallRange = (max - min) <= 10;
            
            if (allIntegers && (binary || smallRange)) {
                looksLikeClassification = true;
                System.out.println(" This looks like classification data disguised as numeric!");
                System.out.println("   - All values are integers: " + allIntegers);
                System.out.println("   - Binary classification: " + binary);
                System.out.println("   - Small range: " + smallRange);
            }
        }

        // Classifier compatibility
        System.out.println("Classifier compatibility:");
        System.out.println("   RandomForest: Compatible");
        System.out.println("   REPTree: Compatible");
        System.out.println("   LinearRegression: Compatible");
        System.out.println("   J48: NOT compatible (requires nominal class)");
        System.out.println("   SMO: NOT compatible (requires nominal class)");
        
        if (looksLikeClassification) {
            System.out.println("\n RECOMMENDATION: Convert to nominal for full classifier compatibility");
        }
    }

    private static void analyzeMissingValues(Instances data) {
        System.out.println("\n--- MISSING VALUE ANALYSIS ---");
        
        int missingCount = 0;
        for (int i = 0; i < data.numInstances(); i++) {
            if (data.instance(i).isMissing(data.classIndex())) {
                missingCount++;
            }
        }
        
        if (missingCount > 0) {
            double percentage = 100.0 * missingCount / data.numInstances();
            System.out.printf(" Missing class values: %d (%.1f%%)\n", missingCount, percentage);
            
            if (percentage > 5.0) {
                System.out.println(" High percentage of missing class values detected!");
            }
        } else {
            System.out.println(" No missing class values found");
        }
    }

    private static void provideRecommendations(Instances data, Attribute classAttr) {
        System.out.println("\n--- RECOMMENDATIONS ---");
        
        if (classAttr.isNumeric()) {
            Set<Double> uniqueValues = new HashSet<>();
            for (int i = 0; i < data.numInstances(); i++) {
                if (!data.instance(i).isMissing(data.classIndex())) {
                    uniqueValues.add(data.instance(i).classValue());
                }
            }
            
            if (uniqueValues.size() <= 10) {
                System.out.println("1. CONVERT TO NOMINAL:");
                System.out.println("   - Use NumericToNominal filter");
                System.out.println("   - Will enable J48 and SMO classifiers");
                System.out.println("   - Better for classification tasks");
                System.out.println();
                System.out.println("2. KEEP AS NUMERIC (current):");
                System.out.println("   - Limited to regression-capable classifiers");
                System.out.println("   - RandomForest, REPTree, LinearRegression only");
            } else {
                System.out.println("1. REGRESSION APPROACH:");
                System.out.println("   - Keep as numeric");
                System.out.println("   - Use RandomForest, LinearRegression, REPTree");
                System.out.println();
                System.out.println("2. DISCRETIZATION:");
                System.out.println("   - Bin values into ranges");
                System.out.println("   - Convert to nominal classes");
                System.out.println("   - May lose information");
            }
        } else {
            System.out.println(" Class attribute is properly configured for classification");
            
            // Check for class imbalance
            int[] counts = data.attributeStats(data.classIndex()).nominalCounts;
            if (counts.length == 2) {
                int min = Math.min(counts[0], counts[1]);
                int max = Math.max(counts[0], counts[1]);
                if (min > 0 && (double) max / min > 3.0) {
                    System.out.println(" Consider addressing class imbalance:");
                    System.out.println("   - Enable SMOTE in Config.java");
                    System.out.println("   - Use cost-sensitive learning");
                    System.out.println("   - Try ensemble methods");
                }
            }
        }
    }

    private static String getAttributeTypeString(Attribute attr) {
        if (attr.isNominal()) {
            return "Nominal (categorical)";
        } else if (attr.isNumeric()) {
            return "Numeric (continuous)";
        } else if (attr.isString()) {
            return "String";
        } else if (attr.isDate()) {
            return "Date";
        } else {
            return "Unknown";
        }
    }

    /**
     * Quick check if class attribute needs conversion
     */
    public static boolean needsClassConversion(Instances data) {
        if (data == null || data.classAttribute() == null) {
            return false;
        }
        
        Attribute classAttr = data.classAttribute();
        if (!classAttr.isNumeric()) {
            return false; // Already nominal
        }
        
        // Count unique values
        Set<Double> uniqueValues = new HashSet<>();
        for (int i = 0; i < data.numInstances(); i++) {
            if (!data.instance(i).isMissing(data.classIndex())) {
                uniqueValues.add(data.instance(i).classValue());
            }
        }
        
        // Suggest conversion if small number of unique values
        return uniqueValues.size() <= 10;
    }

    /**
     * Print quick class summary for debugging
     */
    public static void quickClassSummary(Instances data) {
        if (data == null || data.classAttribute() == null) {
            System.out.println(" No valid class attribute");
            return;
        }
        
        Attribute classAttr = data.classAttribute();
        System.out.printf("Class: %s [%s] ", 
                         classAttr.name(), 
                         classAttr.isNominal() ? "Nominal" : "Numeric");
        
        if (classAttr.isNominal()) {
            System.out.printf("(%d values)\n", classAttr.numValues());
        } else {
            Set<Double> unique = new HashSet<>();
            for (int i = 0; i < Math.min(1000, data.numInstances()); i++) {
                if (!data.instance(i).isMissing(data.classIndex())) {
                    unique.add(data.instance(i).classValue());
                }
            }
            System.out.printf("(%d unique values sampled)\n", unique.size());
        }
    }
}