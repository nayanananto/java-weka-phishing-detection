package org.example.phishingweka;

import weka.core.*;
import weka.classifiers.Classifier;

public class PhishingWeka {
    // PhishingWeka.java এর main method এ debug করুন:

public static void main(String[] args) throws Exception {
    System.out.println("=== PHISHING DETECTION - DEBUG MODE ===");
    
    // (i) Data prep with detailed tracking
    System.out.println("Loading raw data...");
    Instances raw = DataPrep.loadCsv(Config.DATASET_PATH);
    
    // MANUAL CSV CHECK: First few instances
    System.out.println("\n=== MANUAL CSV VERIFICATION ===");
    System.out.println("Raw data shape: " + raw.numInstances() + " x " + raw.numAttributes());
    System.out.println("Class attribute: " + raw.classAttribute().name() + " (index: " + raw.classIndex() + ")");
    
    // Show first 5 instances manually
    System.out.println("First 5 class values from raw data:");
    for (int i = 0; i < Math.min(5, raw.numInstances()); i++) {
        double classVal = raw.instance(i).classValue();
        String classStr = raw.classAttribute().isNominal() ? 
                         raw.classAttribute().value((int)classVal) : 
                         String.valueOf(classVal);
        System.out.println("  Instance " + i + ": " + classStr);
    }
    
    // Count raw class distribution manually
    java.util.Map<String, Integer> rawCounts = new java.util.HashMap<>();
    for (int i = 0; i < raw.numInstances(); i++) {
        if (!raw.instance(i).isMissing(raw.classIndex())) {
            String classLabel;
            if (raw.classAttribute().isNominal()) {
                classLabel = raw.classAttribute().value((int)raw.instance(i).classValue());
            } else {
                classLabel = String.valueOf(raw.instance(i).classValue());
            }
            rawCounts.put(classLabel, rawCounts.getOrDefault(classLabel, 0) + 1);
        }
    }
    
    System.out.println("\n=== RAW CLASS DISTRIBUTION (MANUAL COUNT) ===");
    int totalRaw = 0;
    for (java.util.Map.Entry<String, Integer> entry : rawCounts.entrySet()) {
        System.out.printf("  %s: %d instances\n", entry.getKey(), entry.getValue());
        totalRaw += entry.getValue();
    }
    System.out.println("Total: " + totalRaw + " instances");
    
    // Check for expected 50-50 distribution
    if (rawCounts.size() == 2) {
        java.util.List<Integer> counts = new java.util.ArrayList<>(rawCounts.values());
        int min = java.util.Collections.min(counts);
        int max = java.util.Collections.max(counts);
        double ratio = (double) max / min;
        System.out.printf("Imbalance ratio: %.2f (expected: ~1.0 for 50-50 split)\n", ratio);
        
        if (ratio > 2.0) {
            System.out.println(" WARNING: Raw data shows high imbalance! Expected 50-50 split not found.");
        }
    }
    
    // Preprocessing with tracking
    System.out.println("\n" + "=".repeat(50));
    System.out.println("Starting preprocessing...");
    Instances data = DataPrep.preprocess(raw);
    
    // FINAL CHECK
    System.out.println("\n=== FINAL PREPROCESSED DISTRIBUTION ===");
    ClassDiagnostic.analyzeClassAttribute(data);
    
    // Compare raw vs processed
    System.out.println("\n=== RAW vs PROCESSED COMPARISON ===");
    System.out.printf("Raw instances: %d → Processed instances: %d\n", 
                     raw.numInstances(), data.numInstances());
    System.out.printf("Raw attributes: %d → Processed attributes: %d\n", 
                     raw.numAttributes(), data.numAttributes());
    
    // Continue with original pipeline only if data looks reasonable
    boolean dataLooksGood = checkDataSanity(data, raw);
    if (!dataLooksGood) {
        System.out.println("\n DATA QUALITY ISSUES DETECTED - STOPPING EXECUTION");
        System.out.println("Please fix preprocessing issues before continuing.");
        return;
    }
    
    // Continue with original pipeline...
    Classifier best = SupervisedTrainer.trainAndSelect(data);
    ClusterModule.runKMeans(data);
    RulesModule.mine(data);
    
    System.out.println("\nAll done ");
}

// Helper method to check data sanity
private static boolean checkDataSanity(Instances processed, Instances raw) {
    System.out.println("\n=== DATA SANITY CHECK ===");
    
    boolean sane = true;
    
    // Check 1: Instance count shouldn't change dramatically (unless SMOTE applied)
    double instanceRatio = (double) processed.numInstances() / raw.numInstances();
    if (instanceRatio < 0.5 || instanceRatio > 3.0) {
        System.out.printf(" Instance count changed dramatically: %.2fx\n", instanceRatio);
        if (!Config.USE_SMOTE) {
            sane = false;
        }
    }
    
    // Check 2: Class distribution should be reasonable
    if (processed.classAttribute().isNominal()) {
        int[] dist = processed.attributeStats(processed.classIndex()).nominalCounts;
        int min = java.util.Arrays.stream(dist).min().orElse(0);
        int max = java.util.Arrays.stream(dist).max().orElse(1);
        double ratio = (double) max / min;
        
        if (ratio > 50.0) {
            System.out.printf(" Extreme class imbalance: %.1f:1\n", ratio);
            sane = false;
        } else if (ratio > 10.0) {
            System.out.printf(" High class imbalance: %.1f:1\n", ratio);
        }
    }
    
    // Check 3: Class attribute should exist
    if (processed.classIndex() == -1) {
        System.out.println("No class attribute found in processed data");
        sane = false;
    }
    
    if (sane) {
        System.out.println(" Data passes sanity checks");
    }
    
    return sane;
}
}