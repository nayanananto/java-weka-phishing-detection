package org.example.phishingweka;

import weka.core.*;

public final class Utils {
    private Utils() {}

    public static void printFirstValues(Instances data) {
        if (data == null || data.numInstances() == 0) {
            System.out.println("⚠️  No data to preview");
            return;
        }
        
        Instance first = data.firstInstance();
        System.out.println("\n=== First-row preview (name = value) ===");
        
        int maxAttrsToShow = Math.min(15, data.numAttributes()); // Limit output
        for (int i = 0; i < maxAttrsToShow; i++) {
            Attribute a = data.attribute(i);
            String v;
            
            try {
                if (first.isMissing(i)) {
                    v = "?";
                } else if (a.isNumeric()) {
                    v = String.format("%.4f", first.value(i));
                } else if (a.isNominal()) {
                    int idx = (int) first.value(i);
                    v = (idx >= 0 && idx < a.numValues()) ? a.value(idx) : "?";
                } else {
                    v = first.toString(i);
                }
            } catch (Exception e) {
                v = "ERROR";
            }
            
            System.out.println("  [" + i + "] " + a.name() + " = " + v);
        }
        
        if (data.numAttributes() > maxAttrsToShow) {
            System.out.println("  ... and " + (data.numAttributes() - maxAttrsToShow) + " more attributes");
        }
    }

    /**
     * Improved method to pick positive class index with better logic
     */
    public static int pickPositiveIndex(Instances data) {
        if (data == null || data.classAttribute() == null) {
            System.out.println("⚠️  Invalid data or class attribute");
            return 0;
        }
        
        Attribute classAttr = data.classAttribute();
        
        if (!classAttr.isNominal()) {
            System.out.println("⚠️  Class attribute is not nominal, using index 0");
            return 0;
        }
        
        int numClasses = classAttr.numValues();
        
        if (numClasses < 2) {
            System.out.println("⚠️  Less than 2 classes found, using index 0");
            return 0;
        }
        
        System.out.println("Determining positive class from " + numClasses + " classes:");
        for (int i = 0; i < numClasses; i++) {
            System.out.println("  [" + i + "] " + classAttr.value(i));
        }
        
        // Method 1: Name-based detection (most reliable)
        for (int i = 0; i < numClasses; i++) {
            String className = classAttr.value(i).toLowerCase().trim();
            
            // Check for positive indicators
            if (className.equals("phishing") || className.equals("malicious") || 
                className.equals("bad") || className.equals("positive") ||
                className.equals("1") || className.equals("yes") ||
                className.equals("fraud") || className.equals("spam")) {
                System.out.println("✅ Positive class detected by name: [" + i + "] " + classAttr.value(i));
                return i;
            }
        }
        
        // Method 2: Count-based (minority class in binary classification)
        if (numClasses == 2) {
            try {
                int[] counts = data.attributeStats(data.classIndex()).nominalCounts;
                
                System.out.println("Class distribution:");
                for (int i = 0; i < counts.length; i++) {
                    System.out.printf("  [%d] %s: %d instances (%.1f%%)\n", 
                                    i, classAttr.value(i), counts[i],
                                    100.0 * counts[i] / data.numInstances());
                }
                
                // Use minority class as positive (common in imbalanced datasets)
                if (counts[0] < counts[1]) {
                    System.out.println("✅ Using minority class as positive: [0] " + classAttr.value(0));
                    return 0;
                } else if (counts[1] < counts[0]) {
                    System.out.println("✅ Using minority class as positive: [1] " + classAttr.value(1));
                    return 1;
                }
            } catch (Exception e) {
                System.out.println("⚠️  Error getting class counts: " + e.getMessage());
            }
        }
        
        // Method 3: Convention-based fallback
        if (numClasses == 2) {
            System.out.println("⚠️  Using convention: index 1 as positive class");
            return 1; // Standard convention: 0=negative, 1=positive
        }
        
        // Method 4: Multi-class fallback  
        int defaultIndex = numClasses - 1;
        System.out.println("⚠️  Multi-class fallback: using last class [" + defaultIndex + "] as positive");
        return defaultIndex;
    }

    public static void printConfusion(double[][] cm, Attribute classAttr) {
        if (cm == null || classAttr == null) {
            System.out.println("Cannot display confusion matrix (null data)");
            return;
        }
        
        try {
            System.out.println("Confusion Matrix:");
            
            // Header
            System.out.print("         ");
            for (int j = 0; j < cm.length; j++) {
                System.out.printf("%12s", classAttr.value(j));
            }
            System.out.println();
            
            // Rows
            for (int i = 0; i < cm.length; i++) {
                System.out.printf("%12s", classAttr.value(i));
                for (int j = 0; j < cm[i].length; j++) {
                    System.out.printf("%12.0f", cm[i][j]);
                }
                System.out.println();
            }
            
            // Calculate accuracy from confusion matrix
            double correct = 0;
            double total = 0;
            for (int i = 0; i < cm.length; i++) {
                for (int j = 0; j < cm[i].length; j++) {
                    if (i == j) correct += cm[i][j];
                    total += cm[i][j];
                }
            }
            
            if (total > 0) {
                System.out.printf("Matrix Accuracy: %.4f\n", correct / total);
            }
            
        } catch (Exception e) {
            System.out.println("Error displaying confusion matrix: " + e.getMessage());
        }
    }
}