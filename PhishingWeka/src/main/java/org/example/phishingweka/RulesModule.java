package org.example.phishingweka;

import weka.core.Attribute;
import weka.core.Instances;
import weka.filters.Filter;
import weka.filters.unsupervised.attribute.Remove;
import weka.filters.unsupervised.attribute.Reorder;
import weka.filters.unsupervised.attribute.Discretize;
import weka.associations.Apriori;
import weka.core.SelectedTag;

public final class RulesModule {
    private RulesModule() {}

    /**
     * Mines both Class Association Rules (CAR) and General Association Rules
     * 1) First tries CAR rules (consequent = target class)
     * 2) Then mines general rules for feature relationships
     */
    public static void mine(Instances data) throws Exception {
        System.out.println("\n=== ASSOCIATION RULE MINING ===");
        
        // First mine Class Association Rules (CAR)
        mineClassAssociationRules(data);
        
        // Then mine general association rules
        mineGeneralAssociationRules(data);
    }

    /**
     * Mines Class Association Rules (CAR) - Rules that predict the target class
     * Format: feature_patterns => class_label
     */
    private static void mineClassAssociationRules(Instances data) throws Exception {
        System.out.println("\n=== CLASS ASSOCIATION RULES (CAR) ===");
        
        Instances carData = new Instances(data);
        String targetAttr = carData.classAttribute().name();
        System.out.println("Target attribute for CAR: " + targetAttr);
        
        // Select important features for rule mining
        String[] importantFeatures = {
            "length_url", "length_hostname", "ip", "nb_dots", "nb_hyphens",
            "ratio_intHyperlinks", "ratio_extHyperlinks", "links_in_tags", 
            "safe_anchor", "domain_age", "domain_registration_lengt", 
            "dns_record", "google_index", targetAttr // Include target
        };
        
        // Keep only selected features
        java.util.ArrayList<Integer> keepIndices = new java.util.ArrayList<>();
        for (String featureName : importantFeatures) {
            Attribute attr = carData.attribute(featureName);
            if (attr != null) {
                keepIndices.add(attr.index() + 1); // WEKA uses 1-based indexing
            }
        }
        
        // Ensure target is included
        if (!keepIndices.contains(carData.classIndex() + 1)) {
            keepIndices.add(carData.classIndex() + 1);
        }
        
        java.util.Collections.sort(keepIndices);
        StringBuilder keepSpec = new StringBuilder();
        for (int i = 0; i < keepIndices.size(); i++) {
            if (i > 0) keepSpec.append(",");
            keepSpec.append(keepIndices.get(i));
        }
        
        // Apply Remove filter to keep only selected attributes
        Remove keepFilter = new Remove();
        keepFilter.setInvertSelection(true); // Keep selected, remove others
        keepFilter.setAttributeIndices(keepSpec.toString());
        keepFilter.setInputFormat(carData);
        Instances reducedData = Filter.useFilter(carData, keepFilter);
        
        // Move target attribute to the last position
        int targetIndex = reducedData.attribute(targetAttr).index() + 1; // 1-based
        StringBuilder reorderSpec = new StringBuilder();
        
        // Add all non-target attributes first
        for (int i = 1; i <= reducedData.numAttributes(); i++) {
            if (i != targetIndex) {
                if (reorderSpec.length() > 0) reorderSpec.append(",");
                reorderSpec.append(i);
            }
        }
        // Add target at the end
        reorderSpec.append(",").append(targetIndex);
        
        Reorder reorderFilter = new Reorder();
        reorderFilter.setAttributeIndices(reorderSpec.toString());
        reorderFilter.setInputFormat(reducedData);
        Instances reorderedData = Filter.useFilter(reducedData, reorderFilter);
        reorderedData.setClassIndex(reorderedData.numAttributes() - 1);
        
        System.out.println("CAR data prepared. Class attribute: " + 
                          reorderedData.classAttribute().name() + 
                          " at index: " + reorderedData.classIndex());
        
        // Discretize numeric attributes for rule mining
        Discretize discretizeFilter = new Discretize();
        discretizeFilter.setUseBinNumbers(true);
        discretizeFilter.setBins(Config.RULES_BINS);
        discretizeFilter.setBinRangePrecision(10);
        discretizeFilter.setInputFormat(reorderedData);
        Instances discretizedData = Filter.useFilter(reorderedData, discretizeFilter);
        discretizedData.setClassIndex(discretizedData.numAttributes() - 1);
        
        System.out.println("Data discretized. Final class: " + discretizedData.classAttribute().name());
        System.out.println("Number of instances: " + discretizedData.numInstances());
        System.out.println("Number of attributes: " + discretizedData.numAttributes());
        
        // Try different thresholds to find CAR rules
        double[] supportLevels = {0.15, 0.12, 0.10, 0.08, 0.06, 0.05, 0.04, 0.03, 0.02};
        double[] confidenceLevels = {0.95, 0.90, 0.85, 0.80, 0.75, 0.70, 0.65};
        
        boolean foundCARRules = false;
        
        for (double support : supportLevels) {
            for (double confidence : confidenceLevels) {
                try {
                    Apriori aprioriCAR = new Apriori();
                    
                    // IMPORTANT: Enable CAR mode
                    aprioriCAR.setCar(true);
                    aprioriCAR.setClassIndex(discretizedData.classIndex());
                    
                    // Set thresholds
                    aprioriCAR.setLowerBoundMinSupport(support);
                    aprioriCAR.setMinMetric(confidence); // This is confidence for CAR
                    aprioriCAR.setNumRules(25);
                    aprioriCAR.setDelta(0.01);
                    
                    System.out.printf("\nTrying CAR with support=%.3f, confidence=%.3f...\n", 
                                    support, confidence);
                    
                    long startTime = System.currentTimeMillis();
                    aprioriCAR.buildAssociations(discretizedData);
                    long endTime = System.currentTimeMillis();
                    
                    // Get the rules
                    @SuppressWarnings("rawtypes")
                    java.util.ArrayList[] rules = aprioriCAR.getAllTheRules();
                    int numRules = (rules != null && rules.length > 0) ? rules[0].size() : 0;
                    
                    System.out.printf("Generated %d CAR rules in %d ms\n", 
                                    numRules, (endTime - startTime));
                    
                    if (numRules > 0) {
                        System.out.printf("\n✅ SUCCESS! Found %d Class Association Rules:\n", numRules);
                        System.out.printf("Support=%.3f, Confidence=%.3f\n\n", support, confidence);
                        System.out.println(aprioriCAR.toString());
                        foundCARRules = true;
                        break;
                    }
                    
                } catch (Exception e) {
                    System.out.printf("Error with support=%.3f, confidence=%.3f: %s\n", 
                                    support, confidence, e.getMessage());
                }
            }
            if (foundCARRules) break;
        }
        
        if (!foundCARRules) {
            System.out.println("\n❌ No Class Association Rules found with current thresholds.");
            System.out.println("Try:\n" +
                             "1. Reducing support/confidence thresholds\n" +
                             "2. Increasing discretization bins\n" +
                             "3. Using different feature selection");
        }
    }

    /**
     * Mines general association rules (feature relationships) - OPTIMIZED FOR SPEED
     * Format: feature_pattern => other_feature_pattern
     */
    private static void mineGeneralAssociationRules(Instances data) throws Exception {
        System.out.println("\n=== GENERAL ASSOCIATION RULES (Fast Mode) ===");
        System.out.println("Mining relationships between features (class attribute removed)");
        
        Instances generalData = new Instances(data);
        
        // OPTIMIZATION 1: Sample data if too large (speed up processing)
        if (generalData.numInstances() > 5000) {
            generalData.randomize(new java.util.Random(Config.SEED));
            int sampleSize = Math.min(3000, generalData.numInstances()); // Use max 3000 instances
            Instances sampledData = new Instances(generalData, 0, sampleSize);
            generalData = sampledData;
            System.out.println("Sampled " + sampleSize + " instances for faster processing");
        }
        
        // Remove class attribute for general rule mining
        Remove removeClass = new Remove();
        removeClass.setAttributeIndices(String.valueOf(generalData.classIndex() + 1)); // 1-based
        removeClass.setInputFormat(generalData);
        Instances noClassData = Filter.useFilter(generalData, removeClass);
        noClassData.setClassIndex(-1);
        
        // OPTIMIZATION 2: Keep only most important features (reduce search space)
        String[] keyFeatures = {
            "length_url", "length_hostname", "nb_dots", "nb_hyphens", 
            "ratio_intHyperlinks", "ratio_extHyperlinks", "domain_age", "dns_record"
        };
        
        java.util.ArrayList<Integer> keepIndices = new java.util.ArrayList<>();
        for (String featureName : keyFeatures) {
            Attribute attr = noClassData.attribute(featureName);
            if (attr != null) {
                keepIndices.add(attr.index() + 1); // 1-based
            }
        }
        
        if (!keepIndices.isEmpty()) {
            java.util.Collections.sort(keepIndices);
            StringBuilder keepSpec = new StringBuilder();
            for (int i = 0; i < keepIndices.size(); i++) {
                if (i > 0) keepSpec.append(",");
                keepSpec.append(keepIndices.get(i));
            }
            
            Remove keepSelected = new Remove();
            keepSelected.setInvertSelection(true); // Keep selected
            keepSelected.setAttributeIndices(keepSpec.toString());
            keepSelected.setInputFormat(noClassData);
            noClassData = Filter.useFilter(noClassData, keepSelected);
            System.out.println("Using " + noClassData.numAttributes() + " key features for speed");
        }
        
        // OPTIMIZATION 3: Use fewer bins for faster discretization
        Discretize discretizeGeneral = new Discretize();
        discretizeGeneral.setUseBinNumbers(true);
        discretizeGeneral.setBins(3); // Reduced from Config.RULES_BINS to 3 for speed
        discretizeGeneral.setBinRangePrecision(6); // Reduced precision
        discretizeGeneral.setInputFormat(noClassData);
        Instances discretizedGeneral = Filter.useFilter(noClassData, discretizeGeneral);
        
        // OPTIMIZATION 4: Try multiple fast configurations with timeout
        double[][] fastConfigs = {
            {0.15, 1.5}, // {support, lift} - Most restrictive (fastest)
            {0.12, 1.3}, // Medium restrictive
            {0.10, 1.2}  // Least restrictive (if others fail)
        };
        
        boolean foundRules = false;
        long maxTimePerTry = 30000; // 30 seconds max per configuration
        
        for (double[] config : fastConfigs) {
            double support = config[0];
            double lift = config[1];
            
            try {
                System.out.printf("Trying fast config: support=%.2f, lift=%.1f (max %ds)...\n", 
                                support, lift, maxTimePerTry/1000);
                
                Apriori aprioriGeneral = new Apriori();
                
                // Configure for speed
                aprioriGeneral.setCar(false);
                aprioriGeneral.setMetricType(new SelectedTag(1, Apriori.TAGS_SELECTION)); // Lift
                aprioriGeneral.setMinMetric(lift);
                aprioriGeneral.setLowerBoundMinSupport(support);
                aprioriGeneral.setNumRules(15); // Reduced from 20
                aprioriGeneral.setDelta(0.05); // Increased delta for speed
                
                long startTime = System.currentTimeMillis();
                
                // Create a timeout mechanism
                Thread miningThread = new Thread(() -> {
                    try {
                        aprioriGeneral.buildAssociations(discretizedGeneral);
                    } catch (Exception e) {
                        // Handle in main thread
                    }
                });
                
                miningThread.start();
                miningThread.join(maxTimePerTry); // Wait max 30 seconds
                
                if (miningThread.isAlive()) {
                    miningThread.interrupt();
                    System.out.println("Timeout reached, trying next configuration...");
                    continue;
                }
                
                long endTime = System.currentTimeMillis();
                long elapsedTime = endTime - startTime;
                
                String rulesOutput = aprioriGeneral.toString();
                if (rulesOutput.contains("==>")) {
                    System.out.printf("\n✅ General Association Rules (mined in %d ms):\n", elapsedTime);
                    System.out.println("Relationships between features:\n");
                    System.out.println(rulesOutput);
                    foundRules = true;
                    break;
                } else {
                    System.out.println("No rules found with this configuration, trying next...");
                }
                
            } catch (Exception e) {
                System.out.printf("Error with support=%.2f, lift=%.1f: %s\n", 
                                support, lift, e.getMessage());
            }
        }
        
        if (!foundRules) {
            System.out.println("\n⚠️  General Association Rules: Using fallback quick mode");
            quickFallbackRules(discretizedGeneral);
        }
    }
    
    /**
     * Fallback method for very fast rule generation with minimal constraints
     */
    private static void quickFallbackRules(Instances data) throws Exception {
        try {
            Apriori quickApriori = new Apriori();
            quickApriori.setCar(false);
            quickApriori.setMetricType(new SelectedTag(0, Apriori.TAGS_SELECTION)); // Confidence (faster than lift)
            quickApriori.setMinMetric(0.6); // Lower confidence
            quickApriori.setLowerBoundMinSupport(0.2); // Higher support (faster)
            quickApriori.setNumRules(10); // Fewer rules
            quickApriori.setDelta(0.1); // Larger delta
            
            System.out.println("Quick fallback: support≥0.2, confidence≥0.6, max 10 rules");
            
            long startTime = System.currentTimeMillis();
            quickApriori.buildAssociations(data);
            long endTime = System.currentTimeMillis();
            
            String output = quickApriori.toString();
            if (output.contains("==>")) {
                System.out.printf("✅ Fallback rules found (%d ms):\n", (endTime - startTime));
                System.out.println(output);
            } else {
                System.out.println("❌ No association rules found even with relaxed constraints");
                System.out.println("Dataset may be too sparse or need different preprocessing");
            }
            
        } catch (Exception e) {
            System.out.println("❌ Fallback rule mining failed: " + e.getMessage());
        }
    }
}
