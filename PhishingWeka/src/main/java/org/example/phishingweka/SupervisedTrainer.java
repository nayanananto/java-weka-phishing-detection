package org.example.phishingweka;

import weka.core.*;
import weka.classifiers.*;
import weka.classifiers.trees.RandomForest;
import weka.classifiers.trees.J48;
import weka.classifiers.functions.SMO;
import weka.classifiers.trees.REPTree;
import weka.classifiers.functions.LinearRegression;

import java.util.Random;
import java.util.ArrayList;

public final class SupervisedTrainer {
    private SupervisedTrainer() {}

    public static Classifier trainAndSelect(Instances data) throws Exception {
        // Debug: Print class information first
        System.out.println("\n=== CLASS ANALYSIS ===");
        System.out.println("Class attribute: " + data.classAttribute().name());
        System.out.println("Class index: " + data.classIndex());
        System.out.println("Class type: " + (data.classAttribute().isNominal() ? "Nominal" : "Numeric"));
        
        if (data.classAttribute().isNominal()) {
            System.out.println("Class values:");
            for (int i = 0; i < data.classAttribute().numValues(); i++) {
                System.out.println("  [" + i + "] " + data.classAttribute().value(i));
            }
            
            // Print class distribution
            int[] dist = data.attributeStats(data.classIndex()).nominalCounts;
            System.out.println("Class distribution:");
            for (int i = 0; i < dist.length; i++) {
                System.out.printf("  %s: %d instances\n", 
                                data.classAttribute().value(i), dist[i]);
            }
            
            return trainClassificationModels(data);
        } else {
            System.out.println("Numeric class detected - treating as regression problem");
            return trainRegressionModels(data);
        }
    }

    /**
     * Train classification models for nominal class attributes
     */
    private static Classifier trainClassificationModels(Instances data) throws Exception {
        ArrayList<Classifier> models = new ArrayList<>();
        ArrayList<String> names = new ArrayList<>();

        // Add Random Forest (works with both nominal and numeric classes)
        RandomForest rf = new RandomForest();
        rf.setMaxDepth(0);
        rf.setNumFeatures(0);
        rf.setNumIterations(100);
        models.add(rf);
        names.add("RandomForest");

        // Add J48 (only for nominal classes)
        J48 j48 = new J48();
        j48.setUnpruned(false);
        j48.setConfidenceFactor(0.15f);
        j48.setMinNumObj(5);
        models.add(j48);
        names.add("J48");

        // Add SMO (only for nominal classes)
        SMO smo = new SMO();
        // Use default parameters - they work well for most cases
        models.add(smo);
        names.add("SMO");

        // Add REPTree as additional option
        REPTree rep = new REPTree();
        rep.setMaxDepth(-1);
        rep.setMinNum(2.0);
        models.add(rep);
        names.add("REPTree");

        return evaluateAndSelectBest(models, names, data, true);
    }

    /**
     * Train regression models for numeric class attributes
     */
    private static Classifier trainRegressionModels(Instances data) throws Exception {
        ArrayList<Classifier> models = new ArrayList<>();
        ArrayList<String> names = new ArrayList<>();

        // Add Random Forest (works with both)
        RandomForest rf = new RandomForest();
        rf.setMaxDepth(0);
        rf.setNumFeatures(0);
        models.add(rf);
        names.add("RandomForest");

        // Add Linear Regression
        LinearRegression lr = new LinearRegression();
        lr.setAttributeSelectionMethod(new SelectedTag(1, LinearRegression.TAGS_SELECTION));
        models.add(lr);
        names.add("LinearRegression");

        // Add REPTree for regression
        REPTree rep = new REPTree();
        rep.setMaxDepth(-1);
        rep.setMinNum(2.0);
        models.add(rep);
        names.add("REPTree");

        return evaluateAndSelectBest(models, names, data, false);
    }

    /**
     * Evaluate models and select the best one
     */
    private static Classifier evaluateAndSelectBest(ArrayList<Classifier> models, ArrayList<String> names, 
                                                   Instances data, boolean isClassification) throws Exception {
        
        int bestIdx = 0;
        double bestScore = isClassification ? -1 : Double.MAX_VALUE; // F1 for classification, RMSE for regression

        System.out.println("\n=== " + Config.CV_FOLDS + "-fold CV on preprocessed data ===");
        
        for (int i = 0; i < models.size(); i++) {
            System.out.println("\n--- " + names.get(i) + " ---");
            
            try {
                Evaluation ev = new Evaluation(data);
                ev.crossValidateModel(models.get(i), data, Config.CV_FOLDS, new Random(Config.SEED));

                if (isClassification) {
                    evaluateClassificationModel(ev, data, i, names, bestScore, bestIdx);
                    
                    // Update best model based on F1 or accuracy
                    double score = getBestClassificationScore(ev, data);
                    if (score > bestScore) {
                        bestScore = score;
                        bestIdx = i;
                    }
                } else {
                    evaluateRegressionModel(ev, i, names);
                    
                    // Update best model based on RMSE (lower is better)
                    double rmse = ev.rootMeanSquaredError();
                    if (!Double.isNaN(rmse) && rmse < bestScore) {
                        bestScore = rmse;
                        bestIdx = i;
                    }
                }
                
            } catch (Exception model_error) {
                System.out.println("❌ Error training " + names.get(i) + ": " + model_error.getMessage());
                // Don't print stack trace for known issues like "cannot handle numeric class"
                if (!model_error.getMessage().contains("Cannot handle numeric class")) {
                    model_error.printStackTrace();
                }
            }
        }

        // Select best model
        if (bestScore == (isClassification ? -1 : Double.MAX_VALUE)) {
            System.out.println("\n⚠️ No valid models found. Using first available model as fallback.");
            bestIdx = 0;
        }

        // Train best model on full data
        System.out.println("\n=== BEST MODEL SELECTION ===");
        System.out.println("Selected model: " + names.get(bestIdx));
        if (isClassification && bestScore != -1) {
            System.out.printf("Best score: %.4f\n", bestScore);
        } else if (!isClassification && bestScore != Double.MAX_VALUE) {
            System.out.printf("Best RMSE: %.4f\n", bestScore);
        }
        
        Classifier best = AbstractClassifier.makeCopy(models.get(bestIdx));
        
        try {
            best.buildClassifier(data);
            System.out.println("✅ Best model trained successfully on full dataset");
        } catch (Exception training_error) {
            System.out.println("❌ Error training best model: " + training_error.getMessage());
            throw training_error;
        }

        // Persist model
        try {
            weka.core.SerializationHelper.write(Config.MODEL_PATH, best);
            System.out.println("✅ Model saved → " + Config.MODEL_PATH);
        } catch (Exception save_error) {
            System.out.println("⚠️ Error saving model: " + save_error.getMessage());
        }

        // Test model loading
        testModelLoading(data);

        return best;
    }

    private static void evaluateClassificationModel(Evaluation ev, Instances data, int modelIndex, 
                                                   ArrayList<String> names, double bestScore, int bestIdx) {
        // Print basic metrics
        System.out.printf("Accuracy: %.4f\n", (1.0 - ev.errorRate()));
        System.out.printf("Instances classified: %.0f\n", ev.numInstances());
        
        if (data.classAttribute().isNominal()) {
            try {
                int positiveIndex = Utils.pickPositiveIndex(data);
                
                double precision = ev.precision(positiveIndex);
                double recall = ev.recall(positiveIndex);
                double f1 = ev.fMeasure(positiveIndex);
                
                System.out.printf("Precision(%s): %.4f\n", 
                                data.classAttribute().value(positiveIndex), 
                                Double.isNaN(precision) ? 0.0 : precision);
                System.out.printf("Recall(%s): %.4f\n", 
                                data.classAttribute().value(positiveIndex), 
                                Double.isNaN(recall) ? 0.0 : recall);
                System.out.printf("F1(%s): %.4f\n", 
                                data.classAttribute().value(positiveIndex), 
                                Double.isNaN(f1) ? 0.0 : f1);
                
                // AUC calculation
                try {
                    double auc = ev.areaUnderROC(positiveIndex);
                    System.out.printf("AUC(%s): %.4f\n", 
                                    data.classAttribute().value(positiveIndex), 
                                    Double.isNaN(auc) ? 0.0 : auc);
                } catch (Exception auc_error) {
                    System.out.println("AUC: N/A");
                }
                
            } catch (Exception metric_error) {
                System.out.println("Class-specific metrics: N/A (calculation error)");
            }
        }
        
        // Print confusion matrix
        System.out.println("Confusion Matrix:");
        try {
            Utils.printConfusion(ev.confusionMatrix(), data.classAttribute());
        } catch (Exception cm_error) {
            System.out.println("Cannot display confusion matrix: " + cm_error.getMessage());
        }
    }

    private static void evaluateRegressionModel(Evaluation ev, int modelIndex, ArrayList<String> names) {
        System.out.printf("RMSE: %.4f\n", ev.rootMeanSquaredError());
        System.out.printf("MAE: %.4f\n", ev.meanAbsoluteError());
        System.out.printf("R²: %.4f\n", 1.0 - (ev.errorRate())); // Approximation
        System.out.printf("Mean target value: %.4f\n", ev.unclassified()); // Mean target
    }

    private static double getBestClassificationScore(Evaluation ev, Instances data) {
        try {
            int positiveIndex = Utils.pickPositiveIndex(data);
            double f1 = ev.fMeasure(positiveIndex);
            
            if (!Double.isNaN(f1)) {
                return f1;
            }
            
            // Fallback to accuracy
            return (1.0 - ev.errorRate());
            
        } catch (Exception e) {
            // Last resort: use accuracy
            return (1.0 - ev.errorRate());
        }
    }

    private static void testModelLoading(Instances data) {
        try {
            Classifier loaded = (Classifier) weka.core.SerializationHelper.read(Config.MODEL_PATH);
            
            if (data.numInstances() > 0) {
                double pred = loaded.classifyInstance(data.firstInstance());
                
                if (data.classAttribute().isNominal() && pred >= 0 && pred < data.classAttribute().numValues()) {
                    String label = data.classAttribute().value((int) pred);
                    System.out.println("✅ Model reloaded → first instance prediction: " + label);
                } else {
                    System.out.printf("✅ Model reloaded → first instance prediction: %.4f\n", pred);
                }
            } else {
                System.out.println("✅ Model reloaded successfully (no test instances)");
            }
        } catch (Exception reload_error) {
            System.out.println("⚠️ Error testing model reload: " + reload_error.getMessage());
        }
    }
}