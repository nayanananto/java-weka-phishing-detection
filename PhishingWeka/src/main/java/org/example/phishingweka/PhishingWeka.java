package org.example.phishingweka;

import weka.core.*;
import weka.classifiers.Classifier;

public class PhishingWeka {
    public static void main(String[] args) throws Exception {
        // (i) Data prep
        Instances raw  = DataPrep.loadCsv(Config.DATASET_PATH);
        Instances data = DataPrep.preprocess(raw);
        // Optional: write ARFF
        // DataPrep.saveArff(data, "output/phishing_preproc.arff");

        // (ii) Exploratory analysis (basic) is already printed; add class distribution:
        if (data.classAttribute().isNominal()) {
            int[] dist = data.attributeStats(data.classIndex()).nominalCounts;
            System.out.println("\n=== Class Distribution ===");
            for (int i = 0; i < data.classAttribute().numValues(); i++) {
                System.out.printf("  %s: %d%n", data.classAttribute().value(i), dist[i]);
            }
        }

        // (iii) Supervised: compare RF/J48/SMO with 10-fold CV; save best
        Classifier best = SupervisedTrainer.trainAndSelect(data);

        // (iv) Unsupervised: k-means + interpretation
        ClusterModule.runKMeans(data);

        // (v) Association rules: CAR Apriori (auto-relax) → JRip fallback
        RulesModule.mine(data);

        System.out.println("\nAll done ✅");
    }
}
