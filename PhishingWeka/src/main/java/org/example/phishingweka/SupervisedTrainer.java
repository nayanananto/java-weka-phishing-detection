package org.example.phishingweka;

import weka.core.*;
import weka.classifiers.*;
import weka.classifiers.trees.RandomForest;
import weka.classifiers.trees.J48;
import weka.classifiers.functions.SMO;

import java.util.Random;

public final class SupervisedTrainer {
    private SupervisedTrainer() {}

    public static Classifier trainAndSelect(Instances data) throws Exception {
        Classifier[] models = new Classifier[]{ new RandomForest(), new J48(), new SMO() };
        String[] names = {"RandomForest", "J48", "SMO"};

        // Reasonable defaults
//        ((RandomForest) models[0]).setNumTrees(300);
        ((RandomForest) models[0]).setMaxDepth(0);
        ((RandomForest) models[0]).setNumFeatures(0);

        ((J48) models[1]).setUnpruned(false);
        ((J48) models[1]).setConfidenceFactor(0.15f);
        ((J48) models[1]).setMinNumObj(5);

        int bestIdx = 0;
        double bestF1 = -1;

        System.out.println("\n=== " + Config.CV_FOLDS + "-fold CV on preprocessed data ===");
        for (int i = 0; i < models.length; i++) {
            Evaluation ev = new Evaluation(data);
            ev.crossValidateModel(models[i], data, Config.CV_FOLDS, new Random(Config.SEED));

            int pos = Utils.pickPositiveIndex(data);
            System.out.println("\n--- " + names[i] + " ---");
            System.out.printf("Accuracy: %.4f%n", (1.0 - ev.errorRate()));
            System.out.printf("Precision(%s): %.4f%n", data.classAttribute().value(pos), ev.precision(pos));
            System.out.printf("Recall(%s): %.4f%n", data.classAttribute().value(pos), ev.recall(pos));
            System.out.printf("F1(%s): %.4f%n", data.classAttribute().value(pos), ev.fMeasure(pos));
            try { System.out.printf("AUC(%s): %.4f%n", data.classAttribute().value(pos), ev.areaUnderROC(pos)); }
            catch (Exception ignore) {}
            System.out.println("Confusion Matrix:");
            Utils.printConfusion(ev.confusionMatrix(), data.classAttribute());

            double f1 = ev.fMeasure(pos);
            if (!Double.isNaN(f1) && f1 > bestF1) { bestF1 = f1; bestIdx = i; }
        }

        // Train best on full data
        Classifier best = AbstractClassifier.makeCopy(models[bestIdx]);
        best.buildClassifier(data);
        System.out.println("\n✅ Best model: " + names[bestIdx]);

        // Persist
        weka.core.SerializationHelper.write(Config.MODEL_PATH, best);
        System.out.println("Saved model → " + Config.MODEL_PATH);

        // Reload sanity
        Classifier loaded = (Classifier) weka.core.SerializationHelper.read(Config.MODEL_PATH);
        double pred = loaded.classifyInstance(data.firstInstance());
        String label = data.classAttribute().value((int) pred);
        System.out.println("Reloaded model → first instance prediction: " + label);

        return best;
        }
}
