package org.example.phishingweka;

import weka.core.*;
import weka.core.converters.ConverterUtils.DataSource;
import weka.core.converters.ArffSaver;

import weka.filters.Filter;
import weka.filters.unsupervised.attribute.Remove;
import weka.filters.unsupervised.attribute.RemoveUseless;
import weka.filters.unsupervised.attribute.Normalize;
import weka.filters.unsupervised.attribute.ReplaceMissingValues;
//import weka.filters.supervised.instance.SMOTE;

import java.io.File;

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
        Utils.printFirstValues(raw);
        return raw;
    }

    public static Instances preprocess(Instances raw) throws Exception {
        Instances data = new Instances(raw);

        // Drop high-cardinality 'url' if present (acts like an ID)
        Attribute url = data.attribute("url");
        if (url != null) {
            Remove rm = new Remove();
            rm.setAttributeIndicesArray(new int[]{url.index()});
            rm.setInputFormat(data);
            data = Filter.useFilter(data, rm);
            data.setClassIndex(data.numAttributes() - 1);
            System.out.println("Removed attribute: url");
        }

        // Replace missing
        ReplaceMissingValues rmv = new ReplaceMissingValues();
        rmv.setInputFormat(data);
        data = Filter.useFilter(data, rmv);

        // Remove useless attrs
        RemoveUseless ru = new RemoveUseless();
        ru.setInputFormat(data);
        data = Filter.useFilter(data, ru);

        // Normalize numeric
        Normalize norm = new Normalize();
        norm.setInputFormat(data);
        data = Filter.useFilter(data, norm);

        // Optional SMOTE for imbalance (binary class)
        if (Config.USE_SMOTE && data.classAttribute().isNominal()) {
            int[] dist = data.attributeStats(data.classIndex()).nominalCounts;
            int min = Integer.MAX_VALUE, max = -1;
            for (int c : dist) { if (c < min) min = c; if (c > max) max = c; }
            boolean imbalanced = (dist.length == 2) && (min < 0.4 * max);
            if (imbalanced) {
//                System.out.println("Imbalance detected → applying SMOTE(100%)");
//                SMOTE sm = new SMOTE();
//                sm.setPercentage(100);
//                sm.setNearestNeighbors(5);
//                sm.setInputFormat(data);
//                data = Filter.useFilter(data, sm);
            } else {
                System.out.println("No severe imbalance → SMOTE skipped.");
            }
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
        System.out.println("Saved ARFF → " + outPath);
    }
}
