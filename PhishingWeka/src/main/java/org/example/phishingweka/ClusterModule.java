package org.example.phishingweka;

import weka.core.*;
import weka.filters.Filter;
import weka.filters.unsupervised.attribute.Remove;
import weka.clusterers.SimpleKMeans;

public final class ClusterModule {
    private ClusterModule() {}

    public static void runKMeans(Instances data) throws Exception {
        // Remove class for clustering
        Instances feats = new Instances(data);
        int clsIdx = feats.classIndex();
        Remove dropClass = new Remove();
        dropClass.setAttributeIndices(String.valueOf(clsIdx + 1)); // 1-based
        dropClass.setInputFormat(feats);
        feats = Filter.useFilter(feats, dropClass);
        feats.setClassIndex(-1);

        SimpleKMeans km = new SimpleKMeans();
        km.setNumClusters(Config.KMEANS_K);
        km.setSeed((int) Config.SEED);
        km.setMaxIterations(Config.KMEANS_MAX_ITERS);
        km.buildClusterer(feats);

        // Summaries
        Instances cents = km.getClusterCentroids();
        int k = cents.numInstances(); // robust way to get k
        int[] sizes = new int[k];
        for (int i = 0; i < feats.numInstances(); i++) {
            int c = km.clusterInstance(feats.instance(i));
            if (c >= 0 && c < k) sizes[c]++;
        }

        System.out.println("\n=== KMeans (k=" + k + ") Summary ===");
        System.out.printf("Within-cluster SSE: %.4f%n", km.getSquaredError());
        System.out.print("Cluster sizes: [");
        for (int i = 0; i < k; i++) System.out.print((i>0?", ":"") + sizes[i]);
        System.out.println("]");

        // Centroid preview (first 8 attributes)
        int colsToShow = Math.min(8, cents.numAttributes());
        System.out.println("Centroid preview (first " + colsToShow + " attrs):");
        for (int ci = 0; ci < k; ci++) {
            System.out.print("  C" + ci + ": ");
            for (int a = 0; a < colsToShow; a++) {
                System.out.printf("%s=%.4f ", cents.attribute(a).name(), cents.instance(ci).value(a));
            }
            System.out.println("...");
        }

        // Cluster ↔ Class contingency (interpretation)
        int[][] table = new int[k][data.classAttribute().numValues()];
        for (int i = 0; i < feats.numInstances(); i++) {
            int c = km.clusterInstance(feats.instance(i));
            int y = (int) data.instance(i).classValue();
            table[c][y]++;
        }
        System.out.println("\nCluster ↔ Class counts:");
        for (int c = 0; c < k; c++) {
            System.out.print("Cluster " + c + ": ");
            for (int y = 0; y < table[c].length; y++) {
                System.out.print(data.classAttribute().value(y) + "=" + table[c][y] + " ");
            }
            System.out.println();
        }
    }
}
