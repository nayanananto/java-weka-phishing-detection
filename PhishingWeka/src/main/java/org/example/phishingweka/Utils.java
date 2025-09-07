package org.example.phishingweka;

import weka.core.*;

public final class Utils {
    private Utils() {}

    public static void printFirstValues(Instances data) {
        if (data == null || data.numInstances() == 0) return;
        Instance first = data.firstInstance();
        System.out.println("\n=== First-row preview (name = value) ===");
        for (int i = 0; i < data.numAttributes(); i++) {
            Attribute a = data.attribute(i);
            String v;
            if (first.isMissing(i)) v = "?";
            else if (a.isNumeric()) v = String.format("%.4f", first.value(i));
            else if (a.isNominal()) {
                int idx = (int) first.value(i);
                v = (idx >= 0 && idx < a.numValues()) ? a.value(idx) : "?";
            } else v = first.toString(i);
            System.out.println("  [" + i + "] " + a.name() + " = " + v);
        }
    }

    public static int pickPositiveIndex(Instances data) {
        Attribute c = data.classAttribute();
        if (c.isNominal() && c.numValues() == 2) {
            int[] cnt = data.attributeStats(data.classIndex()).nominalCounts;
            if (cnt[0] < cnt[1]) return 0;
            if (cnt[1] < cnt[0]) return 1;
            // tie fallback: commonly 'phishing' is index 1
            return 1;
        }
        return c.numValues() - 1;
    }

    public static void printConfusion(double[][] cm, Attribute cls) {
        System.out.print("            ");
        for (int j = 0; j < cm.length; j++) System.out.printf("%12s", cls.value(j));
        System.out.println();
        for (int i = 0; i < cm.length; i++) {
            System.out.printf("%12s", cls.value(i));
            for (int j = 0; j < cm[i].length; j++) System.out.printf("%12d", (int) cm[i][j]);
            System.out.println();
        }
    }
}
