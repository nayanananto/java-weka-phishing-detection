package org.example.phishingweka;

public final class Config {
    private Config() {}

    // Paths
    public static final String DATASET_PATH = "data/phishing.csv";
    public static final String MODEL_PATH   = "output/phishing_best.model";

    // General
    public static final int    CV_FOLDS     = 10;
    public static final long   SEED         = 1L;

    // Preprocessing
    public static final boolean USE_SMOTE   = true;

    // Clustering
    public static final int    KMEANS_K    = 3;
    public static final int    KMEANS_MAX_ITERS = 100;

    // Rules
    public static final boolean RUN_RULES  = true;
    public static final int     RULES_DOWNSAMPLE_PERCENT = 30;  // rules-only
    public static final int     RULES_BINS = 4;                 // discretization bins (fast & stable)
}
