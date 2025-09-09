package org.example.phishingweka;

import weka.associations.Apriori;
import weka.core.Attribute;
import weka.core.Instances;
import weka.core.SelectedTag;
import weka.filters.Filter;
import weka.filters.unsupervised.attribute.ClassAssigner;
import weka.filters.unsupervised.attribute.Discretize;
import weka.filters.unsupervised.attribute.Remove;
import weka.filters.unsupervised.attribute.Reorder;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Random;

/**
 * Association rule mining:
 *  - CAR (RHS == class, here status=phishing/legitimate)
 *  - General feature<->feature rules
 *
 * Notes:
 *  - No resampling in CAR path. Your 50:50 balance is preserved.
 *  - We sweep support/confidence and (if needed) relax further until >=K phishing rules appear.
 */
public final class RulesModule {

    // ----------------------------- Tunables ----------------------------------
    private static final int    SEED                = 42;
    private static final int    DISC_BINS_CAR       = 4;     // try 5-6 to sharpen phishing signals
    private static final int    DISC_BINS_GENERAL   = 3;
    private static final int    MAX_RULES_CAR       = 120;   // allow more tail rules
    private static final int    MAX_RULES_GENERAL   = 15;
    private static final long   GENERAL_TIMEOUT_MS  = 30_000;

    

    // Keep-list to speed things up (class is appended automatically)
    private static final String[] IMPORTANT_FEATURES = new String[]{
            "length_url","length_hostname","ip","nb_dots","nb_hyphens",
            "ratio_intHyperlinks","ratio_extHyperlinks","links_in_tags",
            "safe_anchor","domain_age","domain_registration_length",
            "dns_record","google_index"
    };

    private RulesModule() {}

    // ------------------------------------------------------------------------

    public static void mine(Instances data) throws Exception {
        System.out.println("\n=== ASSOCIATION RULE MINING ===");
        mineClassAssociationRules(data);
        mineGeneralAssociationRules(data);
    }

    // ------------------------------------------------------------------------
    // 1) CLASS ASSOCIATION RULES (CAR)
    // ------------------------------------------------------------------------

    private static void mineClassAssociationRules(Instances data) throws Exception {
        System.out.println("\n=== CLASS ASSOCIATION RULES (CAR) ===");

        // 1) Force class to be 'status' (or 'cls_label') and move to last
        Instances d = forceStatusAsClass(data);
        System.out.printf("Target attribute for CAR: %s (index=%d of %d)\n",
                d.classAttribute().name(), d.classIndex(), d.numAttributes());

        // Optional: keep a focused subset (class is kept automatically)
        d = keepImportantPlusClass(d, IMPORTANT_FEATURES);

        // Ensure class is last after keep-list
        d = moveClassToLast(d);

        // 2) Discretize ONLY non-class attributes
        d = discretizeIgnoreClass(d, DISC_BINS_CAR);

        // Quick visibility of class counts to confirm 50:50 remains
        printClassCounts(d);

        System.out.println("Data prepared for CAR: " + d.numInstances() + " instances, " + d.numAttributes() + " attributes");

        boolean metTarget = false;
        String clsName = d.classAttribute().name();
        String phishingRHS = clsName + "=phishing";

        // 3) Primary sweep (support x confidence)
        Apriori apr = new Apriori();
apr.setCar(true);
apr.setMinMetric(0.9);          // confidence threshold
apr.setLowerBoundMinSupport(0.05); // support threshold
apr.setNumRules(120);           // maximum number of rules
apr.setDelta(0.01);

apr.buildAssociations(d);
System.out.println(apr.toString());


       
        
    }

    // ------------------------------------------------------------------------
    // 2) GENERAL (feature<->feature) RULES
    // ------------------------------------------------------------------------

    private static void mineGeneralAssociationRules(Instances data) throws Exception {
        System.out.println("\n=== GENERAL ASSOCIATION RULES (Fast Mode) ===");
        System.out.println("Mining relationships between features (class removed)");

        Instances d = new Instances(data);

        // Optional downsampling ONLY for general rules
        if (d.numInstances() > 5000) {
            d.randomize(new Random(SEED));
            int sampleSize = Math.min(3000, d.numInstances());
            d = new Instances(d, 0, sampleSize);
            System.out.println("Sampled " + sampleSize + " instances for faster processing");
        }

        // Remove class if present
        if (d.classIndex() >= 0) {
            Remove rm = new Remove();
            rm.setAttributeIndices(String.valueOf(d.classIndex() + 1));
            rm.setInputFormat(d);
            d = Filter.useFilter(d, rm);
            d.setClassIndex(-1);
        }

        // Optional small keep-list for speed
        d = keepImportantNoClass(d, new String[]{
                "length_url","length_hostname","nb_dots","nb_hyphens",
                "ratio_intHyperlinks","ratio_extHyperlinks","domain_age","dns_record"
        });

        // Discretize all (no class here)
        d = discretizeAll(d, DISC_BINS_GENERAL);

        double[][] configs = {{0.15, 1.5}, {0.12, 1.3}, {0.10, 1.2}};
        boolean ok = false;

        for (double[] cfg : configs) {
            final double sup = cfg[0], lift = cfg[1];
            try {
                System.out.printf("Trying fast config: support=%.2f, lift=%.1f (timeout %ds)...\n",
                        sup, lift, (int)(GENERAL_TIMEOUT_MS / 1000));

                Apriori ap = new Apriori();
                ap.setCar(false);
                ap.setMetricType(new SelectedTag(1, Apriori.TAGS_SELECTION)); // Lift
                ap.setMinMetric(lift);
                ap.setLowerBoundMinSupport(sup);
                ap.setNumRules(MAX_RULES_GENERAL);
                ap.setDelta(0.05);

                final Instances finalD = d;
                Thread th = new Thread(() -> {
                    try { ap.buildAssociations(finalD); } catch (Exception ignored) {}
                });
                long t0 = System.currentTimeMillis();
                th.start();
                th.join(GENERAL_TIMEOUT_MS);
                if (th.isAlive()) {
                    th.interrupt();
                    System.out.println("Timeout reached, trying next configuration...");
                    continue;
                }
                long t1 = System.currentTimeMillis();

                String out = ap.toString();
                if (hasAnyRule(out)) {
                    System.out.printf("\n✅ General Association Rules (mined in %d ms):\n", (t1 - t0));
                    System.out.println(out);
                    ok = true;
                    break;
                } else {
                    System.out.println("No rules found, trying next...");
                }
            } catch (Exception e) {
                System.out.printf("Error (support=%.2f, lift=%.1f): %s\n", sup, lift, e.getMessage());
            }
        }

        if (!ok) quickFallbackRules(d);
    }

    // ------------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------------

    /** Choose class by name (status preferred, cls_label fallback) and move it to LAST column. */
    private static Instances forceStatusAsClass(Instances in) throws Exception {
        Instances d = new Instances(in);

        String className = null;
        if (d.attribute("status") != null) className = "status";
        else if (d.attribute("cls_label") != null) className = "cls_label";

        if (className != null) {
            ClassAssigner ca = new ClassAssigner();
//            ca.setClassName(className);
            ca.setClassIndex("last");
            ca.setInputFormat(d);
            d = Filter.useFilter(d, ca);
        } else {
            if (d.classIndex() < 0) d.setClassIndex(d.numAttributes() - 1);
            d = moveClassToLast(d);
        }

        System.out.printf("AFTER ClassAssigner: class=%s @%d of %d\n",
                d.classAttribute().name(), d.classIndex(), d.numAttributes());
        return d;
    }

    /** Keep curated attributes plus the class. */
    private static Instances keepImportantPlusClass(Instances d, String[] names) throws Exception {
        ArrayList<Integer> keep = new ArrayList<>();
        for (String n : names) {
            Attribute a = d.attribute(n);
            if (a != null) keep.add(a.index() + 1); // 1-based
        }
        if (d.classIndex() >= 0) {
            int cls1 = d.classIndex() + 1;
            if (!keep.contains(cls1)) keep.add(cls1);
        }
        if (keep.isEmpty()) return d;

        Collections.sort(keep);
        StringBuilder spec = new StringBuilder();
        for (int i = 0; i < keep.size(); i++) {
            if (i > 0) spec.append(",");
            spec.append(keep.get(i));
        }
        Remove r = new Remove();
        r.setInvertSelection(true);
        r.setAttributeIndices(spec.toString());
        r.setInputFormat(d);
        Instances out = Filter.useFilter(d, r);
        if (out.attribute(d.classAttribute().name()) != null) {
            out.setClassIndex(out.attribute(d.classAttribute().name()).index());
        }
        return out;
    }

    /** Keep curated attributes (no class in this branch). */
    private static Instances keepImportantNoClass(Instances d, String[] names) throws Exception {
        ArrayList<Integer> keep = new ArrayList<>();
        for (String n : names) {
            Attribute a = d.attribute(n);
            if (a != null) keep.add(a.index() + 1);
        }
        if (keep.isEmpty()) return d;

        Collections.sort(keep);
        StringBuilder spec = new StringBuilder();
        for (int i = 0; i < keep.size(); i++) {
            if (i > 0) spec.append(",");
            spec.append(keep.get(i));
        }
        Remove r = new Remove();
        r.setInvertSelection(true);
        r.setAttributeIndices(spec.toString());
        r.setInputFormat(d);
        return Filter.useFilter(d, r);
    }

    /** Ensure class is last column. */
    private static Instances moveClassToLast(Instances d) throws Exception {
        if (d.classIndex() < 0) return d;

        int clsOneBased = d.classIndex() + 1;
        StringBuilder order = new StringBuilder();
        for (int i = 1; i <= d.numAttributes(); i++) {
            if (i != clsOneBased) {
                if (order.length() > 0) order.append(",");
                order.append(i);
            }
        }
        order.append(",").append(clsOneBased);

        Reorder ro = new Reorder();
        ro.setAttributeIndices(order.toString());
        ro.setInputFormat(d);
        Instances out = Filter.useFilter(d, ro);
        out.setClassIndex(out.numAttributes() - 1);
        return out;
    }

    /** Discretize all non-class numeric attributes; leave class untouched. */
    private static Instances discretizeIgnoreClass(Instances d, int bins) throws Exception {
        Discretize disc = new Discretize();
        disc.setUseBinNumbers(true);
        disc.setBins(bins);
        disc.setIgnoreClass(true);
        disc.setInputFormat(d);
        Instances out = Filter.useFilter(d, disc);
        out.setClassIndex(out.numAttributes() - 1);
        return out;
    }

    /** Discretize all attributes (used when no class is present). */
    private static Instances discretizeAll(Instances d, int bins) throws Exception {
        Discretize disc = new Discretize();
        disc.setUseBinNumbers(true);
        disc.setBins(bins);
        disc.setInputFormat(d);
        return Filter.useFilter(d, disc);
    }

    /** Quick check if WEKA printed any rules. */
    private static boolean hasAnyRule(String aprioriToString) {
        return aprioriToString != null && aprioriToString.contains("==>");
    }

    /** Count rules whose RHS starts with the given prefix, e.g., "status=phishing". */
    @SuppressWarnings("rawtypes")
    

    /** Fallback general rules with relaxed constraints. */
    private static void quickFallbackRules(Instances d) throws Exception {
        try {
            Apriori ap = new Apriori();
            ap.setCar(false);
            ap.setMetricType(new SelectedTag(0, Apriori.TAGS_SELECTION)); // Confidence
            ap.setMinMetric(0.6);
            ap.setLowerBoundMinSupport(0.2);
            ap.setNumRules(10);
            ap.setDelta(0.1);

            System.out.println("Quick fallback: support≥0.2, confidence≥0.6, max 10 rules");
            long t0 = System.currentTimeMillis();
            ap.buildAssociations(d);
            long t1 = System.currentTimeMillis();

            String out = ap.toString();
            if (hasAnyRule(out)) {
                System.out.printf("✅ Fallback rules found (%d ms):\n", (t1 - t0));
                System.out.println(out);
            } else {
                System.out.println("❌ No association rules found even with relaxed constraints.");
            }
        } catch (Exception e) {
            System.out.println("❌ Fallback rule mining failed: " + e.getMessage());
        }
    }

    /** Debug: show class distribution to confirm no sampling. */
    private static void printClassCounts(Instances d) {
        if (d.classIndex() < 0) return;
        int[] cnt = new int[d.classAttribute().numValues()];
        for (int i = 0; i < d.numInstances(); i++) {
            cnt[(int) d.instance(i).classValue()]++;
        }
        System.out.print("Class counts → ");
        for (int v = 0; v < d.classAttribute().numValues(); v++) {
            if (v > 0) System.out.print(", ");
            System.out.print("'" + d.classAttribute().value(v) + "'=" + cnt[v]);
        }
        System.out.println();
    }
}
