package org.example.phishingweka;

import weka.core.Attribute;
import weka.core.Instances;

import weka.filters.Filter;
import weka.filters.unsupervised.attribute.Remove;
import weka.filters.unsupervised.attribute.Reorder;
import weka.filters.unsupervised.attribute.Discretize;

import weka.associations.Apriori;
import weka.core.SelectedTag;

import java.util.ArrayList;
import java.util.Collections;

public final class RulesModule {
    private RulesModule() {}

    /**
     * Mines association rules with Apriori.
     * 1) Tries CAR rules (consequent = status) with auto-relaxed thresholds.
     * 2) If none found, prints general Apriori rules (class dropped).
     */
    public static void mine(Instances data) throws Exception {
        // === 5) Association Rules (Apriori CAR → status) ===
System.out.println("\n[Rules/Apriori-CAR] start");

Instances rulesBase = new Instances(data);
weka.core.Attribute st = rulesBase.attribute("status");
if (st == null) throw new IllegalStateException("[CAR] 'status' not found");
rulesBase.setClassIndex(st.index());

String[] keepNames = new String[]{
        "length_url","length_hostname","ip","nb_dots","nb_hyphens",
        "ratio_intHyperlinks","ratio_extHyperlinks","links_in_tags","safe_anchor",
        "domain_age","domain_registration_lengt","dns_record","google_index",
        "status" // target
};

// Build keep indices (1-based), safely ignoring missing attrs
java.util.ArrayList<Integer> keepIdx = new java.util.ArrayList<>();
for (String n : keepNames) {
    weka.core.Attribute a = rulesBase.attribute(n);
    if (a != null) keepIdx.add(a.index() + 1);
}
if (!keepIdx.contains(rulesBase.classIndex() + 1)) keepIdx.add(rulesBase.classIndex() + 1);
java.util.Collections.sort(keepIdx);
StringBuilder keepSpec = new StringBuilder();
for (int i = 0; i < keepIdx.size(); i++) { if (i>0) keepSpec.append(","); keepSpec.append(keepIdx.get(i)); }

weka.filters.unsupervised.attribute.Remove keep = new weka.filters.unsupervised.attribute.Remove();
keep.setInvertSelection(true);
keep.setAttributeIndices(keepSpec.toString());
keep.setInputFormat(rulesBase);
Instances reduced = weka.filters.Filter.useFilter(rulesBase, keep);

// Force 'status' LAST and set as class
int status1 = reduced.attribute("status").index() + 1; // 1-based
StringBuilder order = new StringBuilder();
for (int i = 1; i <= reduced.numAttributes(); i++) { if (i != status1) { if (order.length()>0) order.append(","); order.append(i); } }
order.append(",").append(status1);
weka.filters.unsupervised.attribute.Reorder reorder = new weka.filters.unsupervised.attribute.Reorder();
reorder.setAttributeIndices(order.toString());
reorder.setInputFormat(reduced);
Instances reordered = weka.filters.Filter.useFilter(reduced, reorder);
reordered.setClassIndex(reordered.numAttributes() - 1);

System.out.println("[CAR] class after reorder = " + reordered.classAttribute().name());

// Discretize (UNSUPERVISED) → stable, no supervised-Discretize bug
weka.filters.unsupervised.attribute.Discretize disc = new weka.filters.unsupervised.attribute.Discretize();
disc.setUseBinNumbers(true);
disc.setBins(6);               // try 8 if you want more granularity
disc.setBinRangePrecision(10);
disc.setInputFormat(reordered);
Instances discData = weka.filters.Filter.useFilter(reordered, disc);
discData.setClassIndex(discData.numAttributes() - 1);
System.out.println("[CAR] class after discretize = " + discData.classAttribute().name());

// Apriori CAR (predict status). Loosen thresholds progressively until you get multiple rules.
double[] supports = {0.10, 0.08, 0.06, 0.05, 0.04, 0.03, 0.02};
double[] confs    = {0.90, 0.85, 0.80, 0.75};
boolean found = false;

for (double sup : supports) {
    for (double conf : confs) {
        try {
            weka.associations.Apriori apr = new weka.associations.Apriori();
            apr.setCar(true);
            apr.setClassIndex(discData.classIndex()); // ensure RHS is 'status'
            apr.setNumRules(50);            // ask for more
            apr.setLowerBoundMinSupport(sup);
            apr.setMinMetric(conf);         // confidence
            apr.setDelta(0.01);
            long t0 = System.currentTimeMillis();
            apr.buildAssociations(discData);

            @SuppressWarnings("rawtypes")
            java.util.ArrayList[] rules = apr.getAllTheRules(); // premise, consequence, conf, lift, lev, conv
            int n = (rules != null && rules.length > 0) ? rules[0].size() : 0;

            System.out.printf("[CAR] tried sup=%.2f conf=%.2f → %d rules in %d ms%n",
                    sup, conf, n, (System.currentTimeMillis() - t0));

            // Sanity: verify all consequents are the class (status)

if (n > 0) {
    System.out.printf("\n=== Apriori (CAR → status) — support=%.2f, conf=%.2f, rules=%d ===\n", sup, conf, n);
    System.out.println(apr);    // will print … ⇒ status=phishing/legitimate
    found = true;
    break;
}

        } catch (Exception e) {
            System.out.printf("[CAR] error (sup=%.2f conf=%.2f): %s%n", sup, conf, e.getMessage());
        }
    }
    if (found) break;
}

if (!found) {
    System.out.println("\n[Rules/Apriori] General (Lift) fallback");

    // Drop class for general associations
    Remove drop = new Remove();
    drop.setAttributeIndices(String.valueOf(discData.classIndex() + 1)); // 1-based
    drop.setInputFormat(discData);
    Instances noClass = Filter.useFilter(discData, drop);
    noClass.setClassIndex(-1);

    // (Optional) drop google_index to diversify consequents
    Attribute gi = noClass.attribute("google_index");
    if (gi != null) {
        Remove rmGi = new Remove();
        rmGi.setAttributeIndices(String.valueOf(gi.index() + 1)); // 1-based
        rmGi.setInputFormat(noClass);
        noClass = Filter.useFilter(noClass, rmGi);
        System.out.println("[Rules/Apriori] dropped google_index to diversify consequents");
    }

    // Apriori with LIFT as the metric (not confidence)
    Apriori aprLift = new Apriori();
    aprLift.setCar(false);
   // 0 = Confidence, 1 = Lift, 2 = Leverage, 3 = Conviction
aprLift.setMetricType(new SelectedTag(1, weka.associations.Apriori.TAGS_SELECTION));

    aprLift.setMinMetric(1.2);             // min lift (raise to get more “surprising” rules)
    aprLift.setLowerBoundMinSupport(0.08); // raise to 0.10 if too many/slow
    aprLift.setNumRules(30);
    aprLift.setDelta(0.02);

    long t0 = System.currentTimeMillis();
    aprLift.buildAssociations(noClass);
    System.out.printf("\n=== Apriori (general, Lift) — printed in %d ms ===\n",
            (System.currentTimeMillis() - t0));
    System.out.println(aprLift);
}


}
}
