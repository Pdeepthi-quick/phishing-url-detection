package com.phishingdetection.ml;

import weka.classifiers.Classifier;
import weka.classifiers.trees.J48;
import weka.classifiers.trees.RandomForest;
import weka.core.Attribute;
import weka.core.DenseInstance;
import weka.core.Instance;
import weka.core.Instances;
import weka.core.Utils;
import weka.core.converters.ConverterUtils.DataSource;

import com.phishingdetection.utils.ArffCleaner;

// import java.net.URI;   <-- REMOVED (unused import)
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;

public class EnsembleWekaClassifier {

    private final List<Classifier> classifiers = new ArrayList<>();
    private Instances structure;
    private final ExecutorService executor = Executors.newFixedThreadPool(2);

    public EnsembleWekaClassifier(String arffPath) throws Exception {

        String pathToLoad;
        try {
            pathToLoad = ArffCleaner.clean(arffPath);
        } catch (Exception e) {
            System.out.println("Debug: ArffCleaner failed, using original ARFF: " + arffPath);
            pathToLoad = arffPath;
        }

        System.out.println("Debug: Loading dataset: " + pathToLoad);
        DataSource ds = new DataSource(pathToLoad);
        Instances data = ds.getDataSet();
        if (data == null) throw new IllegalStateException("Unable to load ARFF: " + pathToLoad);

        if (data.classIndex() == -1) data.setClassIndex(data.numAttributes() - 1);
        this.structure = new Instances(data, 0);

        System.out.println("Debug: Training on " + data.numInstances() + " instances, " + data.numAttributes() + " attributes");

        J48 j48 = new J48();
        j48.setUseLaplace(true);
        j48.setMinNumObj(2);
        j48.buildClassifier(data);
        classifiers.add(j48);
        System.out.println("Debug: J48 built");

        RandomForest rf = new RandomForest();
        try { rf.setNumIterations(120); } catch (Throwable ignored) {}
        rf.buildClassifier(data);
        classifiers.add(rf);
        System.out.println("Debug: RandomForest built");
    }

    public boolean classifyUrl(String urlStr) throws Exception {
        System.out.println("Debug: Starting classification for URL: " + urlStr);

        Instances insts = buildInstance(urlStr);
        Instance inst = insts.instance(0);

        List<Future<Integer>> futures = new ArrayList<>();
        for (Classifier clf : classifiers) {
            futures.add(executor.submit(() -> {
                try { return (int) clf.classifyInstance(inst); }
                catch (Exception e) {
                    double[] dist = clf.distributionForInstance(inst);
                    int max = 0;
                    for (int i = 1; i < dist.length; i++) if (dist[i] > dist[max]) max = i;
                    return max;
                }
            }));
        }

        Attribute classAttr = structure.classAttribute();
        int phishingVotes = 0;

        for (Future<Integer> f : futures) {
            int idx = f.get();
            if (idx < 0 || idx >= classAttr.numValues()) continue;
            String val = classAttr.value(idx);
            System.out.println("Debug: Classifier voted: " + val);
            if ("-1".equals(val)) phishingVotes++;
        }

        boolean decision = phishingVotes > (classifiers.size() / 2);
        System.out.println("Debug: Classification result: " + (decision ? "Phishing" : "Legitimate"));
        return decision;
    }

    private Instances buildInstance(String urlStr) {

        Instances insts = new Instances(structure, 0);
        double[] vals = new double[structure.numAttributes()];
        for (int i = 0; i < vals.length; i++) vals[i] = Utils.missingValue();

        try {

            // FIXED: Replace deprecated constructor
            URL url = java.net.URI.create(urlStr).toURL();

            String host = url.getHost() == null ? "" : url.getHost().toLowerCase();
            String protocol = url.getProtocol() == null ? "" : url.getProtocol().toLowerCase();
            int urlLen = urlStr.length();

            java.util.function.BiConsumer<String,String> setNom = (attName, value) -> {
                Attribute a = structure.attribute(attName);
                if (a == null) return;
                if (!a.isNominal()) return;
                int idx = a.indexOfValue(value);
                if (idx >= 0) vals[a.index()] = idx;
            };

            // ---- All your original feature mappings remain unchanged ----
            setNom.accept("having_IP_Address", host.matches("\\d+\\.\\d+\\.\\d+\\.\\d+") ? "-1" : "1");
            setNom.accept("URL_Length", urlLen < 54 ? "1" : (urlLen <= 75 ? "0" : "-1"));
            setNom.accept("Shortining_Service", (host.contains("bit.ly") || host.contains("tinyurl") || host.contains("t.co")) ? "-1" : "1");
            setNom.accept("having_At_Symbol", urlStr.contains("@") ? "-1" : "1");
            boolean doubleSlashRedirect = (urlStr.indexOf("//") != -1 && urlStr.indexOf("//", urlStr.indexOf("//") + 2) != -1);
            setNom.accept("double_slash_redirecting", doubleSlashRedirect ? "-1" : "1");
            setNom.accept("Prefix_Suffix", host.contains("-") ? "-1" : "1");

            int subCount = Math.max(0, host.split("\\.").length - 2);
            setNom.accept("having_Sub_Domain", subCount == 0 ? "1" : (subCount == 1 ? "0" : "-1"));

            setNom.accept("SSLfinal_State", "https".equals(protocol) ? "1" : "0");
            setNom.accept("Domain_registeration_length", "1");
            setNom.accept("Favicon", urlStr.contains("favicon") ? "-1" : "1");
            setNom.accept("port", (url.getPort() != -1 && url.getPort() != 80 && url.getPort() != 443) ? "-1" : "1");
            setNom.accept("HTTPS_token", host.contains("https") ? "-1" : "1");
            setNom.accept("Request_URL", "1");
            setNom.accept("URL_of_Anchor", "1");
            setNom.accept("Links_in_tags", "1");
            setNom.accept("SFH", "1");
            setNom.accept("Submitting_to_email", urlStr.contains("mailto:") ? "-1" : "1");
            setNom.accept("Abnormal_URL", (urlStr.contains("%") || (urlStr.contains("?") && urlStr.length() > 100)) ? "-1" : "1");
            setNom.accept("Redirect", (urlStr.contains("redirect") || urlStr.contains("redir") || urlStr.contains("goto")) ? "0" : "1");
            setNom.accept("on_mouseover", "1");
            setNom.accept("RightClick", "1");
            setNom.accept("popUpWidnow", "1");
            setNom.accept("Iframe", "1");
            setNom.accept("age_of_domain", "1");
            setNom.accept("DNSRecord", "1");
            setNom.accept("web_traffic", "1");
            setNom.accept("Page_Rank", "1");
            setNom.accept("Google_Index", "1");
            setNom.accept("Links_pointing_to_page", "1");
            setNom.accept("Statistical_report", "1");

            vals[structure.classIndex()] = Utils.missingValue();

        } catch (Exception e) {
            System.out.println("Debug: Malformed URL: " + e.getMessage());
        }

        Instance inst = new DenseInstance(1.0, vals);
        inst.setDataset(structure);
        insts.add(inst);
        System.out.println("Debug: Instance built successfully.");
        return insts;
    }
}