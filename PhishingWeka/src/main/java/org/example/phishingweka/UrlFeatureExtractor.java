package org.example.phishingweka;

import weka.core.*;
import weka.filters.Filter;
import weka.filters.unsupervised.attribute.Add;
import weka.filters.unsupervised.attribute.Remove;
import java.net.URL;
import java.net.MalformedURLException;
import java.util.*;
import java.util.regex.Pattern;

public final class UrlFeatureExtractor {
    private UrlFeatureExtractor() {}
    
    // Suspicious TLDs commonly used by phishers
    private static final Set<String> SUSPICIOUS_TLDS = new HashSet<>(Arrays.asList(
        "tk", "ml", "ga", "cf", "pw", "top", "click", "download", "science", "party"
    ));
    
    // Legitimate popular TLDs
    private static final Set<String> TRUSTED_TLDS = new HashSet<>(Arrays.asList(
        "com", "org", "net", "edu", "gov", "mil", "int", "co.uk", "de", "fr"
    ));
    
    // Common phishing keywords
    private static final Set<String> PHISHING_KEYWORDS = new HashSet<>(Arrays.asList(
        "paypal", "amazon", "google", "microsoft", "apple", "facebook", "bank", 
        "secure", "login", "verify", "update", "confirm", "account"
    ));

    /**
     * Main method to extract URL features and replace original URL attribute
     */
   public static Instances extractUrlFeatures(Instances data) throws Exception {
        System.out.println("\n=== URL FEATURE ENGINEERING ===");
        
        Attribute urlAttr = data.attribute("url");
        if (urlAttr == null) {
            System.out.println("No 'url' attribute found. Skipping URL feature extraction.");
            return data;
        }
        
        System.out.println("Found URL attribute. Extracting features...");
        
        // IMPORTANT: Remember original class index and class attribute name
        int originalClassIndex = data.classIndex();
        String originalClassName = null;
        if (originalClassIndex >= 0) {
            originalClassName = data.classAttribute().name();
            System.out.println("Original class: " + originalClassName + " at index " + originalClassIndex);
        }
        
        // Create new dataset with URL features
        Instances enhanced = addUrlFeatures(data, urlAttr);
        
        // Remove original URL attribute (high cardinality)
        Remove removeUrl = new Remove();
        removeUrl.setAttributeIndicesArray(new int[]{urlAttr.index()});
        removeUrl.setInputFormat(enhanced);
        Instances finalData = Filter.useFilter(enhanced, removeUrl);
        
        // CRITICAL: Properly restore class index
        if (originalClassName != null) {
            Attribute newClassAttr = finalData.attribute(originalClassName);
            if (newClassAttr != null) {
                finalData.setClassIndex(newClassAttr.index());
                System.out.println("✅ Class index restored: " + originalClassName + " at index " + newClassAttr.index());
            } else {
                System.out.println("⚠️ Could not find class attribute after URL removal!");
                // Fallback: assume class is at the end
                finalData.setClassIndex(finalData.numAttributes() - 1);
            }
        } else {
            System.out.println("⚠️ No original class index to restore");
        }
        
        System.out.println("URL features extracted successfully!");
        System.out.println("Added features: url_length, domain_length, subdomain_count, etc.");
        
        return finalData;
    }
    
    /**
     * Add URL-derived features to the dataset
     */
    private static Instances addUrlFeatures(Instances data, Attribute urlAttr) throws Exception {
        Instances enhanced = new Instances(data);
        
        // Define URL features to extract
        String[] featureNames = {
            "url_length", "domain_length", "subdomain_count", "path_length",
            "query_length", "fragment_length", "digit_count", "special_char_count",
            "hyphen_count", "dot_count", "slash_count", "question_count",
            "has_ip", "has_suspicious_tld", "has_trusted_tld", "has_phishing_keywords",
            "url_entropy", "domain_tokens", "is_shortened_url", "has_redirect_words"
        };
        
        // Add new attributes
        for (String featureName : featureNames) {
            Add addAttr = new Add();
            addAttr.setAttributeIndex("last");
            addAttr.setAttributeName(featureName);
            addAttr.setAttributeType(new SelectedTag(Attribute.NUMERIC, Add.TAGS_TYPE));
            addAttr.setInputFormat(enhanced);
            enhanced = Filter.useFilter(enhanced, addAttr);
        }
        
        // Extract features for each instance
        for (int i = 0; i < data.numInstances(); i++) {
            String urlString = data.instance(i).stringValue(urlAttr);
            UrlFeatures features = extractFeatures(urlString);
            
            // Set feature values
            int baseIndex = enhanced.numAttributes() - featureNames.length;
            enhanced.instance(i).setValue(baseIndex + 0, features.urlLength);
            enhanced.instance(i).setValue(baseIndex + 1, features.domainLength);
            enhanced.instance(i).setValue(baseIndex + 2, features.subdomainCount);
            enhanced.instance(i).setValue(baseIndex + 3, features.pathLength);
            enhanced.instance(i).setValue(baseIndex + 4, features.queryLength);
            enhanced.instance(i).setValue(baseIndex + 5, features.fragmentLength);
            enhanced.instance(i).setValue(baseIndex + 6, features.digitCount);
            enhanced.instance(i).setValue(baseIndex + 7, features.specialCharCount);
            enhanced.instance(i).setValue(baseIndex + 8, features.hyphenCount);
            enhanced.instance(i).setValue(baseIndex + 9, features.dotCount);
            enhanced.instance(i).setValue(baseIndex + 10, features.slashCount);
            enhanced.instance(i).setValue(baseIndex + 11, features.questionCount);
            enhanced.instance(i).setValue(baseIndex + 12, features.hasIp ? 1.0 : 0.0);
            enhanced.instance(i).setValue(baseIndex + 13, features.hasSuspiciousTld ? 1.0 : 0.0);
            enhanced.instance(i).setValue(baseIndex + 14, features.hasTrustedTld ? 1.0 : 0.0);
            enhanced.instance(i).setValue(baseIndex + 15, features.hasPhishingKeywords ? 1.0 : 0.0);
            enhanced.instance(i).setValue(baseIndex + 16, features.urlEntropy);
            enhanced.instance(i).setValue(baseIndex + 17, features.domainTokens);
            enhanced.instance(i).setValue(baseIndex + 18, features.isShortenedUrl ? 1.0 : 0.0);
            enhanced.instance(i).setValue(baseIndex + 19, features.hasRedirectWords ? 1.0 : 0.0);
        }
        
        return enhanced;
    }
    
    /**
     * Extract comprehensive features from a single URL
     */
    private static UrlFeatures extractFeatures(String urlString) {
        UrlFeatures features = new UrlFeatures();
        
        if (urlString == null || urlString.trim().isEmpty()) {
            return features; // Return default values
        }
        
        urlString = urlString.trim().toLowerCase();
        features.urlLength = urlString.length();
        
        try {
            URL url = new URL(urlString.startsWith("http") ? urlString : "http://" + urlString);
            
            // Basic URL components
            String host = url.getHost() != null ? url.getHost().toLowerCase() : "";
            String path = url.getPath() != null ? url.getPath() : "";
            String query = url.getQuery() != null ? url.getQuery() : "";
            String fragment = url.getRef() != null ? url.getRef() : "";
            
            // Domain features
            features.domainLength = host.length();
            features.subdomainCount = countSubdomains(host);
            features.pathLength = path.length();
            features.queryLength = query.length();
            features.fragmentLength = fragment.length();
            
            // Character analysis
            features.digitCount = countDigits(urlString);
            features.specialCharCount = countSpecialChars(urlString);
            features.hyphenCount = countChar(urlString, '-');
            features.dotCount = countChar(urlString, '.');
            features.slashCount = countChar(urlString, '/');
            features.questionCount = countChar(urlString, '?');
            
            // Security indicators
            features.hasIp = isIpAddress(host);
            features.hasSuspiciousTld = hasSuspiciousTld(host);
            features.hasTrustedTld = hasTrustedTld(host);
            features.hasPhishingKeywords = hasPhishingKeywords(urlString);
            
            // Advanced features
            features.urlEntropy = calculateEntropy(urlString);
            features.domainTokens = countDomainTokens(host);
            features.isShortenedUrl = isShortenedUrl(host);
            features.hasRedirectWords = hasRedirectWords(urlString);
            
        } catch (MalformedURLException e) {
            // Handle malformed URLs - often suspicious
            features.specialCharCount = countSpecialChars(urlString);
            features.digitCount = countDigits(urlString);
            features.urlEntropy = calculateEntropy(urlString);
        }
        
        return features;
    }
    
    // Helper methods
    private static int countSubdomains(String host) {
        if (host.isEmpty()) return 0;
        String[] parts = host.split("\\.");
        return Math.max(0, parts.length - 2); // domain.tld = 0 subdomains
    }
    
    private static int countDigits(String str) {
        return (int) str.chars().filter(Character::isDigit).count();
    }
    
    private static int countSpecialChars(String str) {
        return (int) str.chars().filter(c -> !Character.isLetterOrDigit(c) && c != '.' && c != '-' && c != '/').count();
    }
    
    private static int countChar(String str, char c) {
        return (int) str.chars().filter(ch -> ch == c).count();
    }
    
    private static boolean isIpAddress(String host) {
        // Simple IPv4 pattern check
        Pattern ipPattern = Pattern.compile("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$");
        return ipPattern.matcher(host).matches();
    }
    
    private static boolean hasSuspiciousTld(String host) {
        if (host.isEmpty()) return false;
        String[] parts = host.split("\\.");
        if (parts.length == 0) return false;
        String tld = parts[parts.length - 1];
        return SUSPICIOUS_TLDS.contains(tld);
    }
    
    private static boolean hasTrustedTld(String host) {
        if (host.isEmpty()) return false;
        String[] parts = host.split("\\.");
        if (parts.length == 0) return false;
        String tld = parts[parts.length - 1];
        return TRUSTED_TLDS.contains(tld);
    }
    
    private static boolean hasPhishingKeywords(String url) {
        String lowerUrl = url.toLowerCase();
        return PHISHING_KEYWORDS.stream().anyMatch(lowerUrl::contains);
    }
    
    private static double calculateEntropy(String str) {
        Map<Character, Integer> charCount = new HashMap<>();
        for (char c : str.toCharArray()) {
            charCount.put(c, charCount.getOrDefault(c, 0) + 1);
        }
        
        double entropy = 0.0;
        int length = str.length();
        for (int count : charCount.values()) {
            double probability = (double) count / length;
            entropy -= probability * (Math.log(probability) / Math.log(2));
        }
        return entropy;
    }
    
    private static int countDomainTokens(String host) {
        if (host.isEmpty()) return 0;
        // Count meaningful tokens separated by dots, hyphens
        return host.split("[.-]").length;
    }
    
    private static boolean isShortenedUrl(String host) {
        Set<String> shorteners = new HashSet<>(Arrays.asList(
            "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "short.link", "tiny.cc"
        ));
        return shorteners.contains(host);
    }
    
    private static boolean hasRedirectWords(String url) {
        String lowerUrl = url.toLowerCase();
        String[] redirectWords = {"redirect", "forward", "redir", "goto", "link", "url"};
        return Arrays.stream(redirectWords).anyMatch(lowerUrl::contains);
    }
    
    /**
     * Data class to hold extracted URL features
     */
    private static class UrlFeatures {
        int urlLength = 0;
        int domainLength = 0;
        int subdomainCount = 0;
        int pathLength = 0;
        int queryLength = 0;
        int fragmentLength = 0;
        int digitCount = 0;
        int specialCharCount = 0;
        int hyphenCount = 0;
        int dotCount = 0;
        int slashCount = 0;
        int questionCount = 0;
        boolean hasIp = false;
        boolean hasSuspiciousTld = false;
        boolean hasTrustedTld = false;
        boolean hasPhishingKeywords = false;
        double urlEntropy = 0.0;
        int domainTokens = 0;
        boolean isShortenedUrl = false;
        boolean hasRedirectWords = false;
    }
}