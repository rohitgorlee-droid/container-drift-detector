import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * Container Drift Detector (base version)
 *
 * Compares a container's expected baseline (what was deployed) against a
 * runtime snapshot (what is actually running) and reports any drift.
 *
 * Both inputs are simple key=value files, for example:
 *
 *   image=myapp:1.4.2
 *   user=appuser
 *   security.privileged=false
 *   port.8080=tcp
 *   env.LOG_LEVEL=info
 *   mount.data=/var/data:ro
 *   process.java=running
 *
 * Usage:
 *   java ContainerDriftDetector.java                      (runs a built-in demo)
 *   java ContainerDriftDetector.java baseline.properties runtime.properties
 *
 * Exit codes: 0 = no drift, 1 = drift found, 2 = HIGH severity drift found.
 */
public class ContainerDriftDetector {

    enum DriftType { ADDED, REMOVED, MODIFIED }

    enum Severity { LOW, MEDIUM, HIGH }

    record Drift(String key, DriftType type, String expected, String actual, Severity severity) { }

    // ---------------------------------------------------------------
    // Core detection logic
    // ---------------------------------------------------------------

    static List<Drift> detect(Map<String, String> baseline, Map<String, String> runtime) {
        List<Drift> drifts = new ArrayList<>();

        Set<String> allKeys = new TreeSet<>();
        allKeys.addAll(baseline.keySet());
        allKeys.addAll(runtime.keySet());

        for (String key : allKeys) {
            String expected = baseline.get(key);
            String actual = runtime.get(key);

            if (expected == null) {
                drifts.add(new Drift(key, DriftType.ADDED, null, actual, severityFor(key)));
            } else if (actual == null) {
                drifts.add(new Drift(key, DriftType.REMOVED, expected, null, severityFor(key)));
            } else if (!expected.equals(actual)) {
                drifts.add(new Drift(key, DriftType.MODIFIED, expected, actual, severityFor(key)));
            }
        }

        drifts.sort(Comparator.comparing(Drift::severity).reversed().thenComparing(Drift::key));
        return drifts;
    }

    /** Simple rule-based severity: security and image changes matter most. */
    static Severity severityFor(String key) {
        if (key.equals("image") || key.equals("user") || key.startsWith("security.")) {
            return Severity.HIGH;
        }
        if (key.startsWith("port.") || key.startsWith("mount.") || key.startsWith("process.")) {
            return Severity.MEDIUM;
        }
        return Severity.LOW;
    }

    // ---------------------------------------------------------------
    // Loading and reporting
    // ---------------------------------------------------------------

    static Map<String, String> load(Path file) throws IOException {
        Properties props = new Properties();
        try (InputStream in = Files.newInputStream(file)) {
            props.load(in);
        }
        Map<String, String> map = new TreeMap<>();
        for (String name : props.stringPropertyNames()) {
            map.put(name, props.getProperty(name).trim());
        }
        return map;
    }

    static void printReport(String containerName, List<Drift> drifts) {
        System.out.println("=== Container Drift Report: " + containerName + " ===");

        if (drifts.isEmpty()) {
            System.out.println("No drift detected. Runtime matches baseline.");
            return;
        }

        for (Drift d : drifts) {
            System.out.printf("[%-6s] %-8s %s%n", d.severity(), d.type(), d.key());
            switch (d.type()) {
                case ADDED -> System.out.println("           actual   : " + d.actual());
                case REMOVED -> System.out.println("           expected : " + d.expected());
                case MODIFIED -> {
                    System.out.println("           expected : " + d.expected());
                    System.out.println("           actual   : " + d.actual());
                }
            }
        }

        long high = drifts.stream().filter(d -> d.severity() == Severity.HIGH).count();
        long medium = drifts.stream().filter(d -> d.severity() == Severity.MEDIUM).count();
        long low = drifts.stream().filter(d -> d.severity() == Severity.LOW).count();
        System.out.printf("%nSummary: %d drift(s) -> HIGH=%d, MEDIUM=%d, LOW=%d%n",
                drifts.size(), high, medium, low);
    }

    static int exitCodeFor(List<Drift> drifts) {
        if (drifts.isEmpty()) return 0;
        boolean anyHigh = drifts.stream().anyMatch(d -> d.severity() == Severity.HIGH);
        return anyHigh ? 2 : 1;
    }

    // ---------------------------------------------------------------
    // Entry point
    // ---------------------------------------------------------------

    public static void main(String[] args) throws IOException {
        Map<String, String> baseline;
        Map<String, String> runtime;
        String name;

        if (args.length == 2) {
            baseline = load(Path.of(args[0]));
            runtime = load(Path.of(args[1]));
            name = Path.of(args[1]).getFileName().toString();
        } else {
            System.out.println("(No files given - running built-in demo)\n");
            baseline = demoBaseline();
            runtime = demoRuntime();
            name = "demo-container";
        }

        List<Drift> drifts = detect(baseline, runtime);
        printReport(name, drifts);
        System.exit(exitCodeFor(drifts));
    }

    // ---------------------------------------------------------------
    // Demo data
    // ---------------------------------------------------------------

    static Map<String, String> demoBaseline() {
        Map<String, String> m = new TreeMap<>();
        m.put("image", "myapp:1.4.2");
        m.put("user", "appuser");
        m.put("security.privileged", "false");
        m.put("port.8080", "tcp");
        m.put("env.LOG_LEVEL", "info");
        m.put("mount.data", "/var/data:ro");
        m.put("process.java", "running");
        return m;
    }

    static Map<String, String> demoRuntime() {
        Map<String, String> m = new TreeMap<>(demoBaseline());
        m.put("image", "myapp:1.4.3");           // modified: image changed
        m.put("security.privileged", "true");    // modified: privilege escalation
        m.put("env.LOG_LEVEL", "debug");         // modified: env var changed
        m.remove("mount.data");                  // removed: mount missing
        m.put("port.2222", "tcp");               // added: unexpected open port
        m.put("process.sshd", "running");        // added: unexpected process
        return m;
    }
}
