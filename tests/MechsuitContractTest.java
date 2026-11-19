import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.TimeUnit;

/** Black-box, dependency-free contracts for MECHSUIT. JDK 17+. */
public final class MechsuitContractTest {
    static Path binary;
    static int passed, failed;
    static final List<String> failures = new ArrayList<>();

    @FunctionalInterface interface Check { void run() throws Exception; }
    record Result(int exit, String log, Path out) {
        String read(String name) throws IOException { return Files.readString(out.resolve(name)); }
        boolean has(String name) { return Files.exists(out.resolve(name)); }
    }
    static void test(String name, Check check) {
        try { check.run(); passed++; System.out.println("PASS " + name); }
        catch (Throwable e) { failed++; failures.add(name + ": " + e.getMessage()); System.out.println("FAIL " + name + ": " + e.getMessage()); }
    }
    static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
    static Path target(String file, String content) throws IOException {
        Path root = Files.createTempDirectory("mechsuit-contract-");
        Path t = root.resolve("target");
        Files.createDirectories(t);
        if (file != null) {
            Path f = t.resolve(file);
            Files.createDirectories(f.getParent());
            Files.writeString(f, content, StandardCharsets.UTF_8);
        }
        return t;
    }
    static Result execute(Path t, Map<String,String> env, String... extra) throws Exception {
        Path out = Files.createTempDirectory("mechsuit-results-");
        List<String> args = new ArrayList<>(List.of(binary.toString(), t.toString(), out.toString()));
        args.addAll(Arrays.asList(extra));
        ProcessBuilder pb = new ProcessBuilder(args).redirectErrorStream(true);
        pb.environment().putAll(env);
        Process p = pb.start();
        if (!p.waitFor(20, TimeUnit.SECONDS)) { p.destroyForcibly(); throw new AssertionError("scanner timed out after 20 s"); }
        return new Result(p.exitValue(), new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8), out);
    }
    static Result execute(Path t, String... extra) throws Exception { return execute(t, Map.of(), extra); }
    static void complete(Result r) throws Exception {
        require(r.exit == 0, "expected exit 0, got " + r.exit + "; " + r.log);
        for (String f : List.of("mechsuit_noir.json", "mechsuit_vigolium.json", "mechsuit_graph.json",
                "mechsuit_ranked.json", "mechsuit_report.md", "mechsuit_witness.log")) {
            require(r.has(f), "missing required artifact " + f);
            require(!r.read(f).isBlank(), "empty artifact " + f);
        }
        require(r.read("mechsuit_noir.json").stripLeading().startsWith("["), "surface output must be JSON array");
        require(r.read("mechsuit_vigolium.json").contains("\"findings\":["), "findings output missing findings array");
        require(r.read("mechsuit_graph.json").contains("\"nodes\":["), "graph missing nodes array");
        require(r.read("mechsuit_ranked.json").contains("\"edges\":["), "ranked graph missing edges array");
    }
    static String hash(Path path) throws Exception {
        byte[] h = MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(path));
        return HexFormat.of().formatHex(h);
    }
    static final String SAFE = """
        pragma solidity ^0.8.24;
        contract ReadOnly {
            uint256 private value;
            function read() external view returns (uint256) { return value; }
        }
        """;
    static final String COMMENTS = """
        pragma solidity ^0.8.24;
        // tx.origin and selfdestruct are examples, NOT actual operations.
        /* delegatecall is also only a comment. */
        contract Commentary {
            function explain() external pure returns (string memory) {
                return "selfdestruct and tx.origin and delegatecall";
            }
        }
        """;
    static final String REENTRANT = """
        pragma solidity ^0.8.24;
        contract BadVault {
            uint256 private credit;
            function withdraw() external {
                (bool ok,) = msg.sender.call{value: credit}("");
                require(ok);
                credit = 0;
            }
        }
        """;
    static final String ORIGIN = """
        pragma solidity ^0.8.24;
        contract OriginAuth {
            function privileged() external view {
                require(tx.origin == address(0x1234), "not authorized");
            }
        }
        """;

    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            System.err.println("Usage: java tests/MechsuitContractTest.java /absolute/path/to/mechsuit");
            System.exit(2);
        }
        binary = Path.of(args[0]).toAbsolutePath();
        require(Files.isExecutable(binary), "binary missing or not executable: " + binary);
        test("CLI rejects a missing target without producing a report", () -> {
            Path t = Path.of("/this-mechsuit-contract-target-does-not-exist");
            Result r = execute(t);
            require(r.exit != 0, "accepted non-existent target");
            require(!r.has("mechsuit_report.md"), "reported against missing target");
        });
        test("Unknown ecosystem fails closed", () -> {
            Result r = execute(target("README.txt", "No supported source files."));
            require(r.exit != 0, "unknown ecosystem silently accepted");
            require(!r.has("mechsuit_report.md"), "unknown ecosystem generated a report");
        });
        test("Auto-detected Move must not run Monero scanner", () -> {
            Result r = execute(target("sources/main.move", "module example::M {}"));
            require(r.exit != 0, "unsupported Move analyzed with fallback");
            require(!r.has("mechsuit_report.md"), "unsupported Move generated report");
        });
        test("Explicit unsupported Solana toolchain fails closed", () -> {
            Result r = execute(target("src/lib.rs", "pub fn main() {}"), "--toolchain", "solana");
            require(r.exit != 0, "unsupported Solana analyzed with fallback");
            require(!r.has("mechsuit_report.md"), "unsupported Solana generated report");
        });
        test("EVM surfaces public endpoints and emits complete artifacts", () -> {
            Result r = execute(target("ReadOnly.sol", SAFE));
            complete(r);
            require(r.read("mechsuit_noir.json").contains("\"name\":\"read\""), "missed read() endpoint");
            require(r.read("mechsuit_graph.json").contains("ReadOnly.read"), "graph missing endpoint");
        });
        test("Comments and string literals do not trigger vulnerability findings", () -> {
            Result r = execute(target("Commentary.sol", COMMENTS));
            complete(r);
            require(r.read("mechsuit_vigolium.json").contains("\"findings\":[]"), "comment/string was treated as executable vulnerability");
        });
        test("External call before state update creates a reentrancy lead", () -> {
            Result r = execute(target("BadVault.sol", REENTRANT));
            complete(r);
            require(r.read("mechsuit_vigolium.json").contains("\"pattern\":\"reentrancy\""), "missed known reentrancy pattern");
        });
        test("Lexical tx.origin detection cannot self-certify Confirmed", () -> {
            Result r = execute(target("OriginAuth.sol", ORIGIN));
            complete(r);
            String raw = r.read("mechsuit_vigolium.json");
            require(raw.contains("\"pattern\":\"tx-origin\""), "missed tx.origin lead");
            require(!raw.contains("\"confidence\":\"confirmed\""), "pattern detector self-certified a vulnerability");
        });
        test("A scanner lead is not presented as a validated finding", () -> {
            Result r = execute(target("BadVault.sol", REENTRANT));
            complete(r);
            String report = r.read("mechsuit_report.md");
            require(report.contains("UNVALIDATED"), "report missing explicit unvalidated disclaimer");
            require(!report.contains("| Triage | Accepted |"), "accepted without proof");
        });
        test("Monero wallet-side panic is not labeled remote DoS", () -> {
            Path t = target("Cargo.toml", "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n[dependencies]\nmonero=\"0.1\"\n");
            Path f = t.resolve("wallet/src/send/tx.rs");
            Files.createDirectories(f.getParent());
            Files.writeString(f, "pub fn build_transaction(amount: u64) { panic!(\"local builder\"); }\n");
            Result r = execute(t);
            complete(r);
            require(!r.read("mechsuit_report.md").contains("Reachable Panic (DoS)"), "wallet-only panic promoted to network DoS");
        });
        test("Audit never modifies target source", () -> {
            Path t = target("ReadOnly.sol", SAFE);
            Path f = t.resolve("ReadOnly.sol");
            String before = hash(f);
            Result r = execute(t);
            complete(r);
            require(before.equals(hash(f)), "target source modified by audit");
        });
        test("Repeated runs give identical machine-readable analysis", () -> {
            Path t = target("BadVault.sol", REENTRANT);
            Result a = execute(t), b = execute(t);
            complete(a); complete(b);
            for (String name : List.of("mechsuit_noir.json", "mechsuit_vigolium.json", "mechsuit_graph.json", "mechsuit_ranked.json"))
                require(a.read(name).equals(b.read(name)), "non-deterministic: " + name);
        });
        test("Scope allowlist rejects targets outside permitted root", () -> {
            Path inside = target("ReadOnly.sol", SAFE);
            Path unrelated = Files.createTempDirectory("mechsuit-outside-allowlist-");
            Result r = execute(inside, Map.of("MECHSUIT_ALLOWED_ROOT", unrelated.toString()));
            require(r.exit != 0, "ignored MECHSUIT_ALLOWED_ROOT");
            require(!r.has("mechsuit_report.md"), "generated report despite scope rejection");
        });
        System.out.printf("%nMECHSUIT contracts: %d passed, %d failed%n", passed, failed);
        if (!failures.isEmpty()) { failures.forEach(System.err::println); System.exit(1); }
    }
}
