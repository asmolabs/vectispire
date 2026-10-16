import com.asmolabs.vectispire.core.config.MigrationDialect;
import java.util.ArrayList;
import java.util.List;
import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.MigrationInfo;
import org.flywaydb.core.api.output.MigrateResult;
import org.flywaydb.core.api.output.ValidateResult;

/**
 * The real Flyway, configured as the Java control plane configures it, for the Rust runner's tests to
 * compare against.
 *
 * <p><b>The configuration is the application's, not a copy of it.</b> The placeholders and the
 * locations come from {@code MigrationDialect} on {@code vectispire-core}'s classpath — the same enum
 * {@code MigrationPlaceholders} hands Spring's Flyway — and everything else is Flyway's default, as
 * Spring Boot leaves it: {@code validateOnMigrate}, {@code outOfOrder=false}, no baseline, the default
 * table. A location root on disk can replace the classpath, so that another commit's files (V91 on the
 * 0.11.1 line) are migrated by the same code.
 *
 * <pre>
 * java -cp &lt;vectispire-core runtime classpath&gt; FlywayOracle.java migrate|check|validate|history \
 *      &lt;jdbc url&gt; &lt;user&gt; &lt;password&gt; &lt;vendor&gt; [&lt;db/migration root&gt; | -] [&lt;target version&gt;]
 * </pre>
 *
 * <ul>
 *   <li>{@code migrate} applies what is pending (up to the target, if one is given);
 *   <li>{@code check} validates, then migrates and fails if anything was left to apply — what a Java
 *       control plane does when it starts on a database the Rust runner migrated;
 *   <li>{@code validate} reports every validation error and exits 1 if there is one;
 *   <li>{@code history} prints the applied rows, one per line.
 * </ul>
 */
public class FlywayOracle {

    public static void main(String[] args) {
        if (args.length < 5) {
            System.err.println("usage: FlywayOracle migrate|check|validate|history <url> <user> <password> <vendor> [root|-] [target]");
            System.exit(2);
        }
        String command = args[0];
        MigrationDialect dialect = MigrationDialect.ofVendor(args[4])
                .orElseThrow(() -> new IllegalArgumentException("no dialect for " + args[4]));
        String root = args.length > 5 && !args[5].equals("-") ? args[5] : null;
        String target = args.length > 6 ? args[6] : null;

        List<String> locations = new ArrayList<>();
        if (root == null) {
            locations.addAll(dialect.locations());
        } else {
            locations.add("filesystem:" + root + "/common");
            locations.add("filesystem:" + root + "/" + dialect.vendor());
        }

        var configuration = Flyway.configure()
                .dataSource(args[1], args[2], args[3])
                .locations(locations.toArray(String[]::new))
                .placeholders(dialect.placeholders())
                .cleanDisabled(true);
        if (target != null) {
            configuration.target(target);
        }
        Flyway flyway = configuration.load();

        switch (command) {
            case "migrate" -> {
                MigrateResult result = flyway.migrate();
                System.out.println("applied " + result.migrationsExecuted);
            }
            case "check" -> {
                ValidateResult validation = flyway.validateWithResult();
                if (!validation.validationSuccessful) {
                    System.err.println(validation.getAllErrorMessages());
                    System.exit(1);
                }
                MigrateResult result = flyway.migrate();
                if (result.migrationsExecuted != 0) {
                    System.err.println("Flyway applied " + result.migrationsExecuted + " migration(s) the Rust runner left");
                    System.exit(1);
                }
                System.out.println("valid, nothing to apply");
            }
            case "validate" -> {
                ValidateResult validation = flyway.validateWithResult();
                if (!validation.validationSuccessful) {
                    System.out.println(validation.getAllErrorMessages());
                    System.exit(1);
                }
                System.out.println("valid");
            }
            case "history" -> {
                for (MigrationInfo info : flyway.info().applied()) {
                    System.out.println(info.getInstalledRank() + "\t" + info.getVersion() + "\t" + info.getDescription()
                            + "\t" + info.getType() + "\t" + info.getScript() + "\t" + info.getChecksum() + "\t"
                            + info.getState().isApplied());
                }
            }
            default -> {
                System.err.println("unknown command " + command);
                System.exit(2);
            }
        }
    }
}
