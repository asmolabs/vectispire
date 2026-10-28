import com.asmolabs.vectispire.common.domain.audit.AuditChain;
import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.core.audit.AuditLogQueryService;
import com.asmolabs.vectispire.core.audit.AuditLogService;
import com.asmolabs.vectispire.core.audit.internal.AuditMirror;
import com.asmolabs.vectispire.core.audit.persistence.AuditChainHeadRepository;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import jakarta.persistence.EntityManager;
import jakarta.persistence.EntityManagerFactory;
import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.springframework.data.jpa.repository.support.JpaRepositoryFactory;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.orm.jpa.SharedEntityManagerCreator;
import org.springframework.orm.jpa.vendor.HibernateJpaVendorAdapter;

/**
 * The real Java audit log, on a database the Rust tests started, for `cp-audit`'s port to be held to.
 *
 * <p><b>The service is the application's, not a copy of it.</b> {@code AuditLogService} and {@code
 * AuditLogQueryService} from {@code vectispire-core}'s classpath, over the module's own Spring Data
 * repositories and entities, on Hibernate and the JDBC drivers the control plane ships — wired by hand
 * because the rest of the application context (security, the outbox, the scheduler) has no part in writing
 * an entry. No listener and no mirror: those are the SIEM's and the file's, and the chain is what is under
 * test.
 *
 * <pre>
 * java -Duser.timezone=UTC -cp &lt;vectispire-core runtime classpath&gt; AuditOracle.java \
 *      append &lt;jdbc url&gt; &lt;user&gt; &lt;password&gt; &lt;count&gt; &lt;label&gt; [&lt;threads&gt;]
 *      verify &lt;jdbc url&gt; &lt;user&gt; &lt;password&gt;
 *      export &lt;jdbc url&gt; &lt;user&gt; &lt;password&gt;
 * </pre>
 *
 * <ul>
 *   <li>{@code append} writes {@code count} entries through {@code AuditLogService.append} — which throws,
 *       unlike {@code record} — from {@code threads} threads at once, each entry's description naming the
 *       label and its index;
 *   <li>{@code verify} prints {@code AuditLogService.verify()}'s verdict, {@code intact} or the break in its
 *       words, then the count of unverifiable entries, tab-separated;
 *   <li>{@code export} prints {@code AuditLogQueryService.asJsonLines} with the evidence bundle's mapper.
 * </ul>
 */
public class AuditOracle {

    private static final AuditOperation[] OPERATIONS = {
        AuditOperation.LOGIN_SUCCESS, AuditOperation.SETTING_UPDATED, AuditOperation.ISSUE_TRIAGED,
        AuditOperation.USER_CREATED, AuditOperation.API_KEY_CREATED
    };

    public static void main(String[] args) throws Exception {
        if (args.length < 4) {
            System.err.println("usage: AuditOracle append|verify|export <url> <user> <password> [count label [threads]]");
            System.exit(2);
        }
        PrintStream out = new PrintStream(new FileOutputStream(FileDescriptor.out), true, StandardCharsets.UTF_8);
        // Hibernate and Spring log to standard output; the answer is the only thing printed there.
        System.setOut(System.err);
        DriverManagerDataSource dataSource = new DriverManagerDataSource(args[1], args[2], args[3]);
        LocalContainerEntityManagerFactoryBean factory = new LocalContainerEntityManagerFactoryBean();
        factory.setDataSource(dataSource);
        factory.setPackagesToScan("com.asmolabs.vectispire.core.audit.persistence");
        factory.setJpaVendorAdapter(new HibernateJpaVendorAdapter());
        factory.getJpaPropertyMap().put("hibernate.hbm2ddl.auto", "validate");
        factory.afterPropertiesSet();
        EntityManagerFactory emf = factory.getObject();
        EntityManager shared = SharedEntityManagerCreator.createSharedEntityManager(emf);
        JpaRepositoryFactory repositories = new JpaRepositoryFactory(shared);
        AuditLogRepository entries = repositories.getRepository(AuditLogRepository.class);
        AuditChainHeadRepository heads = repositories.getRepository(AuditChainHeadRepository.class);
        JpaTransactionManager transactions = new JpaTransactionManager(emf);
        AuditLogService log = new AuditLogService(
                entries, heads, new AuditMirror.Disabled(), Clock.systemUTC(), List.of(), transactions);
        try {
            switch (args[0]) {
                case "append" -> append(log, Integer.parseInt(args[4]), args[5], args.length > 6 ? Integer.parseInt(args[6]) : 1);
                case "verify" -> {
                    AuditChain.Verification verification = log.verify();
                    out.println((verification.broken() == null ? "intact" : verification.broken())
                            + "\t" + verification.unverifiable());
                }
                case "export" -> {
                    ObjectMapper json = new ObjectMapper()
                            .registerModule(new JavaTimeModule())
                            .enable(SerializationFeature.INDENT_OUTPUT)
                            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
                    AuditLogQueryService query = new AuditLogQueryService(entries, log, event -> {}, Clock.systemUTC());
                    out.print(query.asJsonLines(json).text());
                }
                default -> {
                    System.err.println("unknown command " + args[0]);
                    System.exit(2);
                }
            }
        } finally {
            emf.close();
        }
        out.flush();
    }

    private static void append(AuditLogService log, int count, String label, int threads) throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        List<Future<?>> written = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            int index = i;
            written.add(pool.submit(() -> log.append(entry(label, index))));
        }
        for (Future<?> entry : written) {
            entry.get();
        }
        pool.shutdown();
    }

    /** Every shape the columns take: an address or none, a user agent or a blank one, a description past 255. */
    static AuditLogService.Record entry(String label, int index) {
        AuditOperation operation = OPERATIONS[index % OPERATIONS.length];
        String description = index % 7 == 3
                ? label + " " + index + " " + "é".repeat(300)
                : label + " " + index + " — Java wrote this, \"quoted\" \\ and\nbroken";
        String ip = index % 3 == 0 ? null : "203.0.113." + (index % 250);
        String agent = index % 4 == 0 ? "   " : "AuditOracle/" + index;
        String resource = index % 5 == 0 ? null : "resource-" + index;
        return new AuditLogService.Record(operation, resource, description, "java-" + label, ip, agent);
    }
}
