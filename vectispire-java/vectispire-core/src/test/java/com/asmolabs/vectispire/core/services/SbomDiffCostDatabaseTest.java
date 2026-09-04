package com.asmolabs.vectispire.core.services;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.persistence.ScanEntity;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import com.asmolabs.vectispire.core.repositories.Scans;
import jakarta.persistence.EntityManagerFactory;
import java.time.Instant;
import org.hibernate.SessionFactory;
import org.hibernate.stat.Statistics;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * Comparer deux scans d'une cible ne doit pas lire l'historique du parc.
 *
 * <p><b>Le défaut que ceci ferme.</b> {@code diffLatest} appelait {@code scans.findAll()}, puis
 * filtrait, triait et gardait deux lignes en Java. Toutes les lignes de scan du déploiement
 * étaient donc chargées comme entités pour en retenir deux identifiants — et une ligne de scan
 * transporte sa charge SBOM entière, des mégaoctets pièce. Demander le différentiel d'un dépôt
 * lisait les SBOM de tous les autres.
 *
 * <p><b>Pourquoi un cas dédié et non le balayage.</b> {@code ReadCostSweepTest} parcourt toute la
 * surface GET et aurait dû l'attraper ; il exclut nommément {@code /api/v1/sbom/diff/latest},
 * parce que la route répond 404 tant que la fixture n'a pas deux scans à comparer. L'exclusion
 * était raisonnable et c'est elle qui a laissé passer le défaut : une route qu'on ne peut pas
 * mesurer là où on mesure tout le reste a besoin de sa propre mesure, sans quoi « non mesurée » se
 * lit comme « mesurée et acceptable ».
 */
@DisplayName("le coût du différentiel de SBOM")
class SbomDiffCostDatabaseTest extends VectispireContextTest {

    @DynamicPropertySource
    static void statistics(DynamicPropertyRegistry registry) {
        registry.add("spring.jpa.properties.hibernate.generate_statistics", () -> "true");
    }

    @Autowired
    private SbomDiffService sbomDiff;

    @Autowired
    private GitRepositories repositories;

    @Autowired
    private Scans scans;

    @Autowired
    private EntityManagerFactory entityManagerFactory;

    private long target;

    @BeforeEach
    void seed() {
        target = repository("https://example.invalid/target.git", "target");
        scan(target);
        scan(target);
    }

    @Test
    @DisplayName("ne suit pas le nombre de scans des autres cibles")
    void theCostDoesNotFollowTheEstate() {
        long stranger = repository("https://example.invalid/stranger.git", "stranger");
        for (int index = 0; index < 200; index++) {
            scan(stranger);
        }

        Statistics statistics = entityManagerFactory.unwrap(SessionFactory.class).getStatistics();
        statistics.clear();

        assertThat(sbomDiff.diffLatest(target, null)).isPresent();

        // Deux cents scans étrangers à la question posée. Le seuil est bas et volontairement pas
        // nul : le différentiel charge ensuite les deux scans qu'il compare et leurs constats, ce
        // qui est le travail demandé. Ce qui est interdit est que le parc entre dans le compte.
        assertThat(statistics.getEntityLoadCount())
                .as("comparer deux scans d'un dépôt ne doit pas lire ceux des autres")
                .isLessThan(50);
    }

    @Test
    @DisplayName("un seul scan se compare à lui-même, plutôt que de répondre « rien »")
    void oneScanIsStillAnAnswer() {
        long lonely = repository("https://example.invalid/lonely.git", "lonely");
        scan(lonely);

        // « Rien n'a changé » et « aucune donnée » se ressemblent à l'écran et ne veulent pas dire
        // la même chose ; la seconde se lit comme une panne.
        assertThat(sbomDiff.diffLatest(lonely, null)).isPresent();
    }

    @Test
    @DisplayName("une cible sans scan ne rend rien, et sans lire quoi que ce soit")
    void noScanAtAll() {
        long empty = repository("https://example.invalid/empty.git", "empty");

        Statistics statistics = entityManagerFactory.unwrap(SessionFactory.class).getStatistics();
        statistics.clear();

        assertThat(sbomDiff.diffLatest(empty, null)).isEmpty();
        assertThat(statistics.getEntityLoadCount())
                .as("aucun scan à comparer se répond par une requête, pas par une lecture du parc")
                .isZero();
    }

    private long repository(String url, String name) {
        RepositoryEntity entity = new RepositoryEntity();
        entity.setUrl(url);
        entity.setName(name);
        entity.setBranch("main");
        return repositories.save(entity).getId();
    }

    private void scan(long repoId) {
        ScanEntity entity = new ScanEntity();
        entity.setRepoId(repoId);
        entity.setStatus(ScanStatus.COMPLETED.wireName());
        entity.setBranch("main");
        entity.setCreatedAt(Instant.now());
        scans.save(entity);
    }
}
