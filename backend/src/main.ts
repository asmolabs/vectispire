import { NestFactory } from '@nestjs/core';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import helmet from 'helmet';
import { AppModule } from './app.module';

/**
 * Le point d'entrée.
 *
 * Trois réglages qui ne sont pas des défauts de framework :
 *
 * - **`helmet` sans HSTS.** Zanshin se déploie aussi sur des réseaux internes en HTTP ;
 *   imposer HSTS y rendrait l'application inaccessible après la première visite, sans
 *   moyen simple de revenir en arrière côté navigateur.
 * - **La CSP est resserrée** par rapport à l'ancienne : le bundle Next.js de Reflex
 *   exigeait `unsafe-inline` et `unsafe-eval`, ce dont Angular n'a pas besoin. Cette
 *   relaxation-là disparaît avec Reflex.
 * - **OpenAPI est servi**, parce que c'est de lui que se génère le client TypeScript du
 *   frontend : les types traversent alors la frontière au lieu d'être recopiés à la
 *   main de chaque côté.
 *
 * Pas de `ValidationPipe` global : elle repose sur `class-validator`, et la validation
 * de ce projet passera par **Zod** (`nestjs-zod`, déjà installé). Zod est nettement plus
 * proche de ce que faisait Pydantic v2 côté Python — validateurs entre champs,
 * inférence de types, et surtout la distinction entre « champ absent » et « champ à
 * null » dont dépend le durcissement des politiques de gate. Empiler deux piles de
 * validation aurait garanti qu'elles finissent par désaccorder.
 */
async function bootstrap() {
    const app = await NestFactory.create(AppModule);

    app.use(
        helmet({
            // Voir la note ci-dessus : pas de HSTS.
            strictTransportSecurity: false,
            contentSecurityPolicy: {
                directives: {
                    defaultSrc: ["'self'"],
                    scriptSrc: ["'self'"],
                    styleSrc: ["'self'"],
                    fontSrc: ["'self'", 'data:'],
                    imgSrc: ["'self'", 'data:'],
                    connectSrc: ["'self'"],
                    frameAncestors: ["'none'"]
                }
            },
            referrerPolicy: { policy: 'no-referrer' },
            // `DENY`, et non le `SAMEORIGIN` par défaut de helmet : la CSP dit déjà
            // `frame-ancestors 'none'`, et deux en-têtes qui se contredisent finissent
            // par être lus différemment selon le navigateur. C'est aussi ce que servait
            // l'implémentation Python.
            frameguard: { action: 'deny' }
        })
    );

    const document = SwaggerModule.createDocument(
        app,
        new DocumentBuilder()
            .setTitle('Zanshin')
            .setDescription("API d'administration et d'intégration continue.")
            .setVersion('1')
            .addBearerAuth()
            .build()
    );
    // **Un avis de sécurité connu, et pourquoi il n'est pas traité comme un blocage.**
    // `@nestjs/swagger` épingle `js-yaml@5.2.1`, visé par GHSA-pm4m-ph32-ghv5 : temps
    // d'analyse exponentiel sur les collections en flux. Aucune version stable de Swagger
    // ne prend encore la 5.2.3 corrigée, et un `override` npm ne s'applique pas sans
    // reconstruire tout le verrou — ce qui fait alors surgir un conflit de pairs sans
    // rapport (vitest 3 contre 4 pour @angular/build).
    //
    // La faille est dans **l'analyse**, et ce module n'appelle que `jsyaml.dump` pour
    // sérialiser le document qu'il vient de construire lui-même — vérifié dans son code,
    // pas supposé. Aucun YAML tiers n'est lu. À revoir dès que Swagger monte sa borne ;
    // d'ici là, c'est un signalement d'outil et non une exposition.
    SwaggerModule.setup('api/v1/docs', app, document, { jsonDocumentUrl: 'api/v1/openapi.json' });

    await app.listen(Number(process.env.PORT ?? 3000));
}

void bootstrap();
