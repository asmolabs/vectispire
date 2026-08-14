import { MigrationInterface, QueryRunner } from "typeorm";

export class Baseline1786692508706 implements MigrationInterface {
    name = 'Baseline1786692508706'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`CREATE TABLE \`t_api_key\` (\`id\` varchar(36) NOT NULL, \`name\` varchar(255) NOT NULL, \`key_hash\` varchar(255) NOT NULL, \`prefix\` varchar(16) NULL, \`created_at\` datetime(6) NOT NULL, \`last_used_at\` datetime(6) NULL, \`scopes\` varchar(255) NOT NULL DEFAULT 'read,scan,export', \`target_kind\` varchar(20) NULL, \`target_id\` int NULL, \`expires_at\` datetime(6) NULL, PRIMARY KEY (\`id\`)) ENGINE=InnoDB`);
        await queryRunner.query(`CREATE TABLE \`t_agent\` (\`id\` varchar(36) NOT NULL, \`name\` varchar(255) NOT NULL, \`description\` varchar(500) NULL, \`kind\` varchar(20) NOT NULL, \`labels\` varchar(255) NULL, \`credentials_mode\` varchar(20) NOT NULL, \`enabled\` tinyint NOT NULL, \`max_concurrent\` int NULL, \`api_key_id\` varchar(36) NULL, \`hostname\` varchar(255) NULL, \`platform\` varchar(255) NULL, \`version\` varchar(50) NULL, \`scanner_engine\` varchar(50) NULL, \`capabilities\` json NULL, \`contract_version\` varchar(20) NULL, \`last_seen_at\` datetime(6) NULL, \`created_at\` datetime(6) NOT NULL, PRIMARY KEY (\`id\`)) ENGINE=InnoDB`);
        await queryRunner.query(`CREATE TABLE \`t_container\` (\`id\` int NOT NULL AUTO_INCREMENT, \`registry\` varchar(255) NULL, \`image_name\` varchar(255) NOT NULL, \`tag\` varchar(255) NOT NULL, \`scan_interval_minutes\` int NULL, \`scan_cron\` varchar(255) NULL, \`last_scheduled_scan_at\` datetime(6) NULL, PRIMARY KEY (\`id\`)) ENGINE=InnoDB`);
        await queryRunner.query(`CREATE TABLE \`t_ssh_key\` (\`id\` varchar(36) NOT NULL, \`name\` varchar(255) NOT NULL, \`private_key\` text NOT NULL, \`public_key\` text NULL, \`created_at\` datetime(6) NOT NULL, PRIMARY KEY (\`id\`)) ENGINE=InnoDB`);
        await queryRunner.query(`CREATE TABLE \`t_repository\` (\`id\` int NOT NULL AUTO_INCREMENT, \`url\` varchar(255) NOT NULL, \`branch\` varchar(255) NOT NULL, \`sub_path\` varchar(255) NULL, \`name\` varchar(255) NULL, \`scan_interval_minutes\` int NULL, \`scan_cron\` varchar(255) NULL, \`last_scheduled_scan_at\` datetime(6) NULL, \`ssh_key_id\` varchar(36) NULL, PRIMARY KEY (\`id\`)) ENGINE=InnoDB`);
        await queryRunner.query(`CREATE TABLE \`t_scan\` (\`id\` int NOT NULL AUTO_INCREMENT, \`branch\` varchar(255) NOT NULL, \`sub_path\` varchar(255) NULL, \`status\` varchar(255) NOT NULL, \`sbom\` json NULL, \`cves\` json NULL, \`summary\` json NULL, \`duration_ms\` bigint NULL, \`findings_count\` int NOT NULL DEFAULT '0', \`new_issues_count\` int NOT NULL DEFAULT '0', \`resolved_issues_count\` int NOT NULL DEFAULT '0', \`error\` text NULL, \`created_at\` datetime(6) NOT NULL, \`version\` varchar(255) NULL, \`project_type\` varchar(255) NULL, \`repo_id\` int NULL, \`container_id\` int NULL, \`claimed_by\` varchar(64) NULL, \`claimed_at\` datetime(6) NULL, \`lease_expires_at\` datetime(6) NULL, \`attempts\` int NOT NULL DEFAULT '0', INDEX \`idx_scan_file\` (\`status\`, \`created_at\`, \`id\`), PRIMARY KEY (\`id\`)) ENGINE=InnoDB`);
        await queryRunner.query(`CREATE TABLE \`t_ai_review_result\` (\`id\` int NOT NULL AUTO_INCREMENT, \`scan_id\` int NOT NULL, \`model\` varchar(255) NOT NULL, \`prompt\` text NOT NULL, \`response\` text NULL, \`status\` varchar(50) NOT NULL, \`error\` varchar(500) NULL, \`created_at\` datetime(6) NOT NULL, PRIMARY KEY (\`id\`)) ENGINE=InnoDB`);
        await queryRunner.query(`CREATE TABLE \`t_audit_log\` (\`id\` varchar(36) NOT NULL, \`description\` varchar(255) NOT NULL, \`operation_type\` varchar(255) NOT NULL, \`resource_id\` varchar(255) NOT NULL, \`timestamp\` datetime(6) NOT NULL, \`user_id\` varchar(255) NULL, \`ip_address\` varchar(64) NULL, \`user_agent\` varchar(255) NULL, \`previous_hash\` varchar(64) NULL, \`entry_hash\` varchar(64) NULL, PRIMARY KEY (\`id\`)) ENGINE=InnoDB`);
        await queryRunner.query(`CREATE TABLE \`t_issue\` (\`id\` int NOT NULL AUTO_INCREMENT, \`repo_id\` int NULL, \`container_id\` int NULL, \`fingerprint\` varchar(64) NOT NULL, \`type\` varchar(50) NOT NULL, \`identifier\` varchar(255) NULL, \`package_name\` varchar(255) NULL, \`package_version\` varchar(255) NULL, \`purl\` varchar(255) NULL, \`file_path\` varchar(500) NULL, \`source\` varchar(50) NULL, \`severity\` varchar(50) NULL, \`epss_score\` double NULL, \`is_kev\` tinyint NOT NULL DEFAULT 0, \`cvss_score\` double NULL, \`cvss_vector\` varchar(255) NULL, \`fix_state\` varchar(50) NULL, \`fix_versions\` varchar(255) NULL, \`link\` varchar(500) NULL, \`description\` text NULL, \`state\` varchar(20) NOT NULL DEFAULT 'open', \`first_seen_at\` datetime(6) NOT NULL, \`last_seen_at\` datetime(6) NOT NULL, \`resolved_at\` datetime(6) NULL, \`first_seen_scan_id\` int NULL, \`last_seen_scan_id\` int NULL, \`times_seen\` int NOT NULL DEFAULT '1', \`triage_status\` varchar(30) NOT NULL DEFAULT 'under_review', \`triage_justification\` varchar(64) NULL, \`triage_comment\` text NULL, \`triaged_by\` varchar(255) NULL, \`triaged_at\` datetime(6) NULL, \`triage_expires_at\` datetime(6) NULL, \`is_direct_dependency\` tinyint NULL, \`line\` int NULL, \`ticket_ref\` varchar(64) NULL, \`ticket_url\` varchar(500) NULL, PRIMARY KEY (\`id\`)) ENGINE=InnoDB`);
        await queryRunner.query(`CREATE TABLE \`t_finding\` (\`id\` int NOT NULL AUTO_INCREMENT, \`scan_id\` int NOT NULL, \`type\` varchar(50) NOT NULL, \`severity\` varchar(50) NULL, \`identifier\` varchar(255) NULL, \`package_name\` varchar(255) NULL, \`package_version\` varchar(255) NULL, \`purl\` varchar(255) NULL, \`file_path\` varchar(500) NULL, \`source\` varchar(50) NOT NULL, \`epss_score\` double NULL, \`is_kev\` tinyint NOT NULL, \`created_at\` datetime(6) NOT NULL, \`cvss_score\` double NULL, \`cvss_vector\` varchar(255) NULL, \`fix_state\` varchar(50) NULL, \`fix_versions\` varchar(255) NULL, \`link\` varchar(500) NULL, \`issue_id\` int NULL, \`is_direct_dependency\` tinyint NULL, \`line\` int NULL, \`description\` text NULL, PRIMARY KEY (\`id\`)) ENGINE=InnoDB`);
        await queryRunner.query(`CREATE TABLE \`t_gate_policy\` (\`id\` int NOT NULL AUTO_INCREMENT, \`target_kind\` varchar(20) NOT NULL, \`target_id\` int NOT NULL, \`version\` int NOT NULL, \`is_active\` tinyint NULL, \`fail_on_severity\` varchar(20) NULL, \`fail_on_kev\` tinyint NOT NULL, \`fixable_only\` tinyint NOT NULL, \`include_triaged\` tinyint NOT NULL, \`include_ai_review\` tinyint NOT NULL, \`note\` text NULL, \`created_by\` varchar(255) NULL, \`created_at\` datetime(6) NOT NULL, PRIMARY KEY (\`id\`)) ENGINE=InnoDB`);
        await queryRunner.query(`CREATE TABLE \`t_leader_lease\` (\`name\` varchar(64) NOT NULL, \`holder\` varchar(64) NULL, \`acquired_at\` datetime(6) NULL, \`expires_at\` datetime(6) NULL, \`updated_at\` datetime(6) NOT NULL, PRIMARY KEY (\`name\`)) ENGINE=InnoDB`);
        await queryRunner.query(`CREATE TABLE \`t_login_attempt\` (\`id\` varchar(36) NOT NULL, \`counter_key\` varchar(255) NOT NULL, \`occurred_at\` datetime(6) NOT NULL, PRIMARY KEY (\`id\`)) ENGINE=InnoDB`);
        await queryRunner.query(`CREATE TABLE \`t_outbox_message\` (\`id\` varchar(36) NOT NULL, \`message_type\` varchar(50) NOT NULL, \`payload\` json NOT NULL, \`status\` varchar(20) NOT NULL, \`attempts\` int NOT NULL, \`next_attempt_at\` datetime(6) NULL, \`last_error\` text NULL, \`created_at\` datetime(6) NOT NULL, \`sent_at\` datetime(6) NULL, PRIMARY KEY (\`id\`)) ENGINE=InnoDB`);
        await queryRunner.query(`CREATE TABLE \`t_processed_message\` (\`id\` int NOT NULL AUTO_INCREMENT, \`message_id\` varchar(64) NOT NULL, \`message_type\` varchar(50) NOT NULL, \`agent_id\` varchar(36) NULL, \`processed_at\` datetime(6) NOT NULL, PRIMARY KEY (\`id\`)) ENGINE=InnoDB`);
        await queryRunner.query(`CREATE TABLE \`t_user\` (\`id\` int NOT NULL AUTO_INCREMENT, \`username\` varchar(255) NOT NULL, \`email\` varchar(255) NULL, \`password\` varchar(255) NULL, \`display_name\` varchar(255) NULL, \`avatar_url\` varchar(255) NULL, \`role\` varchar(255) NOT NULL, \`is_active\` tinyint NOT NULL, \`github_id\` varchar(255) NULL, \`keycloak_id\` varchar(255) NULL, \`created_at\` datetime(6) NOT NULL, \`updated_at\` datetime(6) NOT NULL, \`must_change_password\` tinyint NOT NULL, UNIQUE INDEX \`IDX_cebdcd668896f79744000f50dd\` (\`username\`), UNIQUE INDEX \`IDX_1d0b42896fa20240f9ffcc8012\` (\`email\`), UNIQUE INDEX \`IDX_16391e9a0f1e1b6e286ec6ff9b\` (\`github_id\`), UNIQUE INDEX \`IDX_43acce0aa9f45484164891a548\` (\`keycloak_id\`), PRIMARY KEY (\`id\`)) ENGINE=InnoDB`);
        await queryRunner.query(`CREATE TABLE \`t_session\` (\`token\` varchar(64) NOT NULL, \`user_id\` int NOT NULL, \`created_at\` datetime(6) NOT NULL, \`last_seen_at\` datetime(6) NOT NULL, \`expires_at\` datetime(6) NOT NULL, \`user_agent\` varchar(255) NULL, \`ip_address\` varchar(64) NULL, PRIMARY KEY (\`token\`)) ENGINE=InnoDB`);
        await queryRunner.query(`CREATE TABLE \`t_setting\` (\`key\` varchar(255) NOT NULL, \`value\` varchar(255) NULL, PRIMARY KEY (\`key\`)) ENGINE=InnoDB`);
        await queryRunner.query(`ALTER TABLE \`t_agent\` ADD CONSTRAINT \`FK_28216d89bbec1752bb00c82fb3d\` FOREIGN KEY (\`api_key_id\`) REFERENCES \`t_api_key\`(\`id\`) ON DELETE SET NULL ON UPDATE NO ACTION`);
        await queryRunner.query(`ALTER TABLE \`t_repository\` ADD CONSTRAINT \`FK_154e4f287a89244dd8e19591fde\` FOREIGN KEY (\`ssh_key_id\`) REFERENCES \`t_ssh_key\`(\`id\`) ON DELETE SET NULL ON UPDATE NO ACTION`);
        await queryRunner.query(`ALTER TABLE \`t_scan\` ADD CONSTRAINT \`FK_d6f19b8301b5a4aeb38208bc219\` FOREIGN KEY (\`container_id\`) REFERENCES \`t_container\`(\`id\`) ON DELETE CASCADE ON UPDATE NO ACTION`);
        await queryRunner.query(`ALTER TABLE \`t_scan\` ADD CONSTRAINT \`FK_a8c35b7077df870971f96c6ec05\` FOREIGN KEY (\`repo_id\`) REFERENCES \`t_repository\`(\`id\`) ON DELETE CASCADE ON UPDATE NO ACTION`);
        await queryRunner.query(`ALTER TABLE \`t_ai_review_result\` ADD CONSTRAINT \`FK_190898f7957c8095dc8056e0b0a\` FOREIGN KEY (\`scan_id\`) REFERENCES \`t_scan\`(\`id\`) ON DELETE CASCADE ON UPDATE NO ACTION`);
        await queryRunner.query(`ALTER TABLE \`t_issue\` ADD CONSTRAINT \`FK_01a203aba68ef01798fa1831006\` FOREIGN KEY (\`container_id\`) REFERENCES \`t_container\`(\`id\`) ON DELETE CASCADE ON UPDATE NO ACTION`);
        await queryRunner.query(`ALTER TABLE \`t_issue\` ADD CONSTRAINT \`FK_1e46a44f5a6b82dee9f0512b391\` FOREIGN KEY (\`first_seen_scan_id\`) REFERENCES \`t_scan\`(\`id\`) ON DELETE SET NULL ON UPDATE NO ACTION`);
        await queryRunner.query(`ALTER TABLE \`t_issue\` ADD CONSTRAINT \`FK_c2ec84da46d6bbdd89e90b8a275\` FOREIGN KEY (\`last_seen_scan_id\`) REFERENCES \`t_scan\`(\`id\`) ON DELETE SET NULL ON UPDATE NO ACTION`);
        await queryRunner.query(`ALTER TABLE \`t_issue\` ADD CONSTRAINT \`FK_0c779d2cdae6bdf8d243a6435eb\` FOREIGN KEY (\`repo_id\`) REFERENCES \`t_repository\`(\`id\`) ON DELETE CASCADE ON UPDATE NO ACTION`);
        await queryRunner.query(`ALTER TABLE \`t_finding\` ADD CONSTRAINT \`FK_9cb86eaf04924a35b371df9d499\` FOREIGN KEY (\`issue_id\`) REFERENCES \`t_issue\`(\`id\`) ON DELETE SET NULL ON UPDATE NO ACTION`);
        await queryRunner.query(`ALTER TABLE \`t_finding\` ADD CONSTRAINT \`FK_ce962aa8ce0728c834fb2b70caf\` FOREIGN KEY (\`scan_id\`) REFERENCES \`t_scan\`(\`id\`) ON DELETE CASCADE ON UPDATE NO ACTION`);
        await queryRunner.query(`ALTER TABLE \`t_session\` ADD CONSTRAINT \`FK_a5f9f098beacf17f45b99b245d2\` FOREIGN KEY (\`user_id\`) REFERENCES \`t_user\`(\`id\`) ON DELETE CASCADE ON UPDATE NO ACTION`);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE \`t_session\` DROP FOREIGN KEY \`FK_a5f9f098beacf17f45b99b245d2\``);
        await queryRunner.query(`ALTER TABLE \`t_finding\` DROP FOREIGN KEY \`FK_ce962aa8ce0728c834fb2b70caf\``);
        await queryRunner.query(`ALTER TABLE \`t_finding\` DROP FOREIGN KEY \`FK_9cb86eaf04924a35b371df9d499\``);
        await queryRunner.query(`ALTER TABLE \`t_issue\` DROP FOREIGN KEY \`FK_0c779d2cdae6bdf8d243a6435eb\``);
        await queryRunner.query(`ALTER TABLE \`t_issue\` DROP FOREIGN KEY \`FK_c2ec84da46d6bbdd89e90b8a275\``);
        await queryRunner.query(`ALTER TABLE \`t_issue\` DROP FOREIGN KEY \`FK_1e46a44f5a6b82dee9f0512b391\``);
        await queryRunner.query(`ALTER TABLE \`t_issue\` DROP FOREIGN KEY \`FK_01a203aba68ef01798fa1831006\``);
        await queryRunner.query(`ALTER TABLE \`t_ai_review_result\` DROP FOREIGN KEY \`FK_190898f7957c8095dc8056e0b0a\``);
        await queryRunner.query(`ALTER TABLE \`t_scan\` DROP FOREIGN KEY \`FK_a8c35b7077df870971f96c6ec05\``);
        await queryRunner.query(`ALTER TABLE \`t_scan\` DROP FOREIGN KEY \`FK_d6f19b8301b5a4aeb38208bc219\``);
        await queryRunner.query(`ALTER TABLE \`t_repository\` DROP FOREIGN KEY \`FK_154e4f287a89244dd8e19591fde\``);
        await queryRunner.query(`ALTER TABLE \`t_agent\` DROP FOREIGN KEY \`FK_28216d89bbec1752bb00c82fb3d\``);
        await queryRunner.query(`DROP TABLE \`t_setting\``);
        await queryRunner.query(`DROP TABLE \`t_session\``);
        await queryRunner.query(`DROP INDEX \`IDX_43acce0aa9f45484164891a548\` ON \`t_user\``);
        await queryRunner.query(`DROP INDEX \`IDX_16391e9a0f1e1b6e286ec6ff9b\` ON \`t_user\``);
        await queryRunner.query(`DROP INDEX \`IDX_1d0b42896fa20240f9ffcc8012\` ON \`t_user\``);
        await queryRunner.query(`DROP INDEX \`IDX_cebdcd668896f79744000f50dd\` ON \`t_user\``);
        await queryRunner.query(`DROP TABLE \`t_user\``);
        await queryRunner.query(`DROP TABLE \`t_processed_message\``);
        await queryRunner.query(`DROP TABLE \`t_outbox_message\``);
        await queryRunner.query(`DROP TABLE \`t_login_attempt\``);
        await queryRunner.query(`DROP TABLE \`t_leader_lease\``);
        await queryRunner.query(`DROP TABLE \`t_gate_policy\``);
        await queryRunner.query(`DROP TABLE \`t_finding\``);
        await queryRunner.query(`DROP TABLE \`t_issue\``);
        await queryRunner.query(`DROP TABLE \`t_audit_log\``);
        await queryRunner.query(`DROP TABLE \`t_ai_review_result\``);
        await queryRunner.query(`DROP INDEX \`idx_scan_file\` ON \`t_scan\``);
        await queryRunner.query(`DROP TABLE \`t_scan\``);
        await queryRunner.query(`DROP TABLE \`t_repository\``);
        await queryRunner.query(`DROP TABLE \`t_ssh_key\``);
        await queryRunner.query(`DROP TABLE \`t_container\``);
        await queryRunner.query(`DROP TABLE \`t_agent\``);
        await queryRunner.query(`DROP TABLE \`t_api_key\``);
    }

}
