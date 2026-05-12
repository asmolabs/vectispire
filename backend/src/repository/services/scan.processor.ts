import { Processor, WorkerHost } from '@nestjs/bullmq';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository as TypeOrmRepository } from 'typeorm';
import { Job } from 'bullmq';
import { Scan } from '../entities/scan.entity';
import { Logger } from '@nestjs/common';
import { NotificationGateway } from '../gateways/notification.gateway';
import { exec, execFile } from 'child_process';
import { promisify } from 'util';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { SSHKeyService } from '../ssh-key/services/ssh-key.service';
import { SettingsService } from '../../settings/services/settings.service';
import { MailService } from '../../mail/services/mail.service';
import { TeamsService } from '../../notifications/services/teams.service';

const execFileAsync = promisify(execFile);

const execAsync = promisify(exec);

@Processor('scan-queue')
export class ScanProcessor extends WorkerHost {
  private readonly logger = new Logger(ScanProcessor.name);

  constructor(
    @InjectRepository(Scan)
    private readonly scanModel: TypeOrmRepository<Scan>,
    private readonly notificationGateway: NotificationGateway,
    private readonly sshKeyService: SSHKeyService,
    private readonly settingsService: SettingsService,
    private readonly mailService: MailService,
    private readonly teamsService: TeamsService,
  ) {
    super();
  }

  async process(job: Job<any, any, string>): Promise<any> {
    const { scanId, repoUrl, branch, subPath, sshKeyId, isContainer, registry, imageName, tag } = job.data;
    
    if (isContainer) {
      this.logger.log(`Processing container scan job for Scan ID ${scanId}: ${registry ? registry + '/' : ''}${imageName}:${tag}`);
    } else {
      this.logger.log(`Processing git scan job for Scan ID ${scanId}: ${repoUrl} (Branch: ${branch}, Path: ${subPath || 'root'})`);
    }

    // Update scan status to 'scanning'
    await this.scanModel.update(scanId, { status: 'scanning' });
    this.notificationGateway.sendScanUpdate(scanId, 'scanning');
    
    // Create a temporary working directory for this scan job
    const scansBaseDir = path.join(os.tmpdir(), 'zanshin_scans');
    const workDir = path.join(scansBaseDir, `scan_${scanId}`);
    let keyFilePath: string | null = null;
    try {
      if (!fs.existsSync(scansBaseDir)) {
        fs.mkdirSync(scansBaseDir, { recursive: true });
      }
      
      if (!isContainer && sshKeyId) {
        this.logger.log(`Using SSH Key ${sshKeyId} for scan ${scanId}`);
        const privateKey = await this.sshKeyService.getDecryptedKey(sshKeyId);
        keyFilePath = path.join(scansBaseDir, `key_${scanId}`);
        fs.writeFileSync(keyFilePath, privateKey, { mode: 0o600 });
      }

      if (fs.existsSync(workDir)) {
          fs.rmSync(workDir, { recursive: true, force: true });
      }
      fs.mkdirSync(workDir, { recursive: true });
      
      const startTime = Date.now();
      const sbomPath = path.join(workDir, 'sbom.json');
      
      if (isContainer) {
        // --- CONTAINER SCAN ---
        const imageString = `${registry ? registry + '/' : ''}${imageName}:${tag}`;
        this.logger.log(`Generating SBOM for Docker image ${imageString}`);
        
        // Use registry directly to avoid local architecture mismatches (e.g. Mac arm64 trying to pull old amd64 images)
        const syftResult = await execFileAsync('docker', [
          'run', '--rm', 
          '--memory', '1g', '--cpus', '1.0',
          'anchore/syft', `registry:${imageString}`, '--platform', 'linux/amd64', '-o', 'json'
        ], { timeout: 300000, maxBuffer: 50 * 1024 * 1024 }); // 5 minutes timeout, 50MB buffer
        
        fs.writeFileSync(sbomPath, syftResult.stdout);
      } else {
        // --- GIT REPOSITORY SCAN ---
        this.logger.log(`Cloning ${repoUrl} branch ${branch} into ${workDir}`);
        
        const gitSshCommand = keyFilePath 
          ? `ssh -i ${keyFilePath} -o StrictHostKeyChecking=no -o BatchMode=yes` 
          : 'ssh -o StrictHostKeyChecking=no -o BatchMode=yes';

        await execFileAsync('git', ['clone', '--branch', branch, '--depth', '1', repoUrl, workDir], {
          env: { ...process.env, GIT_SSH_COMMAND: gitSshCommand },
          timeout: 120000, // 2 minutes timeout
        });

        let normalizedSubPath = (subPath || '').replace(/^\/+|\/+$/g, '');
        if (normalizedSubPath.includes('..')) {
            this.logger.warn(`Potential directory traversal attempt in subPath: ${subPath}. Defaulting to root.`);
            normalizedSubPath = '';
        }
        
        const targetDir = normalizedSubPath ? `/src/${normalizedSubPath}` : '/src';
        
        this.logger.log(`Generating SBOM for ${repoUrl} (Target: ${targetDir})`);
        const syftResult = await execFileAsync('docker', [
          'run', '--rm', 
          '--memory', '1g', '--cpus', '1.0',
          '-v', `${workDir}:/src`, 
          'anchore/syft', `dir:${targetDir}`, '-o', 'json'
        ], { timeout: 300000, maxBuffer: 50 * 1024 * 1024 }); // 5 minutes timeout, 50MB buffer
        
        fs.writeFileSync(sbomPath, syftResult.stdout);
      }
      
      const sbom = JSON.parse(fs.readFileSync(sbomPath, 'utf8'));

      // 3. Grype - Analyze SBOM for CVEs
      const cvesPath = path.join(workDir, 'cves.json');
      this.logger.log(`Analyzing SBOM for CVEs...`);
      const grypeResult = await execFileAsync('docker', [
        'run', '--rm', 
        '--memory', '1g', '--cpus', '1.0',
        '-v', `${workDir}:/work`, 
        'anchore/grype', 'sbom:/work/sbom.json', '-o', 'json'
      ], { timeout: 300000, maxBuffer: 50 * 1024 * 1024 }); // 5 minutes timeout, 50MB buffer
      
      fs.writeFileSync(cvesPath, grypeResult.stdout);
      const cves = JSON.parse(grypeResult.stdout);

      const endTime = Date.now();
      const duration = endTime - startTime;

      // 4. Compute Summary (count severities)
      const summary = {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        negligible: 0,
        unknown: 0,
        total: 0
      };

      let totalFindings = 0;
      if (cves.matches) {
        totalFindings = cves.matches.length;
        cves.matches.forEach((match: any) => {
          const severity = match.vulnerability.severity.toLowerCase();
          if (summary.hasOwnProperty(severity)) {
            (summary as any)[severity]++;
          } else {
            summary.unknown++;
          }
          summary.total++;
        });
      }

      let version = null;
      let projectType = null;
      if (isContainer) {
        version = tag;
        projectType = 'Docker Image';
      } else {
        const info = await this.detectProjectInfo(workDir, subPath);
        version = info.version;
        projectType = info.projectType;
      }

      // 5. Update Scan record in Database
      await this.scanModel.update(scanId, {
        status: 'completed',
        sbom,
        cves,
        summary: summary as any,
        durationMs: duration,
        findingsCount: totalFindings,
        version: version,
        projectType: projectType
      });
      this.notificationGateway.sendScanUpdate(scanId, 'completed');
      
      // Check and trigger email alert
      const alertSettings = await this.settingsService.getAlertSettings();
      if (alertSettings.alertEmails && alertSettings.alertMinSeverity) {
        const severityLevels = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
        const thresholdIndex = severityLevels.indexOf(alertSettings.alertMinSeverity.toUpperCase());
        
        let shouldAlert = false;
        if (thresholdIndex !== -1) {
          if (thresholdIndex >= 0 && summary.critical > 0) shouldAlert = true;
          if (thresholdIndex >= 1 && summary.high > 0) shouldAlert = true;
          if (thresholdIndex >= 2 && summary.medium > 0) shouldAlert = true;
          if (thresholdIndex >= 3 && summary.low > 0) shouldAlert = true;
        }

        if (shouldAlert) {
          const projectName = isContainer ? `${imageName}:${tag}` : repoUrl;
          await this.mailService.sendVulnerabilityAlert(scanId, projectName, summary, alertSettings.alertEmails);
          
          // Trigger Teams if enabled
          const teamsSettings = await this.settingsService.getTeamsSettings();
          if (teamsSettings.enabled) {
            await this.teamsService.sendVulnerabilityAlert(scanId, projectName, summary);
          }
        }
      }
      
      this.logger.log(`Job completed for scan id ${scanId}`);
    } catch (error: any) {
      const errorMessage = error.stderr || error.message || 'Unknown scanning error';
      this.logger.error(`Job failed for scan id ${scanId}: ${errorMessage}`);
      
      await this.scanModel.update(scanId, { 
        status: 'failed',
        error: errorMessage
      });
      this.notificationGateway.sendScanUpdate(scanId, 'failed');
      throw error;
    } finally {
      // Cleanup temporary scan directory
      if (fs.existsSync(workDir)) {
        fs.rmSync(workDir, { recursive: true, force: true });
      }
      // Cleanup temporary key file
      if (keyFilePath && fs.existsSync(keyFilePath)) {
        fs.unlinkSync(keyFilePath);
      }
    }
  }

  private async detectProjectInfo(workDir: string, subPath: string): Promise<{ version: string | null, projectType: string | null }> {
    const basePath = path.join(workDir, subPath || '');
    this.logger.log(`Detecting project info in ${basePath}`);
    try {
      // Node.js
      const packageJsonPath = path.join(basePath, 'package.json');
      if (fs.existsSync(packageJsonPath)) {
        const pkg = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
        if (pkg.version) {
          this.logger.log(`Detected Node.js version: ${pkg.version}`);
          return { version: pkg.version, projectType: 'Node.js' };
        }
        return { version: null, projectType: 'Node.js' };
      }

      // Java Maven
      const pomPath = path.join(basePath, 'pom.xml');
      if (fs.existsSync(pomPath)) {
        const pomContent = fs.readFileSync(pomPath, 'utf8');
        // Look for version before dependencies to avoid picking up dependency versions
        const projectSection = pomContent.split('<dependencies>')[0];
        const match = projectSection.match(/<version>([^<]+)<\/version>/);
        if (match) {
          this.logger.log(`Detected Java Maven version: ${match[1]}`);
          return { version: match[1], projectType: 'Java (Maven)' };
        }
        return { version: null, projectType: 'Java (Maven)' };
      }

      // Java Gradle
      const buildGradlePath = path.join(basePath, 'build.gradle');
      const buildGradleKtsPath = path.join(basePath, 'build.gradle.kts');
      const gradlePath = fs.existsSync(buildGradlePath) ? buildGradlePath : (fs.existsSync(buildGradleKtsPath) ? buildGradleKtsPath : null);
      
      if (gradlePath) {
        const content = fs.readFileSync(gradlePath, 'utf8');
        const match = content.match(/version\s*=\s*['"]([^'"]+)['"]/);
        if (match) {
          this.logger.log(`Detected Java Gradle version: ${match[1]}`);
          return { version: match[1], projectType: 'Java (Gradle)' };
        }
        return { version: null, projectType: 'Java (Gradle)' };
      }

      // Python - pyproject.toml
      const pyprojectPath = path.join(basePath, 'pyproject.toml');
      if (fs.existsSync(pyprojectPath)) {
        const content = fs.readFileSync(pyprojectPath, 'utf8');
        const match = content.match(/version\s*=\s*["']([^"']+)["']/);
        if (match) {
          this.logger.log(`Detected Python (pyproject) version: ${match[1]}`);
          return { version: match[1], projectType: 'Python' };
        }
        return { version: null, projectType: 'Python' };
      }

      // Python - setup.py
      const setupPyPath = path.join(basePath, 'setup.py');
      if (fs.existsSync(setupPyPath)) {
        const content = fs.readFileSync(setupPyPath, 'utf8');
        const match = content.match(/version\s*=\s*["']([^"']+)["']/);
        if (match) {
          this.logger.log(`Detected Python (setup.py) version: ${match[1]}`);
          return { version: match[1], projectType: 'Python' };
        }
        return { version: null, projectType: 'Python' };
      }

    } catch (e) {
      this.logger.warn(`Failed to detect project info in ${basePath}: ${e.message}`);
    }
    return { version: null, projectType: null };
  }
}
