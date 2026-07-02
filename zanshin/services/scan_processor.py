import json
import logging
import os
import shutil
import tempfile
import time
import uuid
from typing import Dict, Any, Optional
import docker
import git

from zanshin.database import SessionLocal
from zanshin.models.scan import Scan
from zanshin.models.container import Container
from zanshin.services.ssh_key_service import SSHKeyService

logger = logging.getLogger(__name__)

class NotificationGateway:
    def send_scan_update(self, scan_id: int, status: str):
        logger.info(f"Sending scan update: Scan ID {scan_id}, Status {status}")

class ScanProcessor:
    def __init__(self, ssh_key_service: SSHKeyService):
        self.ssh_key_service = ssh_key_service
        self.notification_gateway = NotificationGateway()
        
    def process_scan(self, scan_id: int, repo_url: Optional[str], branch: str, sub_path: str, ssh_key_id: Optional[uuid.UUID]):
        logger.info(f"Processing scan job for Scan ID {scan_id} (Branch: {branch}, Path: {sub_path})")
        
        # Use a dedicated DB session for background processing
        db = SessionLocal()
        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if not scan:
                logger.error(f"Scan not found: {scan_id}")
                return
                
            scan.status = "scanning"
            db.commit()
            self.notification_gateway.send_scan_update(scan_id, "scanning")
            
            is_container = scan.container_id is not None
            start_time = time.time()
            temp_dir = tempfile.mkdtemp(prefix=f"zanshin_scan_{scan_id}_")
            
            try:
                if is_container:
                    container_entity = scan.container
                    image_string = f"{container_entity.registry + '/' if container_entity.registry else ''}{container_entity.image_name}:{container_entity.tag}"
                    
                    # 1. Generate Container SBOM
                    logger.info(f"Generating SBOM for Docker image {image_string}")
                    sbom = self._generate_container_sbom(image_string)
                    
                    # 2. Scan SBOM with Grype
                    logger.info("Scanning SBOM for CVEs")
                    cves = self._scan_sbom(temp_dir, sbom)
                else:
                    # 0. Validate Path
                    self._validate_path(sub_path)
                    
                    # 1. Clone Git Repo
                    logger.info(f"Cloning {repo_url} branch {branch} into {temp_dir}")
                    self._clone_repo(repo_url, branch, temp_dir, ssh_key_id)
                    
                    # 2. Generate Directory SBOM
                    logger.info(f"Generating SBOM for directory (Target: {sub_path})")
                    sbom = self._generate_dir_sbom(temp_dir, sub_path)
                    
                    # 3. Scan SBOM with Grype
                    logger.info("Scanning SBOM for CVEs")
                    cves = self._scan_sbom(temp_dir, sbom)
                    
                duration_ms = int((time.time() - start_time) * 1000)
                summary = self._summarize_findings(cves)
                
                # Update Scan results
                scan.status = "completed"
                scan.sbom = sbom
                scan.cves = cves
                scan.summary = summary
                scan.findings_count = summary.get("total", 0)
                scan.duration_ms = duration_ms
                db.commit()
                
                self.notification_gateway.send_scan_update(scan_id, "completed")
                logger.info(f"Scan completed for ID {scan_id}")
                
            except Exception as e:
                logger.exception(f"Scan failed for ID {scan_id}")
                scan.status = "failed"
                scan.error = str(e)
                db.commit()
                self.notification_gateway.send_scan_update(scan_id, "failed")
            finally:
                # Clean up temp directory
                if os.path.exists(temp_dir):
                    shutil.rmtree(temp_dir, ignore_errors=True)
                    
        finally:
            db.close()

    def _validate_path(self, path: str):
        if path and (".." in path or path.startswith("/") or "\\" in path):
            raise ValueError("Chemin invalide : la traversée de répertoire n'est pas autorisée.")

    def _clone_repo(self, repo_url: str, branch: str, work_dir: str, ssh_key_id: Optional[uuid.UUID]):
        env = {}
        key_file_path = None
        try:
            if ssh_key_id:
                private_key = self.ssh_key_service.get_decrypted_key(ssh_key_id)
                # Create a temporary key file with strict permissions
                fd, key_file_path = tempfile.mkstemp()
                os.close(fd)
                with open(key_file_path, "w") as f:
                    f.write(private_key)
                os.chmod(key_file_path, 0o600)
                env["GIT_SSH_COMMAND"] = f"ssh -i {key_file_path} -o StrictHostKeyChecking=no -o BatchMode=yes"
            else:
                env["GIT_SSH_COMMAND"] = "ssh -o StrictHostKeyChecking=no -o BatchMode=yes"
                
            git.Repo.clone_from(
                url=repo_url,
                to_path=work_dir,
                branch=branch,
                depth=1,
                env=env
            )
        finally:
            if key_file_path and os.path.exists(key_file_path):
                os.remove(key_file_path)

    def _generate_container_sbom(self, image_string: str) -> Dict[str, Any]:
        client = docker.from_env()
        volumes = {}
        
        # Check standard docker sockets
        sockets = [
            "/var/run/docker.sock",
            os.path.expanduser("~/.docker/run/docker.sock")
        ]
        for s in sockets:
            if os.path.exists(s):
                volumes[os.path.abspath(s)] = {"bind": "/var/run/docker.sock", "mode": "rw"}
                break
                
        output_bytes = client.containers.run(
            image="anchore/syft:latest",
            command=["registry:" + image_string, "--platform", "linux/amd64", "-o", "json"],
            volumes=volumes,
            remove=True,
            stdout=True,
            stderr=False
        )
        return json.loads(output_bytes.decode("utf-8"))

    def _generate_dir_sbom(self, work_dir: str, sub_path: str) -> Dict[str, Any]:
        client = docker.from_env()
        target = f"/src/{sub_path}" if sub_path else "/src"
        output_bytes = client.containers.run(
            image="anchore/syft:latest",
            command=["dir:" + target, "-o", "json"],
            volumes={os.path.abspath(work_dir): {"bind": "/src", "mode": "ro"}},
            remove=True,
            stdout=True,
            stderr=False
        )
        return json.loads(output_bytes.decode("utf-8"))

    def _scan_sbom(self, work_dir: str, sbom: Dict[str, Any]) -> Dict[str, Any]:
        client = docker.from_env()
        sbom_file_path = os.path.join(work_dir, "sbom.json")
        with open(sbom_file_path, "w") as f:
            json.dump(sbom, f)
            
        output_bytes = client.containers.run(
            image="anchore/grype:latest",
            command=["sbom:/work/sbom.json", "-o", "json"],
            volumes={os.path.abspath(work_dir): {"bind": "/work", "mode": "ro"}},
            remove=True,
            stdout=True,
            stderr=False
        )
        return json.loads(output_bytes.decode("utf-8"))

    def _summarize_findings(self, cves: Dict[str, Any]) -> Dict[str, Any]:
        summary = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "negligible": 0,
            "unknown": 0,
            "total": 0
        }
        matches = cves.get("matches", [])
        total = 0
        for match in matches:
            vuln = match.get("vulnerability", {})
            severity = vuln.get("severity", "unknown").lower()
            summary[severity] = summary.get(severity, 0) + 1
            total += 1
        summary["total"] = total
        return summary
