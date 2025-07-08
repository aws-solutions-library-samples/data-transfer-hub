#!/usr/bin/env python3
import os
import logging
import subprocess
import requests
import boto3
from dataclasses import dataclass
from typing import List, Dict, Optional, Union
from concurrent.futures import ThreadPoolExecutor
# from tenacity import retry, stop_after_attempt, wait_exponential

# Configure logging
logging.basicConfig(
    filename='/tmp/ECR-Script.log',
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class Config:
    source_registry: str
    target_registry: str
    artifactory_user: str
    artifactory_pass: str
    max_workers: int = 3
    retry_attempts: int = 3
    timeout: int = 300

def load_config() -> Config:
    """Load configuration from environment variables"""
    return Config(
        source_registry=os.getenv('SOURCE_REGISTRY', '<url or ip&port>'),
        target_registry=os.getenv('TARGET_REGISTRY', '<api>'),
        artifactory_user=os.getenv('ARTIFACTORY_USER', '<xxxxxxx>),
        artifactory_pass=os.getenv('ARTIFACTORY_PASS','<xxxxxxx>'),
        max_workers=int(os.getenv('MAX_WORKERS', 3)),
        retry_attempts=int(os.getenv('RETRY_ATTEMPTS', 3)),
        timeout=int(os.getenv('TIMEOUT', 300))
    )

# Initialize global config
config = load_config()

# Obtain current AWS region
AWS_REGION = boto3.Session().region_name

# Initialize AWS client
ecr_client = boto3.client('ecr', region_name=AWS_REGION)

# Initialize requests session for connection pooling
session = requests.Session()

# @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
def run_command(command: str, input: str | None = None) -> str:
    """Execute shell commands with retries and better error handling"""
    try:
        logger.info(f"Executing command: {command}")
        result = subprocess.run(command.split(), shell=False, check=True,
                              text=True, capture_output=True, input = input)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        logger.error(f"Error executing command: {e}")
        logger.error(f"Command output: {e.stderr}")
        raise

def docker_login_jfrog():
    """Docker login to JFrog."""
    login_cmd = f"docker login {config.source_registry} -u {config.artifactory_user} -p {config.artifactory_pass}"
    # subprocess.run(login_cmd, shell=False, check=True)
    run_command(login_cmd)

def docker_login_aws():
    """Docker login to AWS ECR."""
    get_password_cmd = f"aws ecr get-login-password --region {AWS_REGION}"
    password = run_command(get_password_cmd)
    login_cmd = f"docker login --username AWS --password-stdin {config.target_registry}"
    run_command(login_cmd, input=password)
    # subprocess.run(login_cmd, shell=False, check=True)

def validate_repository(repo: Dict) -> bool:
    """Validate repository structure"""
    required_fields = ['key']
    return all(field in repo for field in required_fields)

def get_artifactory_repos() -> List[Dict]:
    """Get list of repositories with validation"""
    logger.info("Fetching repositories from Artifactory")
    url = f"http://{config.source_registry}/artifactory/api/repositories?type=local"
    try:
        response = session.get(
            url,
            auth=(config.artifactory_user, config.artifactory_pass),
            timeout=config.timeout
        )
        response.raise_for_status()
        repos = response.json()

        # Validate repositories
        valid_repos = [repo for repo in repos if validate_repository(repo)]
        logger.info(f"Found {len(valid_repos)} valid repositories in Artifactory")
        return valid_repos
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to fetch repositories: {e}")
        return []

def check_ecr_repo_exists(repo_name: str, image: str) -> bool:
    """Check if ECR repository exists"""
    try:
        # concat repo_name and image
        repo_name = f"{repo_name}/{image}"
        ecr_client.describe_repositories(repositoryNames=[repo_name])
        return True
    except ecr_client.exceptions.RepositoryNotFoundException:
        return False
    except Exception as e:
        logger.error(f"Error checking ECR repository: {e}")
        return False

def create_ecr_repo(repo_name: str, image: str) -> bool:
    """Create ECR repository"""
    try:
        # concat repo_name and image
        repo_name = f"{repo_name}/{image}"
        ecr_client.create_repository(
            repositoryName=repo_name,
            imageScanningConfiguration={'scanOnPush': True}
        )
        logger.info(f"Created ECR repository: {repo_name}")
        return True
    except Exception as e:
        logger.error(f"Error creating ECR repository: {e}")
        return False

# @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
def list_docker_images(repo_name: str):
    """List all Docker images and their tags in a specific JFrog repository."""
    url = f"http://{config.source_registry}/artifactory/api/docker/{repo_name}/v2/_catalog"
    try:
        response = session.get(
            url,
            auth=(config.artifactory_user, config.artifactory_pass),
            timeout=config.timeout
        )
        response.raise_for_status()
        return response.json().get('repositories', [])
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to fetch tags for {repo_name}: {e}")
        return []

# @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
def list_image_tags(repo_name: str, image: str) -> List[str]:
    """Get list of tags for a repository"""
    url = f"http://{config.source_registry}/artifactory/api/docker/{repo_name}/v2/{image}/tags/list"
    try:
        response = session.get(
            url,
            auth=(config.artifactory_user, config.artifactory_pass),
            timeout=config.timeout
        )
        response.raise_for_status()
        return response.json().get('tags', [])
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to fetch tags for {repo_name}: {e}")
        return []

def process_tag(repo_name: str, image: str, tag: str) -> None:
    """Process a single tag"""
    try:
        source_image = f"{config.source_registry}/{repo_name}/{image}:{tag}"
        target_image = f"{config.target_registry}/{repo_name}/{image}:{tag}"

        # Pull image
        run_command(f"docker pull {source_image}")

        # Tag image
        run_command(f"docker tag {source_image} {target_image}")

        # Push image
        run_command(f"docker push {target_image}")

        logger.info(f"Successfully migrated {source_image} to {target_image}")
    except Exception as e:
        logger.error(f"Error processing tag {tag} for repo {repo_name}/{image}: {e}")

def process_repo(repo: Dict) -> None:
    """Process a single repository"""
    repo_name = repo['key']
    logger.info(f"Processing repository: {repo_name}")

    try:
        # List all Docker images in the repository
        images = list_docker_images(repo_name)
        for image in images:
            # List all tags for each image

            if not check_ecr_repo_exists(repo_name, image):
                if not create_ecr_repo(repo_name, image):
                    logger.error(f"Failed to create ECR repository for {repo_name}")
                    return

            tags = list_image_tags(repo_name, image)
            for tag in tags:
                process_tag(repo_name, image, tag)

    except Exception as e:
        logger.error(f"Error processing repository {repo_name}: {e}")

def main() -> None:
    """Main function to orchestrate the image migration process"""
    try:
        logger.info("Starting image migration process")
        docker_login_jfrog()
        docker_login_aws()

        # List all repositories in JFrog
        repos = get_artifactory_repos()

        if not repos:
            logger.error("No valid repositories found")
            return

        # # Use ThreadPoolExecutor for parallel processing
        # with ThreadPoolExecutor(max_workers=config.max_workers) as executor:
        #     list(executor.map(process_repo, repos))
        for repo in repos:
            process_repo(repo)

        logger.info("Image migration process completed")
    except Exception as e:
        logger.error(f"Error in main process: {e}")

if __name__ == "__main__":
    main()
